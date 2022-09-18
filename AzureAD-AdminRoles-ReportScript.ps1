############################################################################################################
#                                                                                                          #
#  Powershell script showcasing how to fetch data from various sources to compile an actionable status     #
#  report on Azure AD administrative role assignments.                                                     #
#                                                                                                          #
#  The script is only an example and will require changes depending on your AAD tenant.                    #
#                                                                                                          #
#  Please read the blogpost first:                                                                         #
#  https://learningbydoing.cloud/blog/building-a-comprehensive-report-on-azure-ad-admin-role-assignments/  #
#                                                                                                          #
############################################################################################################

### Start of script

# Connect to MS Graph using Graph Powershell SDK
Connect-MgGraph -Scopes RoleEligibilitySchedule.Read.Directory, RoleAssignmentSchedule.Read.Directory, CrossTenantInformation.ReadBasic.All, AuditLog.Read.All, User.Read.All
Select-MgProfile -Name Beta

# Connect to Azure Log Analytics workspace using Azure Powershell module
Connect-AzAccount
Set-AzContext -Subscription "STB - Visual Studio Professional Subscription"
$workspaceName = "stb-vl-prod-loganalytics-workspace"
$workspaceRG = "stb-vl-prod-loganalytics"
$workspaceID = (Get-AzOperationalInsightsWorkspace -Name $workspaceName -ResourceGroupName $workspaceRG).CustomerID

# Get MFA registration details
Write-Host -ForegroundColor Yellow "Fetching MFA registration details report"
$mfaRegistrationDetails = Get-MgReportAuthenticationMethodUserRegistrationDetail -All:$true
$mfaRegistrationDetailsHashmap = $mfaRegistrationDetails | Group-Object -Property Id -AsHashTable
Write-Host -ForegroundColor Yellow "Found $($mfaRegistrationDetails.count) MFA registration detail records"

# Get assigned role assignments
Write-Host -ForegroundColor Yellow "Fetching assigned role assignments, might take a minute..."
$assignedRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -ExpandProperty "*" -All:$true
$activatedRoleAssignments = $assignedRoleAssignments | Where-Object { $_.AssignmentType -eq 'Activated' }
$filteredAssignedRoleAssignments = $assignedRoleAssignments | Where-Object { $_.AssignmentType -eq 'Assigned' }
Write-Host -ForegroundColor Yellow "Found $($filteredAssignedRoleAssignments.count) assigned role assignments"

# Get eligible role assignments
Write-Host -ForegroundColor Yellow "Fetching eligible role assignments, might take a minute..."
$eligibleRoleAssignments = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -ExpandProperty "*" -All:$true
Write-Host -ForegroundColor Yellow "Found $($eligibleRoleAssignments.count) eligible PIM role assignments, whereof $($activatedRoleAssignments.count) are activated"

# Combine assignments
$allRoleAssignments = @(
    $eligibleRoleAssignments #| Select-Object -First 10
    $filteredAssignedRoleAssignments #| Select-Object -First 1
)

# Process records
$countProcess = 0
$report = $allRoleAssignments | ForEach-Object {
    $roleObject = $_
    $countProcess++
    if($null -eq $roleObject.AssignmentType) {
        Write-Host "Processing eligible role assignment #$countProcess of $($allRoleAssignments.count)" -ForegroundColor Yellow
    } else {
        Write-Host "Processing active role assignment #$countProcess of $($allRoleAssignments.count)" -ForegroundColor Yellow
    }

    # Fetch last sign-in
    $principalSignInActivity = $null
    $principalLastSignIn = $null
    $adminAccountOwner = $null
    $adminAccountOwnerAccountName = $null
    $mfaCapable = $false
    $mfaDefaultMethod = $null
    $kqlQuery = $null
    switch ($roleObject.Principal.AdditionalProperties.'@odata.type') {
        '#microsoft.graph.user' { 
            $principalSignInActivity = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/users/$($roleObject.Principal.Id)?`$select=id,userPrincipalName,userType,signInActivity"
            if($principalSignInActivity) {
                if($principalSignInActivity.signInActivity.lastSignInDateTime -gt $principalSignInActivity.signInActivity.lastNonInteractiveSignInDateTime) {
                    $principalLastSignIn = $principalSignInActivity.signInActivity.lastSignInDateTime
                } else { $principalLastSignIn = $principalSignInActivity.signInActivity.lastNonInteractiveSignInDateTime }
            }

            # Fetch admin account owner
            if($roleObject.Principal.AdditionalProperties.userPrincipalName -like 'admin-*@*') {
                $adminAccountOwnerAccountName = $roleObject.Principal.AdditionalProperties.userPrincipalName -replace "@tenant.onmicrosoft.com","" -replace "admin-",""
                $adminAccountOwner = Get-MgUser -Filter "onPremisesSamAccountName eq '$($adminAccountOwnerAccountName)' and employeeId eq '$($roleObject.Principal.AdditionalProperties.employeeId)'" -ConsistencyLevel "eventual" -CountVariable counter -Select "id,userPrincipalName,displayName,onPremisesSamAccountName,employeeId,companyName,department,accountEnabled,signInActivity"
            }

            # Fetch default MFA method and cabability
            if($mfaRegistrationDetailsHashmap.ContainsKey("$($roleObject.Principal.Id)")) {
                $mfaCapable = $mfaRegistrationDetailsHashmap["$($roleObject.Principal.Id)"].IsMfaCapable
                $mfaDefaultMethod = $mfaRegistrationDetailsHashmap["$($roleObject.Principal.Id)"].AdditionalProperties.defaultMfaMethod
            }
        }
        '#microsoft.graph.servicePrincipal' { 
            switch ($roleObject.Principal.AdditionalProperties.servicePrincipalType) {
                'Application' {
                    # KQL query for SP last sign-in
                    $query = "AADServicePrincipalSignInLogs
                    | where ResultType == '0'
                    | where TimeGenerated > ago(90d)
                    | where AppId == '$($roleObject.Principal.AdditionalProperties.appId)'
                    | sort by TimeGenerated desc
                    | limit 1"

                    $kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
                    $principalLastSignIn = $kqlQuery.Results.TimeGenerated
                }
                'ManagedIdentity' {
                    # KQL query for MSI last sign-in
                    $query = "AADManagedIdentitySignInLogs
                    | where ResultType == '0'
                    | where TimeGenerated > ago(90d)
                    | where AppId == '$($roleObject.Principal.AdditionalProperties.appId)'
                    | sort by TimeGenerated desc
                    | limit 1"

                    $kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
                    $principalLastSignIn = $kqlQuery.Results.TimeGenerated
                }
            }
        }
    }

    # Build report object
    [PSCustomObject]@{
        'PIM-role last activated' = if($null -eq $roleObject.AssignmentType) {
            switch ($roleObject.Principal.AdditionalProperties.'@odata.type') {
                '#microsoft.graph.user' {
                    # KQL query for last PIM role activation
                    $query = "AuditLogs
                    | where TimeGenerated > ago(90d)
                    | where OperationName == 'Add member to role completed (PIM activation)'
                    | where Result == 'success'
                    | where InitiatedBy.user.id == '$($roleObject.Principal.Id)'
                    | where TargetResources[0].id == '$($roleObject.RoleDefinition.Id)'
                    | sort by TimeGenerated desc
                    | limit 1"

                    $kqlQuery = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceID -Query $query
                    $kqlQuery.Results.TimeGenerated
                }
            }
        }
        'Principal Type' = switch ($roleObject.Principal.AdditionalProperties.'@odata.type') {
            '#microsoft.graph.user' { "User" }
            '#microsoft.graph.servicePrincipal' { $roleObject.Principal.AdditionalProperties.servicePrincipalType }
            '#microsoft.graph.group' { "RoleAssignableGroup" }
        }
        'Principal User Type' = $principalSignInActivity.userType
        'Principal Created' = $roleObject.Principal.AdditionalProperties.createdDateTime
        'Principal AD Synced' = $roleObject.Principal.AdditionalProperties.onPremisesSyncEnabled -eq $true
        'Principal Enabled' = $roleObject.Principal.AdditionalProperties.accountEnabled
        'Principal Last SignIn' = $principalLastSignIn
        'Principal DisplayName' = $roleObject.Principal.AdditionalProperties.displayName
        'Principal UPN / AppId' = switch ($roleObject.Principal.AdditionalProperties.'@odata.type') {
            '#microsoft.graph.user' { $roleObject.Principal.AdditionalProperties.userPrincipalName }
            '#microsoft.graph.servicePrincipal' { $roleObject.Principal.AdditionalProperties.appId }
            '#microsoft.graph.group' { "" }
        }
        'Principal Object ID' = $roleObject.Principal.Id
        'Principal Owner' = if ($null -ne $roleObject.Principal.AdditionalProperties.appOwnerOrganizationId) {
            $graphResult = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/tenantRelationships/findTenantInformationByTenantId(tenantId='$($roleObject.Principal.AdditionalProperties.appOwnerOrganizationId)')"
            $graphResult.displayName + " ($($graphResult.defaultDomainName))"
        }
        'MFA Capable' = $mfaCapable
        'MFA Default Method' = $mfaDefaultMethod
        'Member Type' = $roleObject.MemberType
        'Assignment Type' = if($roleObject.AssignmentType) { $roleObject.AssignmentType } else { "Eligible" }
        'Directory Scope' = $roleObject.DirectoryScopeId
        'Assigned Role' = $roleObject.roleDefinition.DisplayName
        'Assignment Start Date' = if($roleObject.StartDateTime) { $roleObject.StartDateTime } elseif ($roleObject.scheduleInfo.startDateTime) { $roleObject.scheduleInfo.startDateTime }
        'Assignment End Date' = if($roleObject.EndDateTime) { $roleObject.EndDateTime } elseif ($roleObject.scheduleInfo.expiration.endDateTime) { $roleObject.scheduleInfo.expiration.endDateTime }
        'Has End Date' = $roleObject.EndDateTime -or $roleObject.scheduleInfo.expiration.endDateTime
        'Custom Role' = -not $roleObject.RoleDefinition.IsBuiltIn
        'Role Template' = $roleObject.RoleDefinition.TemplateId
        'AdminOwner Company' = $adminAccountOwner.CompanyName
        'AdminOwner Department' = $adminAccountOwner.Department
        'AdminOwner Name' = $adminAccountOwner.DisplayName
        'AdminOwner UPN' = $adminAccountOwner.UserPrincipalName
        'AdminOwner Signature' = $adminAccountOwner.OnPremisesSamAccountName
        'AdminOwner EmployeeId' = $adminAccountOwner.EmployeeId
        'AdminOwner Enabled' = $adminAccountOwner.AccountEnabled
        'AdminOwner LastSignIn' = if($adminAccountOwner.SignInActivity) {
            if($adminAccountOwner.SignInActivity.lastSignInDateTime -gt $adminAccountOwner.SignInActivity.lastNonInteractiveSignInDateTime) {
                $adminAccountOwner.SignInActivity.lastSignInDateTime
            } else { $adminAccountOwner.SignInActivity.lastNonInteractiveSignInDateTime }
        }
    }
}

# Output to GridView
$report | Out-GridView

### End of script
