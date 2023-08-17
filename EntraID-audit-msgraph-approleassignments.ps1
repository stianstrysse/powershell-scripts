############################################################################################################
#                                                                                                          #
#  Powershell script showcasing how to fetch and report on all app role assignments for Microsoft Graph    #
#  and Azure AD Graph. Requires Microsoft Graph Powershell SDK v2, but the script can be altered to also   #
#  work in v1 if replacing beta-cmdlets.                                                                   #
#                                                                                                          #
#  The script only requires read-access and a few Graph scopes in Entra ID.                                #
#                                                                                                          #
#  Please read the blogpost first:                                                                         #
#  https://learningbydoing.cloud/blog/audit-ms-graph-app-role-assignments/                                 #
#                                                                                                          #
############################################################################################################

### Start of script

#region: Script Configuration

# The tier 0 app roles below are typically what can be abused to become Global Admin.
# NOTE: Organizations should do their own investigations and include any app roles to regard as sensitive, and which tier to assign them.
$appRoleTiers = @{
    'Application.ReadWrite.All'          = 'Tier 0' # SP can add credentials to other high-privileged apps, and then sign-in as the high-privileged app
    'AppRoleAssignment.ReadWrite.All'    = 'Tier 0' # SP can add any app role assignments to any resource, including MS Graph
    'Directory.ReadWrite.All'            = 'Tier 0' # SP can read and write all objects in the directory, including adding credentials to other high-privileged apps
    'RoleManagement.ReadWrite.Directory' = 'Tier 0' # SP can grant any role to any principal, including Global Admin
}

#endregion: Script Configuration

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Application.Read.All","AuditLog.Read.All","CrossTenantInformation.ReadBasic.All"

# Get Microsoft Graph SPN, appRoles, appRolesAssignedTo and generate hashtable for quick lookups
$servicePrincipalMsGraph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
[array] $msGraphAppRoles = $servicePrincipalMsGraph.AppRoles
[array] $msGraphAppRolesAssignedTo = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipalMsGraph.Id -All
$msGraphAppRolesHashTableId = $msGraphAppRoles | Group-Object -Property Id -AsHashTable

# Get Azure AD Graph SPN, appRoles, appRolesAssignedTo and generate hashtable for quick lookups
$servicePrincipalAadGraph = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0000-c000-000000000000'"
[array] $aadGraphAppRoles = $servicePrincipalAadGraph.AppRoles
[array] $aadGraphAppRolesAssignedTo = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $servicePrincipalAadGraph.Id -All
$aadGraphAppRolesHashTableId = $aadGraphAppRoles | Group-Object -Property Id -AsHashTable

# Join appRolesAssignedTo entries for AAD / MS Graph
$joinedAppRolesAssignedTo = @(
    $msGraphAppRolesAssignedTo
    $aadGraphAppRolesAssignedTo
)

# Process each appRolesAssignedTo for AAD / MS Graph
$progressCounter = 0
$cacheAppOwnerOrganizations = @()
$cacheServicePrincipalObjects = @()
$cacheServicePrincipalSigninActivities = @()
$cacheServicePrincipalsWithoutSigninActivities = @()
[array] $msGraphAppRoleAssignedToReport = $joinedAppRolesAssignedTo | ForEach-Object {
    $progressCounter++
    $currentAppRoleAssignedTo = $_
    Write-Host "Processing appRole # $progressCounter of $($joinedAppRolesAssignedTo.count)"

    # Lookup appRole for MS Graph
    $currentAppRole = $msGraphAppRolesHashTableId["$($currentAppRoleAssignedTo.AppRoleId)"]
    if($null -eq $currentAppRole) {
        # Lookup appRole for AAD Graph
        $currentAppRole = $aadGraphAppRolesHashTableId["$($currentAppRoleAssignedTo.AppRoleId)"]
    }
    
    # Lookup servicePrincipal object - check cache
    $currentServicePrincipalObject = $null
    if($cacheServicePrincipalObjects.Id -contains $currentAppRoleAssignedTo.PrincipalId) {
        $currentServicePrincipalObject = $cacheServicePrincipalObjects | Where-Object { $_.Id -eq $currentAppRoleAssignedTo.PrincipalId }
    } 

    else {
        # Retrieve servicePrincipalObject from MS Graph
        $currentServicePrincipalObject = Get-MgServicePrincipal -ServicePrincipalId $currentAppRoleAssignedTo.PrincipalId
        $cacheServicePrincipalObjects += $currentServicePrincipalObject
        Write-Host "Added servicePrincipal object to cache: $($currentServicePrincipalObject.displayName)"
    }

    # Lookup app owner organization
    $currentAppOwnerOrgObject = $null
    if($null -ne $currentServicePrincipalObject.AppOwnerOrganizationId) {
        # Check if app owner organization is in cache
        if($cacheAppOwnerOrganizations.tenantId -contains $currentServicePrincipalObject.AppOwnerOrganizationId) {
            $currentAppOwnerOrgObject = $cacheAppOwnerOrganizations | Where-Object { $_.tenantId -eq $currentServicePrincipalObject.AppOwnerOrganizationId }
        } 

        else {
            # Retrieve app owner organization from MS Graph
            $currentAppOwnerOrgObject = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='$($currentServicePrincipalObject.AppOwnerOrganizationId)')"
            $cacheAppOwnerOrganizations += $currentAppOwnerOrgObject
            Write-Host "Added app owner organization tenant to cache: $($currentAppOwnerOrgObject.displayName)"
        }
    }

    # Lookup servicePrincipal sign-in activity if not already in no-signin-activity list
    $currentSpSigninActivity = $null
    if($currentServicePrincipalObject.AppId -notin $cacheServicePrincipalsWithoutSigninActivities) {
        if($cacheServicePrincipalSigninActivities.AppId -contains $currentServicePrincipalObject.AppId) {
            $currentSpSigninActivity = $cacheServicePrincipalSigninActivities | Where-Object { $_.AppId -eq $currentServicePrincipalObject.AppId }
        } 

        else {
            # Retrieve servicePrincipal sign-in activity from MS Graph
            $currentSpSigninActivity = Get-MgBetaReportServicePrincipalSignInActivity -Filter "AppId eq '$($currentServicePrincipalObject.AppId)'"
            
            # If sign-in activity was found, add it to the cache - else add appId to no-signin-activity list
            if($currentSpSigninActivity) {
                $cacheServicePrincipalSigninActivities += $currentSpSigninActivity
                Write-Host "Found servicePrincipal sign-in activity and added it to cache: $($currentServicePrincipalObject.displayName)"
            }

            else {
                $cacheServicePrincipalsWithoutSigninActivities += $currentServicePrincipalObject.AppId
                Write-Host "Did not find servicePrincipal sign-in activity: $($currentServicePrincipalObject.displayName)"
            }
        }
    }

    # Create reporting object
    [PSCustomObject]@{
        ServicePrincipalDisplayName = $currentServicePrincipalObject.DisplayName
        ServicePrincipalId = $currentServicePrincipalObject.Id
        ServicePrincipalType = $currentServicePrincipalObject.ServicePrincipalType
        ServicePrincipalEnabled = $currentServicePrincipalObject.AccountEnabled
        AppId = $currentServicePrincipalObject.AppId
        AppSignInAudience = $currentServicePrincipalObject.SignInAudience
        AppOwnerOrganizationTenantId = $currentServicePrincipalObject.AppOwnerOrganizationId
        AppOwnerOrganizationTenantName = $currentAppOwnerOrgObject.DisplayName
        AppOwnerOrganizationTenantDomain = $currentAppOwnerOrgObject.DefaultDomainName
        Resource = $currentAppRoleAssignedTo.ResourceDisplayName
        AppRole = $currentAppRole.Value
        AppRoleTier = $appRoleTiers["$($currentAppRole.Value)"]
        AppRoleAssignedDate = $(if($currentAppRoleAssignedTo.CreatedDateTime) {(Get-Date $currentAppRoleAssignedTo.CreatedDateTime -Format 'yyyy-MM-dd')})
        AppRoleName = $currentAppRole.DisplayName
        AppRoleDescription = $currentAppRole.Description
        LastSignInActivity = $currentSpSigninActivity.LastSignInActivity.LastSignInDateTime
        DelegatedClientSignInActivity = $currentSpSigninActivity.DelegatedClientSignInActivity.LastSignInDateTime
        DelegatedResourceSignInActivity = $currentSpSigninActivity.DelegatedResourceSignInActivity.LastSignInDateTime
        ApplicationAuthenticationClientSignInActivity = $currentSpSigninActivity.ApplicationAuthenticationClientSignInActivity.LastSignInDateTime
        ApplicationAuthenticationResourceSignInActivity = $currentSpSigninActivity.ApplicationAuthenticationResourceSignInActivity.LastSignInDateTime
    }
}

$msGraphAppRoleAssignedToReport | Out-GridView

### End of script
