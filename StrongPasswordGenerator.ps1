<#
.Synopsis
    Generate a strong password
.DESCRIPTION
    Generate a strong password with alphanumeric characters (a-z, A-Z, 0-9) and special characters (!#$%&*+-.:?@). 
    Requires atleast a length of 16 characters with 25 as default, defaults to 3 special characters with 2 as a minimum.
.EXAMPLE
    New-StrongPassword -Length 25 -SpecialCharacters 3
#>
function New-StrongPassword {
    [CmdletBinding()]

    param (
        [Parameter(Mandatory=$false)]
        [ValidateRange(16,256)]
        [Int] $Length = 25,
        [Parameter(Mandatory=$false)]
        [ValidateRange(2,5)]
        [Int] $SpecialCharacters = 3
    )

    Process {
        $counter = 0

        do {
            $counter++
            Write-Verbose "Generating strong password to verify for compliance: #$counter"

            # Generate strong password with allowed characters from ASCII coded values
            $generatedPw = -join ((33..33) + (35..38) + (42..43) + (45..46) + (48..58) + (63..90) + (97..122) | Get-Random -Count $Length | ForEach-Object {[char]$_})
        } until (
            # Check generated password for number of required special characters
            [regex]::matches($generatedPw,"[\W]").count -ge $SpecialCharacters -and 

            # Check generated password for number of required alphanumeric characters
            [regex]::matches($generatedPw,"[\w]").count -ge ($Length - $SpecialCharacters) -and 

            # Check generated password starting with alphanumeric character
            $generatedPw -match '^[a-zA-Z]'
        )

        return $generatedPw
    }
}
