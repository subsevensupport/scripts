<#
.SYNOPSIS
    Creates or updates a local user account on a Windows machine.

.DESCRIPTION
    This script creates a new local user or updates an existing one.
    It can optionally add the user to the local Administrators group.
    The script is designed for non-interactive execution, reading parameters
    from environment variables.

.PARAMETER Name
    The username for the account. This parameter is mandatory.

.PARAMETER PlainPwd
    The plaintext password for the account. This parameter is mandatory.

.PARAMETER Desc
    An optional description for the user account.

.PARAMETER FullName
    An optional full name for the user account.

.PARAMETER IsAdmin
    A boolean switch ($true or $false) to indicate if the user should be
    added to the local Administrators group. Defaults to $false.

.NOTES
    Security Warning: This script accepts a plaintext password via an environment
    variable due to external constraints. This is insecure. Environment variables
    can be inspected by other processes, exposing the credential.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Name = $env:name,

    [string]$PlainPwd = $env:password,

    [string]$Desc = $env:description,

    [string]$FullName = $env:fullname,

    [bool]$IsAdmin = [bool]::Parse($env:admin)
)

try {
    $securePassword = ConvertTo-SecureString -String $PlainPwd -AsPlainText -Force

    $userParams = @{
        Name     = $Name
        Password = $securePassword
    }
    if ($PSBoundParameters.ContainsKey('Desc')) { $userParams.Description = $Desc }
    if ($PSBoundParameters.ContainsKey('FullName')) { $userParams.FullName = $FullName }


    $userExists = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue

    if (-not $userExists) {
        Write-Verbose "User '$Name' not found. Creating new user."
        if ($PSCmdlet.ShouldProcess("Local machine", "Create user '$Name'")) {
            New-LocalUser @userParams -ErrorAction Stop
        }
    }
    else {
        Write-Verbose "User '$Name' already exists. Updating user."
        if ($PSCmdlet.ShouldProcess("Local machine", "Update user '$Name'")) {
            Set-LocalUser @userParams -ErrorAction Stop
        }
    }

    Write-Output "Successfully processed user '$Name'."

    if ($IsAdmin) {
        Write-Verbose "Attempting to add '$Name' to the Administrators group."
        $isAdminMember = Get-LocalGroupMember -Group 'Administrators' -Member $Name -ErrorAction SilentlyContinue
        
        if (-not $isAdminMember) {
            if ($PSCmdlet.ShouldProcess("Group 'Administrators'", "Add member '$Name'")) {
                Add-LocalGroupMember -Group 'Administrators' -Member $Name -ErrorAction Stop
                Write-Verbose "Successfully added '$Name' to Administrators."
            }
        }
        else {
            Write-Verbose "User '$Name' is already a member of the Administrators group."
        }
    }
}
catch {
    $errorMessage = $_.Exception.Message
    Write-Error "Script failed with error: $errorMessage"
    exit 1
}

exit 0
