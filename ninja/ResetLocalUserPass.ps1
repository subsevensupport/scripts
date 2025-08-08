[CmdletBinding()]
param (
    [string]
    $Username = $env:user_name,

    [securestring]
    $NewPassword = (ConvertTo-SecureString -AsPlainText -Force -String $env:new_password),

    [bool]
    $PasswordNeverExpires = [System.Convert]::ToBoolean($env:password_never_expires)
)


$UserAccount = Get-LocalUser -Name $Username
$UserAccount | Set-LocalUser -Password $NewPassword -PasswordNeverExpires $PasswordNeverExpires