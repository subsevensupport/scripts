[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [string]
    $OldSuffix = $env:old_suffix,
    
    [string]
    $NewSuffix = $env:new_suffix
)

$ADUsers = Get-ADUser -Filter "UserPrincipalName -like '*@$OldSuffix'"
Write-Verbose "Found $($ADUsers.Length) users with suffix $OldSuffix"

$UpdatedUsers = @()

$ADUsers | ForEach-Object {
    $OldUPN = $_.UserPrincipalName
    $NewUPN = $_.UserPrincipalName.Replace($OldSuffix, $NewSuffix)
    $AccountName = $_.SamAccountName
    if ($PSCmdlet.ShouldProcess($AccountName, "Update UPN from $OldUPN to $NewUPN")) {
        Set-ADUser -Identity $_ -UserPrincipalName $NewUPN
        $UpdatedUsers += $AccountName
    }    
}

Write-Verbose "Updated $($UpdatedUsers.Length) users:"
$UpdatedUsers | ForEach-Object {
    $ADUser = Get-ADUser -Filter "SamAccountName -like '$_'"
    Write-Verbose "$($_): UPN is now $($ADUser.UserPrincipalName)"
}