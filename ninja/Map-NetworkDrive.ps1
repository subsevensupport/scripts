# RUN IN CURRENT USER CONTEXT
[CmdletBinding()]
param (
    [string] $DriveLetter = $env:driveletter,
    [string] $RemotePath = $env:remotepath,
    [string] $RemoteUser = $env:remoteuser,
    [string] $RemotePlainPwd = $env:remoteplainpwd
)

try {
    $RemoteSecurePwd = ConvertTo-SecureString -String $RemotePlainPwd -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ($RemoteUser, $RemoteSecurePwd)

    New-PSDrive -Name $DriveLetter -Root $RemotePath -Persist -PSProvider "Filesystem" -Scope "Global" -Credential $Cred
    
}
catch {
    Write-Error "Script failed with error: $_.Exception.Message"
    exit 1
}

exit 0