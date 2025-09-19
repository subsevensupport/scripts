Import-Module GroupPolicy

$Domain = (Get-ADDomain).DNSRoot
$GPOs = Get-GPO -All

$result = foreach ($gpo in $GPOs) {
    $xmlPath = "\\$Domain\SYSVOL\$Domain\Policies\{$($gpo.Id)}\User\Preferences\Drives\Drives.xml"
    if (Test-Path $xmlPath) {
        [xml]$xml = Get-Content $xmlPath
        foreach ($drive in $xml.Drives.Drive) {
            [PSCustomObject]@{
                GPO         = $gpo.DisplayName
                DriveLetter = $drive.Properties.letter
                Path        = $drive.Properties.path
                Action      = $drive.Properties.action
            }
        }
    }
}

$result |
Sort-Object DriveLetter, GPO |
Format-Table -AutoSize