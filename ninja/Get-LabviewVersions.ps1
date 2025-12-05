# Define the standard install paths for 32-bit and 64-bit LabVIEW
$SearchPaths = @(
    "C:\Program Files\National Instruments\LabVIEW *",
    "C:\Program Files (x86)\National Instruments\LabVIEW *"
)

# Find the folders, then look for the executable
$InstalledVersions = Get-ChildItem -Path $SearchPaths -ErrorAction SilentlyContinue | ForEach-Object {
    $exePath = Join-Path -Path $_.FullName -ChildPath "LabVIEW.exe"
    
    if (Test-Path $exePath) {
        $fileInfo = Get-Item $exePath
        $versionInfo = $fileInfo.VersionInfo
        
        # Determine bitness based on the path
        $bitness = If ($exePath -like "*x86*") { "32-bit" } Else { "64-bit" }

        [PSCustomObject]@{
            Year    = $_.Name.Replace("LabVIEW ", "") # Extracts "2023 Q3", "2016", etc.
            Version = $versionInfo.ProductVersion     # The exact internal version (e.g., 23.3.1)
            Bitness = $bitness
            Path    = $exePath
        }
    }
} | Sort-Object Year, Bitness

$InstalledVersions | Format-Table -AutoSize

if ($InstalledVersions) {
    $VersionsString = ($InstalledVersions | ForEach-Object {
            $shortYear = $_.Year -replace '^20', ''
            $bitSymbol = if ($_.Bitness -eq '32-bit') { 'x86' } else { 'x64' }
        
            "$shortYear$bitSymbol"
        }) -join ", "
}
else {
    $VersionsString = "N/A"
}

Write-Host $VersionsString
Set-NinjaProperty -Name "labviewversions" -Value $VersionsString