Set-Location "C:\Program Files (x86)\HomeDev\PatchCleaner"

switch ($env:action) {
    "move" { $output = .\PatchCleaner.exe /m }
    "delete" { $output = .\PatchCleaner.exe /d }
    Default { $output = .\PatchCleaner.exe }
}
$ouput | Write-Host
# Ninja-Property-Set -Name "patchcleaner" -Value $output