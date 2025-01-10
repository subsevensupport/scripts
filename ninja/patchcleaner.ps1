Set-Location "C:\Program Files (x86)\HomeDev\PatchCleaner"

switch ($action) {
    "move" { $output = .\PatchCleaner.exe /m }
    "delete" { $output = .\PatchCleaner.exe /d }
    Default { $output = .\PatchCleaner.exe }
}

Ninja-Property-Set -Name "patchcleaner" -Value $Output