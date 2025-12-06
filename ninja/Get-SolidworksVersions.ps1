# Script to find installed SolidWorks versions and output them as a comma-delimited string

# Define the Registry paths where uninstall information is stored (64-bit and 32-bit)
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# Initialize an array to hold the found versions
$swVersions = @()

# Regex for Strict Name Validation (Fallback method)
# Matches: "SOLIDWORKS 2023", "SOLIDWORKS 2024 SP05", "SOLIDWORKS 2023 SP1.2"
# Rejects: "SOLIDWORKS 2023 API", "SOLIDWORKS 2023 Flow Simulation", "SOLIDWORKS 2023 SDK"
# Explanation: 
#   ^SOLIDWORKS \d{4}  = Starts with SOLIDWORKS and a year
#   (?: SP[\d.]+)?     = Optional group: space, "SP", and dots/digits
#   $                  = MUST END HERE (No extra words allowed)
$strictRegex = '^SOLIDWORKS \d{4}(?: SP[\d.]+)?$'

foreach ($path in $regPaths) {
    # Get all keys, suppressing errors
    $installedSoftware = Get-ItemProperty $path -ErrorAction SilentlyContinue
    
    # Filter: Broad initial match to find candidates (optimizes the loop)
    $matches = $installedSoftware | Where-Object { $_.DisplayName -match '^SOLIDWORKS \d{4}' }

    foreach ($software in $matches) {
        $isValid = $false

        # --- CHECK 1: File Verification (Most Robust) ---
        if ($software.InstallLocation -and (Test-Path (Join-Path $software.InstallLocation "sldworks.exe"))) {
            $isValid = $true
        }
        # --- CHECK 2: Strict Name Regex (Fallback if path is missing) ---
        elseif ($software.DisplayName -match $strictRegex) {
            $isValid = $true
        }

        if ($isValid) {
            # Clean up the name: Remove "SOLIDWORKS " prefix
            $cleanVersion = $software.DisplayName -replace '^SOLIDWORKS\s+', ''
            $swVersions += $cleanVersion
        }
    }
}

# Remove duplicates and sort ascending
$uniqueVersions = $swVersions | Select-Object -Unique | Sort-Object

# Output result
if ($uniqueVersions.Count -gt 0) {
    $resultString = $uniqueVersions -join ", "
}
else {
    $resultString = "N/A"
}

Write-Host $resultString

Set-NinjaProperty -Name "solidworksversions" -Value $resultString