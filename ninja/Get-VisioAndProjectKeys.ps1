# Title: Visio and Project Key Isolator
# Description: Runs OSPP.VBS and filters output specifically for Visio and Project keys.

Clear-Host
Write-Host "Searching for Visio and Project licenses..." -ForegroundColor Cyan
Write-Host "-------------------------------------------" -ForegroundColor Gray

# 1. Define possible paths for the OSPP.VBS script (Checks Office 2016/2019/365 and 2013)
$possiblePaths = @(
    "C:\Program Files\Microsoft Office\Office16\OSPP.VBS",
    "C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS",
    "C:\Program Files\Microsoft Office\Office15\OSPP.VBS",
    "C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS"
)

$osppPath = $null

# 2. Find the valid path
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $osppPath = $path
        break
    }
}

if (-not $osppPath) {
    Write-Error "Could not find OSPP.VBS in standard locations."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
}

# 3. Run the command and capture output
# //nologo prevents the Microsoft copyright header from appearing
$rawOutput = cscript //nologo $osppPath /dstatus

# 4. Parse the output for Visio and Project
$foundAny = $false
$currentProduct = $null

foreach ($line in $rawOutput) {
    # Check if the line describes a License Name
    if ($line -match "LICENSE NAME:\s*(.*)") {
        $licenseName = $matches[1]
        
        # Check if it is Visio or Project
        if ($licenseName -match "Visio") {
            $currentProduct = "Visio"
        }
        elseif ($licenseName -match "Project") {
            $currentProduct = "Project"
        }
        else {
            $currentProduct = $null
        }
    }

    # If we are currently inside a Visio or Project block, look for the key
    if ($currentProduct -and $line -match "Last 5 characters of installed product key:\s*([A-Z0-9]{5})") {
        $partialKey = $matches[1]
        
        Write-Host "Found $currentProduct" -ForegroundColor Green
        Write-Host "   Edition: $licenseName" -ForegroundColor Gray
        Write-Host "   Key (Last 5): $partialKey" -ForegroundColor Yellow
        Write-Host ""
        Set-NinjaProperty -Name "$($currentProduct)Key" -Value $partialKey
        
        $foundAny = $true
        $currentProduct = $null # Reset for next block
    }
}

if (-not $foundAny) {
    Write-Host "No active Visio or Project installations were found." -ForegroundColor Red
}