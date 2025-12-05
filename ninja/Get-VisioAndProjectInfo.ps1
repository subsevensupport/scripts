# Title: Visio and Project Key & Version Isolator (Multi-Version Support)
# Description: Runs OSPP.VBS, aggregates all keys/versions found, and sets Ninja properties (defaults to N/A if missing).

Clear-Host
Write-Host "Searching for Visio and Project licenses..." -ForegroundColor Cyan
Write-Host "-------------------------------------------" -ForegroundColor Gray

# 1. Define possible paths for the OSPP.VBS script
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

# If OSPP is not found, we assume Office isn't installed in a way we can track, 
# so we set everything to N/A immediately and exit.
if (-not $osppPath) {
    Write-Warning "OSPP.VBS not found. Setting properties to N/A."
    Set-NinjaProperty -Name "VisioKey"       -Value "N/A"
    Set-NinjaProperty -Name "VisioVersion"   -Value "N/A"
    Set-NinjaProperty -Name "ProjectKey"     -Value "N/A"
    Set-NinjaProperty -Name "ProjectVersion" -Value "N/A"
    exit
}

# 3. Run the command
$rawOutput = cscript //nologo $osppPath /dstatus

# 4. Storage for results
$visioInstalls = @()   # Will hold objects with Key and Version
$projectInstalls = @() # Will hold objects with Key and Version

$currentProduct = $null
$currentFriendlyName = $null

# 5. Parse Output
foreach ($line in $rawOutput) {
    # Check for License Name
    if ($line -match "LICENSE NAME:\s*(.*)") {
        $licenseName = $matches[1]
        
        # DEBUG: Uncomment the line below to troubleshoot detection logic
        # Write-Host "DEBUG: Found License Name: [$licenseName]" -ForegroundColor Magenta

        # Reset current tracking
        $currentProduct = $null
        $currentFriendlyName = $null
        
        # FILTER: Skip Grace period / Trial keys to prevent duplicates
        if ($licenseName -match "Grace") {
            continue
        }
        
        # Identify Product
        if ($licenseName -match "Visio") {
            $currentProduct = "Visio"
        }
        elseif ($licenseName -match "Project") {
            $currentProduct = "Project"
        }

        # Determine Friendly Name if valid product
        if ($currentProduct) {
            $year = "Unknown Year"
            $edition = "Unknown Edition"

            # Parse Year (Order matters: Check specific years first, then 365, then generic fallbacks)
            if ($licenseName -match "2024") { $year = "2024" }
            elseif ($licenseName -match "2021") { $year = "2021" }
            elseif ($licenseName -match "2019") { $year = "2019" }
            elseif ($licenseName -match "365" -or $licenseName -match "Plan") { $year = "365 (Subscription)" }
            # Fallback: If it says Office16 (like Office16VisioStdR_Retail) but wasn't caught by 2019/2021/365 above, it is 2016.
            elseif ($licenseName -match "2016" -or $licenseName -match "ProX" -or $licenseName -match "StdX" -or $licenseName -match "Office16") { $year = "2016" }
            elseif ($licenseName -match "2013" -or $rawOutput -contains "Office 15") { $year = "2013" }
            
            # Parse Edition
            if ($licenseName -match "Pro") { $edition = "Professional" }
            elseif ($licenseName -match "Std") { $edition = "Standard" }
            elseif ($licenseName -match "Plan 2") { $edition = "Plan 2" }
            elseif ($licenseName -match "Plan 1") { $edition = "Plan 1" }

            # Removed $currentProduct prefix since the property name covers it
            $currentFriendlyName = "$edition $year"
        }
    }

    # Check for Key
    if ($currentProduct -and $line -match "Last 5 characters of installed product key:\s*([A-Z0-9]{5})") {
        $partialKey = $matches[1]
        
        # Store the result in the appropriate array
        $infoObject = [PSCustomObject]@{
            Version = $currentFriendlyName
            Key     = $partialKey
        }

        if ($currentProduct -eq "Visio") {
            $visioInstalls += $infoObject
        }
        elseif ($currentProduct -eq "Project") {
            $projectInstalls += $infoObject
        }
        
        # Reset to avoid duplicates if output format changes
        $currentProduct = $null 
    }
}

# 6. Process Final Results and Set Properties

# --- Helper Function to set N/A or Join properties ---
function Set-NinjaProductInfo {
    param ($ProductName, $InstallList)

    if ($InstallList.Count -eq 0) {
        Write-Host "No $ProductName installations found. Setting N/A." -ForegroundColor DarkGray
        Set-NinjaProperty -Name "$($ProductName)Key"     -Value "N/A"
        Set-NinjaProperty -Name "$($ProductName)Version" -Value "N/A"
    }
    else {
        # Join multiple versions with comma if they exist
        $strKeys = ($InstallList.Key -join ", ")
        $strVers = ($InstallList.Version -join ", ")
        
        Write-Host "Found $ProductName!" -ForegroundColor Green
        Write-Host "   Versions: $strVers"
        Write-Host "   Keys:     $strKeys"
        
        Set-NinjaProperty -Name "$($ProductName)Key"     -Value $strKeys
        Set-NinjaProperty -Name "$($ProductName)Version" -Value $strVers
    }
}

# Set for Visio
Set-NinjaProductInfo -ProductName "Visio" -InstallList $visioInstalls

# Set for Project
Set-NinjaProductInfo -ProductName "Project" -InstallList $projectInstalls