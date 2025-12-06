<#
.SYNOPSIS
    Local RMM Script to find PST/OST files and write to a NinjaRMM Custom Field.
.DESCRIPTION
    Scans local fixed drives for .pst and .ost files using CMD.EXE for maximum performance.
    - Parameter $ScanEntireDrive (bool) defaults to True if Ninja Env Var is "true".
    - Formats output for NinjaRMM: "FullFilePath - Size(MB/GB)".
#>
param (
    # We set the default value to an expression.
    # ($env:scanentiredrive -eq "true") evaluates to a real [bool] $true only if the text is "true".
    # This effectively ignores empty strings, nulls, or garbage data, preventing crashes.
    [Parameter(Mandatory = $false)]
    [bool]$ScanEntireDrive = ($env:scanentiredrive -eq "true")
)

# 1. Get all local fixed drives (C:, D:, etc.)
# Filter: DisplayRoot must not be a network share (\\) AND Root must look like a drive letter (C:\)
$Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
    $_.DisplayRoot -notlike "\\*" -and $_.Root -match "^[a-zA-Z]:\\$" 
}

$FoundFiles = @()

Write-Host "Starting Scan (High Performance Mode). Full Drive Scan: $ScanEntireDrive" -ForegroundColor Cyan

foreach ($Drive in $Drives) {
    
    # Determine the search path
    if (-not $ScanEntireDrive) {
        $SearchPath = Join-Path $Drive.Root "Users"
        
        # Check if Users folder exists. Wrapped in try/catch to handle locked drives (e.g. B: Recovery partitions)
        $PathExists = $false
        try {
            $PathExists = Test-Path $SearchPath -ErrorAction Stop
        }
        catch {
            Write-Host "  -> Skipping drive $($Drive.Root) (Access Denied or Invalid)" -ForegroundColor Gray
            continue
        }

        if (-not $PathExists) {
            Write-Host "  -> Skipping drive $($Drive.Root) (No 'Users' folder found)" -ForegroundColor Gray
            continue
        }
    }
    else {
        $SearchPath = $Drive.Root
    }

    Write-Host "  -> Scanning: $SearchPath" -ForegroundColor Cyan

    # OPTIMIZATION:
    # Instead of Get-ChildItem -Include (which is slow), we use cmd.exe /c dir.
    # /s = recurse, /b = bare format (path only), /a-d = files only (no folders)
    # We pipe stderr (2>) to null to suppress "File Not Found" noise if one type is missing.
    $RawPaths = cmd /c dir /s /b /a-d "$SearchPath\*.pst" "$SearchPath\*.ost" 2>$null

    # cmd /c dir returns an array of strings. We process them here.
    foreach ($Path in $RawPaths) {
        # Check if $Path is valid (cmd might return nothing)
        if ([string]::IsNullOrWhiteSpace($Path)) { continue }

        Write-Host "    -> Found: $Path" -ForegroundColor Green

        try {
            # Get file details
            $Item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            
            # Check size to determine unit (MB vs GB)
            if ($Item.Length -lt 1GB) {
                $SizeFormatted = "{0}MB" -f [math]::Round($Item.Length / 1MB, 2)
            }
            else {
                $SizeFormatted = "{0}GB" -f [math]::Round($Item.Length / 1GB, 2)
            }
            
            # Format: "C:\Users\Bob\Documents\archive.pst - 2.55GB" (or 500MB)
            $Entry = "{0} - {1}" -f $Path, $SizeFormatted
            $FoundFiles += $Entry
        }
        catch {
            $Entry = "{0} - Unknown Size" -f $Path
            $FoundFiles += $Entry
        }
    }
}

# 2. Format the result string
if ($FoundFiles.Count -gt 0) {
    $ResultString = $FoundFiles -join ", "
}
else {
    $ResultString = "None"
}

# 3. Output to Console (for RMM logs)
Write-Host "Scan Complete. Result: $ResultString"

# 4. Set NinjaRMM Custom Field
if (Get-Command -Name "Set-NinjaProperty" -ErrorAction SilentlyContinue) {
    # Since the field is now 'Multi-Line', we can write the full string without length checks.
    Set-NinjaProperty -Name "OutlookFiles" -Value $ResultString
    Write-Host "Successfully wrote to Ninja-Property 'OutlookFiles'"
}
else {
    Write-Warning "Set-NinjaProperty command not found."
}