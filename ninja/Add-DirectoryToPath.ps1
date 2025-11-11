[CmdletBinding()]
param(
    [string]$Directory = $env:directorytoadd,    
    [switch]$System,  # Add to system PATH instead of user PATH - remember it's only going to work in user if you're running as logged in user
    [switch]$Force    # Skip duplicate check
)

# Validate directory exists
if (!(Test-Path $Directory)) {
    Write-Warning "Directory does not exist: $Directory"
    return 1
}

# Remove trailing backslash if present
$Directory = $Directory.TrimEnd('\')

$target = if ($System) { "Machine" } else { "User" }

# Check for admin rights if modifying system PATH
if ($System -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Administrator rights required to modify SYSTEM PATH. Run PowerShell as Administrator."
    return 1
}

$currentPath = [Environment]::GetEnvironmentVariable("PATH", $target)
$pathDirs = $currentPath -split ';' | Where-Object { $_ -ne '' }

if ($Force -or $pathDirs -notcontains $Directory) {
    $newPath = $currentPath + ";" + $Directory
    [Environment]::SetEnvironmentVariable("PATH", $newPath, $target)
    Write-Host "✓ Added '$Directory' to $target PATH" -ForegroundColor Green
    
    # Apply to current session
    # $env:PATH = [Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [Environment]::GetEnvironmentVariable("PATH", "User")
}
else {
    Write-Error "Directory already exists in $target PATH" -ForegroundColor Yellow
    return 1
}