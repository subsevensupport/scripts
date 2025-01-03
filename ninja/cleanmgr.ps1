# configure registry keys for windows disk cleanup settings,
# then run it with those settings

# Ask for elevated permissions if required
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

$hive = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
# 2 means option is selected, 0 means unselected
$keys = @(
    @{ Name = "Active Setup Temp Folders"; Value = 2 }
    @{ Name = "BranchCache"; Value = 2 }
    @{ Name = "D3D Shader Cache"; Value = 2 }
    @{ Name = "Delivery Optimization Files"; Value = 2 }
    @{ Name = "Diagnostic Data Viewer database files"; Value = 2 }
    @{ Name = "Downloaded Program Files"; Value = 2 }
    @{ Name = "Feedback Hub Archive log files"; Value = 2 }
    @{ Name = "Internet Cache Files"; Value = 2 }
    @{ Name = "Language Pack"; Value = 2 }
    @{ Name = "Old ChkDsk Files"; Value = 2 }
    @{ Name = "Recycle Bin"; Value = 2 }
    @{ Name = "RetailDemo Offline Content"; Value = 2 }
    @{ Name = "Setup Log Files"; Value = 2 }
    @{ Name = "System error memory dump files"; Value = 2 }
    @{ Name = "System error minidump files"; Value = 2 }
    @{ Name = "Temporary Files"; Value = 2 }
    @{ Name = "Thumbnail Cache"; Value = 2 }
    @{ Name = "Update Cleanup"; Value = 2 }
    @{ Name = "User file versions"; Value = 0 }
    @{ Name = "Windows Defender"; Value = 2 }
    @{ Name = "Windows Error Reporting Files"; Value = 2 }
)

Write-Host "Attempting to write registry keys..."
foreach ($key in $keys) {
    $path = "$hive\$($key.Name)"
    $regkey = try {
        Get-Item -Path $path -ErrorAction Stop
    }
    catch {
        New-Item -Path $path -Force
    }
    
    Set-ItemProperty -Path $regkey.PSPath -Name StateFlags7777 -Value $key.Value
    
}

Write-Host "Running Disk Cleanup..."
# cleanmgr /sagerun:7777
Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:7777' -WindowStyle Hidden -Wait