#Requires -Version 3.0

<#
.SYNOPSIS
    Runs an internet speed test using Ookla Cli on the target windows device and saves the results to a Multi-Line Custom Field.
.DESCRIPTION
    Runs an internet speed test using Ookla Cli on the target windows device and saves the results to a Multi-Line Custom Field.
    Script will pick a random time slot from 0 to 60 minutes to run the speed test.
    This lessens the likely hood that multiple devices are testing at the same time.

    The default custom field: speedTestResults
.OUTPUTS
    None
.NOTES
    Minimum OS Architecture Supported: Windows 7, Windows Server 2012
    Minimum PowerShell Version: 3.0
    Release Notes: Renamed script and added Script Variable support
By using this script, you indicate your acceptance of the following legal terms as well as our Terms of Use at https://www.ninjaone.com/terms-of-use.
    Ownership Rights: NinjaOne owns and will continue to own all right, title, and interest in and to the script (including the copyright). NinjaOne is giving you a limited license to use the script in accordance with these legal terms. 
    Use Limitation: You may only use the script for your legitimate personal or internal business purposes, and you may not share the script with another party. 
    Republication Prohibition: Under no circumstances are you permitted to re-publish the script in any script library or website belonging to or under the control of any other software provider. 
    Warranty Disclaimer: The script is provided “as is” and “as available”, without warranty of any kind. NinjaOne makes no promise or guarantee that the script will be free from defects or that it will meet your specific needs or expectations. 
    Assumption of Risk: Your use of the script is at your own risk. You acknowledge that there are certain inherent risks in using the script, and you understand and assume each of those risks. 
    Waiver and Release: You will not hold NinjaOne responsible for any adverse or unintended consequences resulting from your use of the script, and you waive any legal or equitable rights or remedies you may have against NinjaOne relating to your use of the script. 
    EULA: If you are a NinjaOne customer, your use of the script is subject to the End User License Agreement applicable to you (EULA).
.COMPONENT
    Utility
#>
[CmdletBinding()]
param (
    [Parameter()]
    [string]$CustomField = "speedtest",
    [Parameter()]
    [switch]$SkipSleep = [System.Convert]::ToBoolean($env:skipRandomSleepTime)
)
begin {
    if ($env:customFieldName -and $env:customFieldName -notlike "null") { $CustomField = $env:customFieldName }
    # add TLS 1.2 and SSL3 to allow Invoke-WebRequest to work under older PowerShell versions
    if ($PSVersionTable.PSVersion.Major -eq 2) {
        Write-Host "Requires at least PowerShell 3.0 to run."
        exit 1
    }
    else {
        try {
            $TLS12Protocol = [System.Net.SecurityProtocolType] 'Ssl3 , Tls12, Tls11'
            [System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol
        }
        catch {
            Write-Host "Failed to set SecurityProtocol to Tls 1.2, Tls1.1, and Ssl3"
        }
    }
    $CurrentPath = Get-Item -Path ".\"
}
process {
    # Random delay from 0 to 60 minutes in 2 minute time slots
    $MaximumDelay = 60
    $TimeChunks = 2
    $Parts = ($MaximumDelay / $TimeChunks) + 1
    $RandomNumber = Get-Random -Minimum 0 -Maximum $Parts
    $Minutes = $RandomNumber * $TimeChunks
    if (-not $SkipSleep) {
        Start-Sleep -Seconds $($Minutes * 60)
    }

    # Get latest version of speedtest cli
    try {
        $Cli = Invoke-WebRequest -Uri "https://www.speedtest.net/apps/cli" -UseBasicParsing
    }
    catch {
        Write-Host "Failed to query https://www.speedtest.net/apps/cli for speed test cli zip."
        exit 1
    }
    
    # Get the download link
    $Url = $Cli.Links | Where-Object { $_.href -like "*win64*" } | Select-Object -ExpandProperty href
    # Build the URL and destination path
    $InvokeSplat = @{
        Uri     = $Url
        OutFile = Join-Path -Path $CurrentPath -ChildPath $($Url | Split-Path -Leaf)
    }
    # Download the speedtest cli zip
    try {
        Invoke-WebRequest @InvokeSplat -UseBasicParsing
    }
    catch {
        Write-Host "Failed to download speed test cli zip from $Url"
        exit 1
    }
    
    # Build the path to speedtest.exe
    $ExePath = Join-Path -Path $CurrentPath -ChildPath "speedtest.exe"
    $MdPath = Join-Path -Path $CurrentPath -ChildPath "speedtest.md"

    if ($(Get-Command -Name "Expand-Archive" -ErrorAction SilentlyContinue).Count) {
        Expand-Archive -Path $InvokeSplat["OutFile"] -DestinationPath $CurrentPath
    }
    else {
        # Unzip the speedtest cli zip
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        if ((Test-Path -Path $ExePath)) {
            Remove-Item -Path $ExePath, $MdPath -Force -Confirm:$false -ErrorAction Stop
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($InvokeSplat["OutFile"], $CurrentPath)
    }

    $JsonOutput = if ($(Test-Path -Path $ExePath -ErrorAction SilentlyContinue)) {
        # Run speed test and output in a json format
        try {
            Invoke-Command -ScriptBlock {
                & .\speedtest.exe --accept-license --accept-gdpr --format=json
                if (0 -ne $LASTEXITCODE) {
                    Write-Error -Message "Failed to run speedtest.exe."
                }
            }
        }
        catch {
            Remove-Item -Path $ExePath, $MdPath, $InvokeSplat["OutFile"] -Force -Confirm:$false
            Write-Error -Message "Failed to run speedtest.exe."
            exit 1
        }
    }

    if ($JsonOutput) {
        # Convert from Json to PSCustomObject
        $Output = $JsonOutput | ConvertFrom-Json
        # Output the results
        $Results = [PSCustomObject]@{
            Date       = $Output.timestamp | Get-Date
            ISP        = $Output.isp
            Down       = "$([System.Math]::Round($Output.download.bandwidth * 8 / 1MB,0)) Mbps"
            Up         = "$([System.Math]::Round($Output.upload.bandwidth * 8 / 1MB,0)) Mbps"
            ResultUrl  = $Output.result.url
            PacketLoss = $Output.packetLoss
            Jitter     = $Output.ping.jitter
            Latency    = $Output.ping.latency
            Low        = $Output.ping.low
            High       = $Output.ping.high
        } | Out-String
        $Results | Write-Host
        Ninja-Property-Set -Name $CustomField -Value $Results
    }
    Remove-Item -Path $ExePath, $MdPath, $InvokeSplat["OutFile"] -Force -Confirm:$false
    exit 0
}
end {
    
    
    
}