[CmdletBinding(SupportsShouldProcess)]
param (
    [switch]$ForceReboot,
    [switch]$IsServer
)

if (Test-Path -Path ".env") {
    $Env = Get-Content -Raw -Path ".env" | ConvertFrom-StringData
    $Env.GetEnumerator() | ForEach-Object {
        $Name, $Value = $_.Name, $_.Value
        Set-Content -Path "env:/$Name" -Value $Value
    }
}

$SERVER_ROLE_CODE_MAP = @{
    '9c00bbd9-ce17-4860-81c7-5c26990c230b' = 'AP' # Application Server
    'e72bd390-6ce1-4539-bc7e-13d610a03b8e' = 'BK' # Backup Server
    '932efb89-d16a-4071-b27b-f57e7958dd6e' = 'DC' # Domain Controller
    '3df1ffe9-69c4-49e4-9a28-a6b2d4e672ec' = 'FS' # File Server
    'e37d0ed1-6690-490c-b826-0a6c0dce5d81' = 'GP' # General Purpose
    'fad57f41-8cd6-452d-86cc-b62f75cbe8c5' = 'GW' # Gateway/Firewall
    '9d0578dc-c74b-4ec8-8aee-bd145431fe72' = 'HV' # Hyper-V Host
    '5dfc8986-a39a-46d0-b9bb-b884b07e22c2' = 'LI' # Licensing Server
    '0cd12c00-030d-4e61-99ad-e9503baec622' = 'MN' # Monitoring Server
    'aa87eff4-21a8-46b0-814c-fbd47e672130' = 'MX' # Mail/Exchange Server
    'f7851c54-fe82-4dee-b40c-a7a5c80ec603' = 'NV' # Network Video Server/Recorder
    '27dac752-7c8d-47c0-92dd-be86c7ba9901' = 'PR' # Print Server
    '3cf88de6-624c-4c68-b56d-7a4f97337c02' = 'RD' # Remote Desktop Server
    '014b6213-00c3-4e70-ba31-22d1d20825fe' = 'SQ' # SQL Server
    '3e4b73b6-8154-4993-ba8b-afe5c2199a5d' = 'UP' # WSUS/Update Server
    '8c31281d-ecc0-42ca-9720-5a95a2637c90' = 'WB' # Web Server
}
$TAG_API_ENDPOINT = "https://tag.lab.subseven.net/next-number"


function Get-ComputerAssetTag {
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    Write-Verbose "Checking current asset tag custom field..."
    try {
        $AssetTag = Ninja-Property-Get assetTag
        if ([string]::IsNullOrWhiteSpace($AssetTag)) {
            Write-Verbose "Asset tag custom field is empty"
            return $null
        }
        
        # Validate asset tag format (should be 4 digits)
        if ($AssetTag -notmatch 4) {
            Write-Warning "Asset tag '$AssetTag' is not in expected 4-digit format. Consider updating it."
        }
        
        Write-Verbose "Found existing asset tag: $AssetTag"
        return $AssetTag.Trim()
    }
    catch {
        throw "Failed to read asset tag from custom field 'assetTag'. Error: $($_.Exception.Message)"
    }
}

function Get-NextAvailableAssetTag {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param ()

    if ($PSCmdlet.ShouldProcess($TAG_API_ENDPOINT, "Get Next Available Asset Tag")) {
        Write-Verbose "Querying tag API for next available asset tag..."
        
        # Validate required environment variables
        if ([string]::IsNullOrWhiteSpace($env:ASSET_TAG_USERNAME)) {
            throw "ASSET_TAG_USERNAME environment variable is required but not set. Please configure credentials in .env file."
        }
        if ([string]::IsNullOrWhiteSpace($env:ASSET_TAG_PASSWORD)) {
            throw "ASSET_TAG_PASSWORD environment variable is required but not set. Please configure credentials in .env file."
        }

        try {
            $Username = $env:ASSET_TAG_USERNAME
            $Password = ConvertTo-SecureString $env:ASSET_TAG_PASSWORD -AsPlainText -Force
            $Cred = New-Object System.Management.Automation.PSCredential ($Username, $Password)
            
            $response = Invoke-RestMethod -Uri $TAG_API_ENDPOINT -Method Get -Credential $Cred -TimeoutSec 30 -ErrorAction Stop
            
            if (-not $response -or -not $response.number) {
                throw "Asset tag API returned invalid response. Expected 'number' property but received: $($response | ConvertTo-Json -Compress)"
            }
            
            $nextTagInt = $response.number
            if ($nextTagInt -lt 1 -or $nextTagInt -gt 9999) {
                throw "Asset tag API returned invalid number '$nextTagInt'. Expected value between 1 and 9999."
            }
            
            $AssetTag = $nextTagInt.ToString().PadLeft(4, '0')
            Write-Verbose "Retrieved asset tag: $AssetTag"
            return $AssetTag
        }
        catch [System.Net.WebException] {
            throw "Failed to connect to asset tag API at '$TAG_API_ENDPOINT'. Check network connectivity and API availability. Error: $($_.Exception.Message)"
        }
        catch [System.UnauthorizedAccessException] {
            throw "Authentication failed for asset tag API. Please verify ASSET_TAG_USERNAME and ASSET_TAG_PASSWORD credentials. Error: $($_.Exception.Message)"
        }
        catch {
            throw "Failed to retrieve asset tag from API. Error: $($_.Exception.Message)"
        }
    }
    else {
        # -WhatIf mode: return placeholder and show what would happen
        Write-Verbose "What if: Would retrieve next available asset tag from API at '$TAG_API_ENDPOINT'" 
        return "XXXX"
    }
}

function Get-ServerRoleCode {
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    Write-Verbose "Reading server primary role from custom field..."
    try {
        $ServerRole = Ninja-Property-Get primaryRole
        
        if ([string]::IsNullOrWhiteSpace($ServerRole)) {
            throw "Primary Server Role custom field 'primaryRole' is empty. Please set the server role before running this script."
        }
        
        $ServerRole = $ServerRole.Trim()
        
        if (-not $SERVER_ROLE_CODE_MAP.ContainsKey($ServerRole)) {
            $ValidRoles = ($SERVER_ROLE_CODE_MAP.Keys | Sort-Object) -join "', '"
            throw "Server role '$ServerRole' is not recognized. Valid roles are: '$ValidRoles'"
        }
        
        $RoleCode = $SERVER_ROLE_CODE_MAP[$ServerRole]
        Write-Verbose "Found server role: $ServerRole -> $RoleCode"
        return $RoleCode
    }
    catch {
        throw "Failed to read server role from custom field 'primaryRole'. Error: $($_.Exception.Message)"
    }
}

function Set-ComputerAssetTag {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^\d{4}$')]
        [string]$AssetTag
    )
    
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Setting Ninja asset tag to $AssetTag")) {
        Write-Verbose "Saving asset tag $AssetTag to custom field..."
        try {
            Ninja-Property-Set assetTag $AssetTag
            Write-Verbose "Successfully saved asset tag $AssetTag to custom field"
            
            # Verify the save was successful
            $VerifyTag = Ninja-Property-Get assetTag
            if ($VerifyTag -ne $AssetTag) {
                throw "Asset tag verification failed. Expected '$AssetTag' but got '$VerifyTag'"
            }
        }
        catch {
            throw "Failed to save asset tag '$AssetTag' to custom field 'assetTag'. Error: $($_.Exception.Message)"
        }
    }
    else {
        Write-Verbose "What if: Would set asset tag custom field to '$AssetTag'"
    }
}

function Get-ComputerTypeCode {
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    Write-Verbose "Building computer type code string..."
    
    if ($IsServer) {
        try {
            $Model = Get-CimInstance -ClassName CIM_ComputerSystem -ErrorAction Stop | Select-Object -ExpandProperty Model
            $FormFactor = if ($Model -match "virtual") { "SV" } else { "SP" }
            Write-Verbose "Server Model: $Model, Form Factor: $FormFactor"
        }
        catch {
            Write-Warning "Failed to detect server model via CIM. Defaulting to physical server (SP). Error: $($_.Exception.Message)"
            $FormFactor = "SP"
        }
        
        # Server role is critical - let exception bubble up if it fails
        $RoleCode = Get-ServerRoleCode
        $TypeCode = "$FormFactor$RoleCode"
        Write-Verbose "Server type code: $TypeCode"
        return $TypeCode
    }

    # For workstations, use non-critical error handling with fallbacks
    try {
        $ChassisType = Get-CimInstance -ClassName CIM_Chassis -ErrorAction Stop | Select-Object -ExpandProperty ChassisTypes
        Write-Verbose "Detected chassis type(s): $($ChassisType -join ', ')"
    }
    catch {
        Write-Warning "Failed to detect chassis type via CIM. Defaulting to WKDT. Error: $($_.Exception.Message)"
        return "WKDT"
    }

    # https://debugactiveprocess.medium.com/determining-device-type-with-wmi-a-comprehensive-guide-to-windows-management-instrumentation-49a867c1ed77
    switch ($ChassisType) {
        { $_ -in 3, 4, 5, 6, 7, 13, 15, 17, 23, 35, 36 } {
            Write-Verbose "Chassis type indicates desktop workstation"
            return "WKDT"
        }
        { $_ -in 8, 9, 10, 14, 16 } {
            Write-Verbose "Chassis type indicates laptop workstation"
            return "WKLT"
        }
        { $_ -in 11, 30, 31, 32 } {
            Write-Verbose "Chassis type indicates mobile workstation"
            return "WKMO"
        }
        Default {
            Write-Warning "Could not recognize chassis code $ChassisType. Defaulting to WKDT..."
            return "WKDT"
        }
    }
}

function Get-ComputerClientCode {
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    Write-Verbose "Reading client code from custom field..."
    try {
        $ClientCode = Ninja-Property-Get clientCode
        
        if ([string]::IsNullOrWhiteSpace($ClientCode)) {
            throw "Client code custom field 'clientCode' is empty. Please set the client code before running this script."
        }
        
        $ClientCode = $ClientCode.Trim().ToUpper()
        
        # Validate client code format (should be 4 characters, alphanumeric)
        if ($ClientCode -notmatch '^[A-Z0-9]{4}$') {
            throw "Client code '$ClientCode' is not in expected format. Expected exactly 4 alphanumeric characters (e.g., 'ABCD', 'XYZ1')."
        }
        
        Write-Verbose "Found client code: $ClientCode"
        return $ClientCode
    }
    catch {
        throw "Failed to read client code from custom field 'clientCode'. Error: $($_.Exception.Message)"
    }
}

function Set-ComputerName {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateLength(14, 14)]
        [ValidatePattern('^[A-Z0-9-]+$')]
        [string]$NewComputerName
    )

    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Rename Computer to $NewComputerName")) {
        Write-Verbose "Renaming computer from '$env:COMPUTERNAME' to '$NewComputerName'..."
        try {
            if ($ForceReboot) {
                Write-Output "Renaming computer and forcing reboot..."
                Rename-Computer -NewName $NewComputerName -Restart -Force -ErrorAction Stop
            }
            else {
                Rename-Computer -NewName $NewComputerName -ErrorAction Stop
                Write-Output "Computer renamed to '$NewComputerName'. Restart required to complete the process."
            }
            Write-Verbose "Computer rename operation completed successfully"
        }
        catch [System.InvalidOperationException] {
            throw "Failed to rename computer. The name '$NewComputerName' may already be in use or invalid. Error: $($_.Exception.Message)"
        }
        catch [System.UnauthorizedAccessException] {
            throw "Failed to rename computer due to insufficient permissions. Run as administrator. Error: $($_.Exception.Message)"
        }
        catch {
            throw "Failed to rename computer from '$env:COMPUTERNAME' to '$NewComputerName'. Error: $($_.Exception.Message)"
        }
    }
    else {
        Write-Verbose "What if: Would rename computer from '$env:COMPUTERNAME' to '$NewComputerName'"
        if ($ForceReboot) {
            Write-Verbose "What if: Would also restart the computer immediately"
        }
    }
}

function New-ComputerName {
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    try {
        Write-Verbose "Starting computer name generation process..."
        
        $ClientCode = Get-ComputerClientCode
        Write-Verbose "Client code: $ClientCode"
        
        $TypeCode = Get-ComputerTypeCode
        Write-Verbose "Type code: $TypeCode"

        $AssetTag = Get-ComputerAssetTag
        if (-not $AssetTag) {
            Write-Verbose "Current asset tag field is empty, retrieving new asset tag..."
            $AssetTag = Get-NextAvailableAssetTag
            
            if ($AssetTag -ne "XXXX") {
                # Only save if not in WhatIf mode
                Set-ComputerAssetTag -AssetTag $AssetTag
                # Verify the asset tag was saved properly
                $SavedAssetTag = Get-ComputerAssetTag
                if ($SavedAssetTag -ne $AssetTag) {
                    throw "Asset tag verification failed after saving. Expected '$AssetTag' but custom field contains '$SavedAssetTag'"
                }
                Write-Verbose "Asset tag $AssetTag saved and verified successfully"
            }
            else {
                Write-Verbose "Using placeholder asset tag for WhatIf simulation"
            }
        }
        else {
            Write-Verbose "Using existing asset tag: $AssetTag"
        }

        $ComputerName = "$ClientCode-$TypeCode-$AssetTag"
        Write-Verbose "Generated computer name: $ComputerName"        
        return $ComputerName
    }
    catch {
        throw "Failed to generate computer name. Error: $($_.Exception.Message)"
    }
}

# Main script execution with error handling
try {
    Write-Output "Starting computer naming process..."
    
    $NewComputerName = New-ComputerName
    Write-Output "Generated computer name: $NewComputerName" 
    
    Set-ComputerName -NewComputerName $NewComputerName
    
    if (-not $WhatIfPreference) {
        Write-Output "Computer naming process completed successfully!" 
        if (-not $ForceReboot) {
            Write-Output "Please restart the computer to complete the rename process." 
        }
    }
}
catch {
    Write-Error "Computer naming process failed: $($_.Exception.Message)"
    Write-Output "Troubleshooting tips:" 
    Write-Output "1. Ensure client code custom field is populated at the organization level" 
    Write-Output "2. For servers, ensure primaryRole custom field is set" 
    Write-Output "3. Verify .env file contains ASSET_TAG_USERNAME and ASSET_TAG_PASSWORD" 
    Write-Output "4. Run as administrator for computer rename operations" 
    Write-Output "5. Check network connectivity to asset tag API"
    exit 1
}