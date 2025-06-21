# NinjaOne OAuth Test Script
# This script tests the OAuth 2.0 client credentials flow with NinjaOne's API

# Load environment variables from .env file
$envPath = Join-Path -Path $PSScriptRoot -ChildPath ".env"
if (Test-Path $envPath) {
    # Read the file, filter out comments and empty lines, then convert to hashtable
    $envVars = Get-Content $envPath | 
        Where-Object { $_ -notmatch '^\s*#' -and $_.Contains('=') } |
        Out-String | 
        ConvertFrom-StringData
    
    # Set each environment variable
    $envVars.GetEnumerator() | ForEach-Object {
        [System.Environment]::SetEnvironmentVariable($_.Key, $_.Value)
    }
} else {
    Write-Error ".env file not found at $envPath"
    exit 1
}

# Configuration
$config = @{
    ClientId = [System.Environment]::GetEnvironmentVariable('NINJA_CLIENT_ID')
    ClientSecret = [System.Environment]::GetEnvironmentVariable('NINJA_CLIENT_SECRET')
    OAuthUrl = [System.Environment]::GetEnvironmentVariable('NINJA_OAUTH_URL')
    ApiUrl = [System.Environment]::GetEnvironmentVariable('NINJA_API_URL')
}

# Validate configuration
$missingConfig = $config.GetEnumerator() | Where-Object { -not $_.Value }
if ($missingConfig) {
    Write-Error "Missing required configuration values: $($missingConfig.Name -join ', ')"
    exit 1
}

# Function to get OAuth token
function Get-NinjaToken {
    [CmdletBinding()]
    param (
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$TokenUrl
    )
    
    try {
        Write-Host "Requesting OAuth token from $TokenUrl"
        
        # Create basic auth header
        $base64Auth = [Convert]::ToBase64String(
            [Text.Encoding]::ASCII.GetBytes("${ClientId}:${ClientSecret}")
        )
        
        $headers = @{
            'Authorization' = "Basic $base64Auth"
            'Content-Type' = 'application/x-www-form-urlencoded'
        }
        
        $body = @{
            grant_type = 'client_credentials'
            scope = 'monitoring'
        }
        
        # Convert body to form-urlencoded format
        $formData = $body.GetEnumerator() | ForEach-Object {
            [System.Web.HttpUtility]::UrlEncode($_.Key) + '=' + [System.Web.HttpUtility]::UrlEncode($_.Value)
        } -join '&'
        
        # Make the request
        $response = Invoke-RestMethod -Uri $TokenUrl \
            -Method Post \
            -Headers $headers \
            -Body $formData \
            -ErrorAction Stop
        
        Write-Host "Successfully obtained access token" -ForegroundColor Green
        return $response
        
    } catch {
        Write-Error "Failed to get access token: $_"
        if ($_.Exception.Response) {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            Write-Error "Response: $responseBody"
        }
        throw
    }
}

# Main execution
try {
    # Get OAuth token
    $tokenResponse = Get-NinjaToken \
        -ClientId $config.ClientId \
        -ClientSecret $config.ClientSecret \
        -TokenUrl $config.OAuthUrl
    $headers = @{
        'Authorization' = "Bearer $accessToken"
    }
    
    Write-Host "successfully auth'd"

    # --- 2. GET AND INCREMENT THE CENTRAL COUNTER ---
    $readUrl = "$NINJA_API_URL/v2/organization/$MSP_ORGANIZATION_ID/custom-fields"
    $allFields = Invoke-RestMethod -Uri $readUrl -Method Get -Headers $headers
    
    $lastNumberString = ($allFields | Where-Object { $_.name -eq $COUNTER_CUSTOM_FIELD_NAME }).value
    
    if (-not $lastNumberString) {
        throw "FATAL ERROR: Central counter field '$COUNTER_CUSTOM_FIELD_NAME' not found on organization ID $MSP_ORGANIZATION_ID."
    }
    
    $lastNumber = [int]$lastNumberString
    $newNumber = $lastNumber + 1

    $writeBody = @{
        "$COUNTER_CUSTOM_FIELD_NAME" = "$newNumber"
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "$NINJA_API_URL/v2/organization/$MSP_ORGANIZATION_ID/custom-fields" -Method Put -Headers $headers -Body $writeBody -ContentType 'application/json'

    # --- 3. WRITE THE NEW TAG TO THE LOCAL DEVICE'S CUSTOM FIELD ---
    # Using 'D5' for a 5-digit number (e.g., 01001). Change to 'D4' for 4 digits.
    $newAssetTagPadded = $newNumber.ToString("D5") 
    
    $deviceWriteBody = @{
        "$DEVICE_ASSET_TAG_FIELD_NAME" = $newAssetTagPadded
    } | ConvertTo-Json
    
    $deviceWriteUrl = "$NINJA_API_URL/v2/device/$localDeviceId/custom-fields"
    Invoke-RestMethod -Uri $deviceWriteUrl -Method Put -Headers $headers -Body $deviceWriteBody -ContentType 'application/json'

    # --- 4. REPORT COMPLETE SUCCESS ---
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "  SUCCESS!" -ForegroundColor Green
    Write-Host "  New Asset Tag: $newAssetTagPadded" -ForegroundColor Cyan
    Write-Host "  Successfully wrote tag to this device's '$DEVICE_ASSET_TAG_FIELD_NAME' field."
    Write-Host "  The central counter has been updated to $newNumber."
    Write-Host "==================================================" -ForegroundColor Green

}
catch {
    # This block runs if any 'throw' command is triggered.
    Write-Host "==================================================" -ForegroundColor Red
    Write-Host "  AN ERROR OCCURRED:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow # $_ holds the error record
    Write-Host "==================================================" -ForegroundColor Red
}