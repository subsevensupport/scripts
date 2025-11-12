[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $CustomFieldName = $env:customfieldname
)

try {
    $tpm = Get-Tpm

    if ($null -eq $tpm) {
        Write-Host "TPM command returned null"
        Set-NinjaProperty -Name $CustomFieldName -Value "Undetermined"
        return 1
    }

    if ($tpm.TpmPresent) {
        $tpmVersion = Get-CimInstance -Class Win32_Tpm -Namespace root\CIMV2\Security\MicrosoftTpm | Select-Object -Property SpecVersion

        if ($null -eq $tpmVersion.SpecVersion) {
            Write-Host "TPM present but version is null"
            Set-NinjaProperty -Name $CustomFieldName -Value "Present, Null Version"
            return
        }

        $majorVersion = $tpmVersion.SpecVersion.Split(",")[0]

        Write-Host "TPM present with version $majorVersion"
        Set-NinjaProperty -Name $CustomFieldName -Value "Present, $majorVersion"
        return
    }
    else {
        Write-Host "TPM not present"
        Set-NinjaProperty -Name $CustomFieldName -Value "Not Present"
        return
    }
}
catch {
    Write-Host "TPM command failed"
    Set-NinjaProperty -Name $CustomFieldName -Value "Undetermined"
    return 1
}
