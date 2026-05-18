# Secure Boot Certificate Update Validation Script
# Run as Administrator after applying update and rebooting
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host " SECURE BOOT CERTIFICATE UPDATE VALIDATION" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host ""
# 1. Secure Boot state
$sb = Confirm-SecureBootUEFI
Write-Host "[$(if($sb){'PASS'}else{'FAIL'})] Secure Boot Enabled: $sb"
# 2. DB certificates (parse raw bytes for cert subject strings)
$dbBytes = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).Bytes)
# Windows Production PCA 2023 - required on ALL systems
$pca2023 = $dbBytes -match "Windows UEFI CA 2023"
Write-Host "[$(if($pca2023){'PASS'}else{'FAIL'})] Windows UEFI CA 2023 in DB"
# 3P: Check if device has UEFI CA 2011 OR already has UEFI CA 2023 (was a 3P device)
$has3P2011 = $dbBytes -match "UEFI CA 2011"
$has3P2023 = $dbBytes -match "Microsoft UEFI CA 2023"
$is3PDevice = $has3P2011 -or $has3P2023
if ($is3PDevice) {
    $optrom = $dbBytes -match "Option ROM UEFI CA 2023"
    Write-Host "[$(if($has3P2023){'PASS'}else{'FAIL'})] Microsoft UEFI CA 2023 in DB"
    Write-Host "[$(if($optrom){'PASS'}else{'FAIL'})] Option ROM UEFI CA 2023 in DB"
} else {
    $has3P2023 = $true
    $optrom = $true
    Write-Host "[SKIP] Microsoft UEFI CA 2023 - N/A (not a 3P device)"
    Write-Host "[SKIP] Option ROM UEFI CA 2023 - N/A (not a 3P device)"
}
# 3. KEK certificate
$kekBytes = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI kek).Bytes)
$kek23 = $kekBytes -match "KEK 2K CA 2023"
Write-Host "[$(if($kek23){'PASS'}else{'FAIL'})] KEK 2K CA 2023 in KEK"
# 4. Boot manager status
$svcReg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing" -EA SilentlyContinue
$status = if ($svcReg) { $svcReg.UEFICA2023Status } else { "NotFound" }
$bmOk = $status -eq "Updated"
Write-Host "[$(if($bmOk){'PASS'}else{'FAIL'})] Boot Manager re-signed (UEFICA2023Status): $status"
# 5. Event 1808 (fully updated)
$ev1808 = Get-WinEvent -FilterHashtable @{LogName="System"; Id=1808} -MaxEvents 1 -EA SilentlyContinue
$evOk = $null -ne $ev1808
Write-Host "[$(if($evOk){'PASS'}else{'FAIL'})] Event 1808 (fully updated): $evOk"
# 6. Error events
$errorIds = @(1032,1033,1795,1796,1801,1802,1803)
$errors = @()
foreach ($eid in $errorIds) {
    $ev = Get-WinEvent -FilterHashtable @{LogName="System"; Id=$eid; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 5 -EA SilentlyContinue
    if ($ev) { $errors += $ev }
}
if ($errors) {
    Write-Host "[FAIL] Error events found:" -ForegroundColor Red
    $errors | Format-Table TimeCreated, Id, Message -AutoSize
} else {
    Write-Host "[PASS] No error events found"
}
# 7. BitLocker
$bl = $null

# Check if the cmdlet exists before attempting to run it
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
}

if ($bl) {
    $blOn = $bl.ProtectionStatus -eq "On"
    Write-Host "[$(if($blOn){'PASS'}else{'WARN'})] BitLocker Protection: $($bl.ProtectionStatus)"
} else {
    Write-Host "[INFO] BitLocker not configured or command not found on C:"
}

# 8. List all DB certs for reference
Write-Host ""
Write-Host "--- All DB Certificates (subject strings found) ---" -ForegroundColor Gray
$dbRaw = (Get-SecureBootUEFI db).Bytes
$certStore = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
try {
    # Parse EFI_SIGNATURE_LIST to extract individual X.509 certs
    $offset = 0
    while ($offset -lt $dbRaw.Length - 44) {
        # EFI_SIGNATURE_LIST header: SignatureType GUID (16) + ListSize (4) + HeaderSize (4) + SignatureSize (4) = 28
        $listSize = [BitConverter]::ToUInt32($dbRaw, $offset + 16)
        $headerSize = [BitConverter]::ToUInt32($dbRaw, $offset + 20)
        $sigSize = [BitConverter]::ToUInt32($dbRaw, $offset + 24)
        if ($listSize -eq 0 -or $sigSize -eq 0) { break }
        $sigOffset = $offset + 28 + $headerSize
        while ($sigOffset + $sigSize -le $offset + $listSize) {
            try {
                # Skip SignatureOwner GUID (16 bytes), rest is cert data
                $certData = $dbRaw[($sigOffset + 16)..($sigOffset + $sigSize - 1)]
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @(,$certData)
                Write-Host " $($cert.Subject)" -ForegroundColor Gray
            } catch {}
            $sigOffset += $sigSize
        }
        $offset += $listSize
   }
} catch {
    Write-Host " (Could not parse individual certs - raw byte scan used above)" -ForegroundColor DarkGray
}
# Summary
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
$allPass = $sb -and $pca2023 -and $has3P2023 -and $optrom -and $kek23 -and $bmOk -and $evOk -and (-not $errors)
if ($allPass) {
    Write-Host " RESULT: ALL CHECKS PASSED - Device is validated" -ForegroundColor Green
} else {
    Write-Host " RESULT: SOME CHECKS FAILED - Review above" -ForegroundColor Red
}
Write-Host ("=" * 60) -ForegroundColor Cyan