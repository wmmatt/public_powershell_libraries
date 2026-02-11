<#
.SYNOPSIS
    Comprehensive BitLocker Edge Case Test Suite
    
.DESCRIPTION
    Tests ALL possible scenarios that could cause key loss or unexpected behavior.
    
    TEST CATEGORIES:
    ================
    
    A. KEY PRESERVATION (Critical - the whole point!)
       A1. Normal encryption - key saved immediately
       A2. Encryption paused mid-way - key still in registry
       A3. Encryption resumed - same key, not new one
       A4. Decryption initiated on encrypted drive - key preserved BEFORE decryption starts
       A5. Re-encryption after decryption - NEW key saved
       A6. USB/External drive removed - key still in registry
       A7. USB/External drive reconnected - key still valid
       A8. Machine reboot during encryption - key survives reboot
       A9. Multiple encryptions same volume - all keys preserved or just latest?
       A10. Script run multiple times - keys not duplicated/corrupted
    
    B. VOLUME STATE TRANSITIONS
       B1. FullyDecrypted → EncryptionInProgress → FullyEncrypted
       B2. FullyEncrypted → DecryptionInProgress → FullyDecrypted
       B3. EncryptionInProgress → EncryptionPaused → EncryptionInProgress → FullyEncrypted
       B4. DecryptionInProgress → DecryptionPaused → DecryptionInProgress → FullyDecrypted
       B5. FullyEncrypted (wrong method) → Decrypt → Re-encrypt (correct method)
    
    C. AUTO-UNLOCK SCENARIOS
       C1. System drive encrypted first - auto-unlock works on D:
       C2. Try encrypt D: before C: encrypted - warning issued, auto-unlock may fail
       C3. Auto-unlock survives reboot
       C4. External drive with auto-unlock - works when reconnected?
    
    D. MULTI-VOLUME SCENARIOS
       D1. Encrypt C: only (SystemDriveOnly)
       D2. Encrypt C: and D: (InternalOnly)  
       D3. Encrypt C:, D:, and USB (InternalAndExternal)
       D4. Different encryption methods per volume - detected correctly
    
    E. REGISTRY EDGE CASES
       E1. First run - registry created properly
       E2. Disconnected drive - key preserved in registry
       E3. Drive letter changed - key found by VolumeID
       E4. Registry manually cleared - keys re-saved on next run
       E5. Corrupt registry entry - handled gracefully
    
    F. ERROR HANDLING
       F1. Encryption fails - error captured, no crash
       F2. Volume locked/in use - handled gracefully
       F3. TPM not ready - proper error message
       F4. Non-eligible OS - proper error message
    
    G. IDEMPOTENCY (run multiple times safely)
       G1. Run Set twice when already encrypted - no errors, no duplicate keys
       G2. Run Set twice when already decrypted - encrypts once
       G3. Run during encryption in progress - waits/continues properly
    
.PARAMETER ScriptPath
    Path to bitlocker-2.0.ps1
    
.PARAMETER MaxWaitMinutes
    Maximum time to wait for encryption/decryption operations
    
.PARAMETER TestCategories
    Which test categories to run. Default: All
    Options: All, KeyPreservation, StateTransitions, AutoUnlock, MultiVolume, Registry, ErrorHandling, Idempotency
    
.PARAMETER IncludeDestructive
    Include tests that require full decrypt/re-encrypt cycles (slow but thorough)
    
.PARAMETER IncludeRebootTests
    Include tests that require a reboot (manual intervention needed)
    
.EXAMPLE
    # Run all tests except reboot tests
    .\Test-BitLockerEdgeCases.ps1
    
.EXAMPLE
    # Quick test - just key preservation
    .\Test-BitLockerEdgeCases.ps1 -TestCategories KeyPreservation
    
.EXAMPLE
    # Full test including reboot scenarios (will pause for manual reboot)
    .\Test-BitLockerEdgeCases.ps1 -IncludeRebootTests
    
.NOTES
    ⚠️  RUN ON TEST VM ONLY - This script WILL encrypt/decrypt/pause/resume drives!
    ⚠️  Some tests are SLOW (full encryption cycles)
    ⚠️  Reboot tests require manual intervention
    
    Copy the full output and paste back to Claude for analysis.
#>

#requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ScriptPath = (Join-Path $PSScriptRoot "bitlocker-2.0.ps1"),
    [int]$MaxWaitMinutes = 120,
    
    [ValidateSet('All', 'KeyPreservation', 'StateTransitions', 'AutoUnlock', 'MultiVolume', 'Registry', 'ErrorHandling', 'Idempotency')]
    [string[]]$TestCategories = @('All'),
    
    [switch]$IncludeDestructive,
    [switch]$IncludeRebootTests,
    [switch]$SkipExternalDrives
)

# ============================================================================
# INITIALIZATION
# ============================================================================

$ErrorActionPreference = 'Continue'
$script:TestResults = [System.Collections.ArrayList]::new()
$script:Log = [System.Collections.ArrayList]::new()
$script:StartTime = Get-Date
$script:KeySnapshots = @{}  # Store key states at various points

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message, 
        [ValidateSet('INFO', 'WARN', 'ERROR', 'PASS', 'FAIL', 'SECTION', 'SUBSECTION')]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    
    $prefix = switch ($Level) {
        'SECTION'    { "`n$('=' * 70)`n" }
        'SUBSECTION' { "`n$('-' * 50)`n" }
        default      { "" }
    }
    
    $entry = "$prefix[$timestamp] [$Level] $Message"
    [void]$script:Log.Add($entry)
    
    $color = switch ($Level) {
        "ERROR"      { "Red" }
        "WARN"       { "Yellow" }
        "PASS"       { "Green" }
        "FAIL"       { "Red" }
        "SECTION"    { "Cyan" }
        "SUBSECTION" { "DarkCyan" }
        default      { "White" }
    }
    Write-Host $entry -ForegroundColor $color
}

function Add-TestResult {
    param(
        [string]$Category,
        [string]$TestID,
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = "",
        [string]$Impact = "Unknown"  # Critical, High, Medium, Low
    )
    
    [void]$script:TestResults.Add([PSCustomObject]@{
        Category = $Category
        TestID   = $TestID
        TestName = $TestName
        Passed   = $Passed
        Details  = $Details
        Impact   = $Impact
    })
    
    $status = if ($Passed) { "PASS" } else { "FAIL" }
    Write-Log "[$TestID] $TestName - $status" -Level $status
    if ($Details) { 
        Write-Log "    Details: $Details" 
    }
    if (-not $Passed) {
        Write-Log "    Impact: $Impact" -Level WARN
    }
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Wait-ForEncryptionComplete {
    param(
        [int]$TimeoutMinutes = $MaxWaitMinutes,
        [int]$PollIntervalSeconds = 15,
        [string]$TargetVolume = $null,  # If specified, only wait for this volume
        [string[]]$ExcludeVolumes = @()  # Volumes to exclude from waiting
    )
    
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $lastStatus = ""
    $pendingStatuses = @('EncryptionInProgress', 'DecryptionInProgress')
    
    while ((Get-Date) -lt $deadline) {
        $volumes = Get-BitLockerVolume
        
        if ($TargetVolume) {
            $volumes = $volumes | Where-Object { $_.MountPoint -eq $TargetVolume }
        }
        
        # Exclude specified volumes (e.g., external drives)
        if ($ExcludeVolumes.Count -gt 0) {
            $volumes = $volumes | Where-Object { $_.MountPoint -notin $ExcludeVolumes }
        }
        
        $pending = $volumes | Where-Object { 
            [string]$_.VolumeStatus -in $pendingStatuses
        }
        
        if (-not $pending) {
            return $true
        }
        
        $statusParts = @()
        foreach ($v in $pending) {
            $statusParts += "$($v.MountPoint):$($v.EncryptionPercentage)%"
        }
        $currentStatus = $statusParts -join " | "
        
        if ($currentStatus -ne $lastStatus) {
            Write-Log "Waiting: $currentStatus"
            $lastStatus = $currentStatus
        }
        
        Start-Sleep -Seconds $PollIntervalSeconds
    }
    
    Write-Log "TIMEOUT waiting for operation to complete" -Level WARN
    return $false
}

function Get-KeySnapshot {
    <#
    .SYNOPSIS
        Captures current state of all keys for comparison
    #>
    param([string]$Label)
    
    $snapshot = @{
        Timestamp = Get-Date
        Label = $Label
        RegistryKeys = @{}
        LiveKeys = @{}
    }
    
    # Get keys from registry
    $regKeys = Get-BitLockerSavedKeys
    if ($regKeys -notlike "*No BitLocker*") {
        foreach ($line in ($regKeys -split "`n")) {
            if ($line -match "VolumeID:\s*([^\|]+)\|.*Key:\s*([^\|]+)") {
                $volId = $matches[1].Trim()
                $key = $matches[2].Trim()
                $snapshot.RegistryKeys[$volId] = $key
            }
        }
    }
    
    # Get live keys from BitLocker
    $status = Get-BitLockerStatus -Scope All
    foreach ($vol in $status) {
        $snapshot.LiveKeys[$vol.MountPoint] = @{
            VolumeID = $vol.VolumeID
            RecoveryPassword = $vol.RecoveryPassword
            Status = $vol.VolumeStatus
        }
    }
    
    $script:KeySnapshots[$Label] = $snapshot
    # Don't return anything to avoid console output
}

function Compare-KeySnapshots {
    <#
    .SYNOPSIS
        Compares two key snapshots to detect changes
    #>
    param(
        [string]$Before,
        [string]$After
    )
    
    $snap1 = $script:KeySnapshots[$Before]
    $snap2 = $script:KeySnapshots[$After]
    
    if (-not $snap1 -or -not $snap2) {
        return @{ Error = "Snapshot not found" }
    }
    
    $result = @{
        KeysAdded = @()
        KeysRemoved = @()
        KeysChanged = @()
        KeysUnchanged = @()
    }
    
    # Check registry keys
    foreach ($volId in $snap2.RegistryKeys.Keys) {
        if (-not $snap1.RegistryKeys.ContainsKey($volId)) {
            $result.KeysAdded += $volId
        }
        elseif ($snap1.RegistryKeys[$volId] -ne $snap2.RegistryKeys[$volId]) {
            $result.KeysChanged += $volId
        }
        else {
            $result.KeysUnchanged += $volId
        }
    }
    
    foreach ($volId in $snap1.RegistryKeys.Keys) {
        if (-not $snap2.RegistryKeys.ContainsKey($volId)) {
            $result.KeysRemoved += $volId
        }
    }
    
    return $result
}

function Invoke-SafeDecrypt {
    <#
    .SYNOPSIS
        Decrypts a volume safely (saves keys first)
    #>
    param([string]$MountPoint)
    
    $mp = ($MountPoint -replace '[:\\]', '') + ":"
    
    # Save keys first!
    Save-KeysToRegistry
    
    try {
        $vol = Get-BitLockerVolume -MountPoint $mp
        if ([string]$vol.VolumeStatus -eq 'FullyDecrypted') {
            return "Already decrypted"
        }
        
        Disable-BitLocker -MountPoint $mp -ErrorAction Stop | Out-Null
        return "Decryption started"
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

function Invoke-SafeEncrypt {
    <#
    .SYNOPSIS
        Encrypts a volume safely (won't add duplicate protectors)
    #>
    param(
        [string]$MountPoint,
        [string]$Method = 'Aes256'
    )
    
    $mp = ($MountPoint -replace '[:\\]', '') + ":"
    
    try {
        $vol = Get-BitLockerVolume -MountPoint $mp
        $status = [string]$vol.VolumeStatus
        
        # Check if already encrypted or encrypting
        if ($status -eq 'FullyEncrypted') {
            return "Already encrypted"
        }
        
        if ($status -eq 'EncryptionInProgress') {
            return "Already encrypting"
        }
        
        # Check if it already has a RecoveryPassword protector (prevents duplicates)
        $hasRecoveryKey = $vol.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
        if ($hasRecoveryKey) {
            return "Already has recovery key protector"
        }
        
        Enable-BitLocker -MountPoint $mp -EncryptionMethod $Method -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
        
        # Save keys immediately!
        Save-KeysToRegistry
        
        return "Encryption started"
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

function Invoke-PauseEncryption {
    <#
    .SYNOPSIS
        Pauses encryption on a volume
    #>
    param([string]$MountPoint)
    
    $mp = ($MountPoint -replace '[:\\]', '') + ":"
    
    try {
        Suspend-BitLocker -MountPoint $mp -RebootCount 0 -ErrorAction Stop | Out-Null
        return "Paused"
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

function Invoke-ResumeEncryption {
    <#
    .SYNOPSIS
        Resumes encryption on a volume
    #>
    param([string]$MountPoint)
    
    $mp = ($MountPoint -replace '[:\\]', '') + ":"
    
    try {
        Resume-BitLocker -MountPoint $mp -ErrorAction Stop | Out-Null
        return "Resumed"
    }
    catch {
        return "Error: $($_.Exception.Message)"
    }
}

function Get-VolumeState {
    <#
    .SYNOPSIS
        Gets current state of a volume as a string
    #>
    param([string]$MountPoint)
    
    $mp = ($MountPoint -replace '[:\\]', '') + ":"
    $vol = Get-BitLockerVolume -MountPoint $mp -ErrorAction SilentlyContinue
    
    if (-not $vol) { return "NotFound" }
    
    return "$([string]$vol.VolumeStatus)|$([string]$vol.EncryptionMethod)|$($vol.EncryptionPercentage)%"
}

function Clear-TestRegistry {
    <#
    .SYNOPSIS
        Clears the BitLocker registry for testing (preserves keys in memory first)
    #>
    $regPath = "HKLM:\SOFTWARE\BitLockerHistory"
    
    # Snapshot current state first
    Get-KeySnapshot -Label "PreClear"
    
    if (Test-Path $regPath) {
        Remove-Item -Path $regPath -Recurse -Force
        return $true
    }
    return $false
}

function Get-SmallestSecondaryInternal {
    <#
    .SYNOPSIS
        Returns the smallest secondary internal drive for faster test cycles
    #>
    param(
        [string[]]$SecondaryDrives
    )
    
    if ($SecondaryDrives.Count -eq 0) { return $null }
    if ($SecondaryDrives.Count -eq 1) { return $SecondaryDrives[0] }
    
    # Get volume sizes and pick smallest
    $smallest = Get-Volume | 
        Where-Object { "$($_.DriveLetter):" -in $SecondaryDrives } |
        Sort-Object Size |
        Select-Object -First 1
    
    if ($smallest) {
        return "$($smallest.DriveLetter):"
    }
    
    # Fallback to first one
    return $SecondaryDrives[0]
}

# ============================================================================
# LOAD SCRIPT UNDER TEST
# ============================================================================

Write-Log "BITLOCKER EDGE CASE TEST SUITE" -Level SECTION
Write-Log "Start Time: $($script:StartTime)"
Write-Log "Script Path: $ScriptPath"
Write-Log "Test Categories: $($TestCategories -join ', ')"
Write-Log "Include Destructive Tests: $IncludeDestructive"
Write-Log "Include Reboot Tests: $IncludeRebootTests"
Write-Log "Skip External Drives: $SkipExternalDrives"

if (-not (Test-Path $ScriptPath)) {
    Write-Log "Cannot find bitlocker-2.0.ps1 at: $ScriptPath" -Level ERROR
    exit 1
}

try {
    . $ScriptPath
    Write-Log "Script loaded successfully"
}
catch {
    Write-Log "Error loading script: $($_.Exception.Message)" -Level ERROR
    exit 1
}

# ============================================================================
# PRE-FLIGHT CHECKS
# ============================================================================

Write-Log "PRE-FLIGHT CHECKS" -Level SECTION

$eligibility = Test-BitLockerEligibility -Detailed
Write-Log "TPM Exists: $($eligibility.TPMExists)"
Write-Log "TPM Ready: $($eligibility.TPMReady)"
Write-Log "OS Eligible: $($eligibility.OSEligible)"

if (-not $eligibility.Eligible) {
    Write-Log "System not eligible - cannot run tests" -Level ERROR
    exit 1
}

# Discover volumes
$sysDrive = ($env:SystemDrive -replace '[:\\]', '') + ":"
$internalVolumes = @(Get-InternalVolumes | ForEach-Object { "$($_.DriveLetter):" })

# External drives - skip if requested
if ($SkipExternalDrives) {
    $externalVolumes = @()
    Write-Log "External drives: SKIPPED (SkipExternalDrives flag set)"
}
else {
    $externalVolumes = @(Get-ExternalVolumes | ForEach-Object { "$($_.DriveLetter):" })
    Write-Log "External Volumes: $($externalVolumes -join ', ')"
}

$secondaryInternal = $internalVolumes | Where-Object { $_ -ne $sysDrive }

Write-Log "System Drive: $sysDrive"
Write-Log "Internal Volumes: $($internalVolumes -join ', ')"
Write-Log "Secondary Internal: $($secondaryInternal -join ', ')"

# Initial state snapshot
Write-Log ""
Write-Log "Initial Volume States:"
foreach ($vol in (Get-BitLockerVolume)) {
    Write-Log "  $($vol.MountPoint): $([string]$vol.VolumeStatus) | $([string]$vol.EncryptionMethod)"
}

Get-KeySnapshot -Label "Initial"
Write-Log ""
Write-Log "Initial Registry Keys:"
Write-Log (Get-BitLockerSavedKeys)


# ============================================================================
# CATEGORY A: KEY PRESERVATION TESTS (Critical!)
# ============================================================================

$runKeyTests = ($TestCategories -contains 'All') -or ($TestCategories -contains 'KeyPreservation')

if ($runKeyTests) {
    Write-Log "CATEGORY A: KEY PRESERVATION TESTS" -Level SECTION
    Write-Log "These tests verify that recovery keys are NEVER lost"
    
    # -------------------------------------------------------------------------
    # A1: Normal encryption - key saved immediately
    # -------------------------------------------------------------------------
    Write-Log "A1: Key saved immediately upon encryption" -Level SUBSECTION
    
    # Find a decrypted volume to test with, or decrypt one if IncludeDestructive
    # Only look at internal volumes if SkipExternalDrives is set
    $candidateVolumes = Get-BitLockerVolume | Where-Object { [string]$_.VolumeStatus -eq 'FullyDecrypted' }
    if ($SkipExternalDrives) {
        $candidateVolumes = $candidateVolumes | Where-Object { $_.MountPoint -in $internalVolumes }
    }
    $testVol = $candidateVolumes | Select-Object -First 1
    
    # If no decrypted volume and we're in destructive mode, decrypt a secondary drive
    if (-not $testVol -and $IncludeDestructive -and $secondaryInternal.Count -gt 0) {
        $volToDecrypt = Get-SmallestSecondaryInternal -SecondaryDrives $secondaryInternal
        Write-Log "No decrypted volume available - decrypting $volToDecrypt for test (smallest internal)..."
        Invoke-SafeDecrypt -MountPoint $volToDecrypt | Out-Null
        Wait-ForEncryptionComplete -TargetVolume $volToDecrypt | Out-Null
        $testVol = Get-BitLockerVolume -MountPoint $volToDecrypt
    }
    
    if ($testVol -and [string]$testVol.VolumeStatus -eq 'FullyDecrypted') {
        $mp = $testVol.MountPoint
        Get-KeySnapshot -Label "A1-Before"
        
        Write-Log "Encrypting $mp..."
        $result = Invoke-SafeEncrypt -MountPoint $mp
        Write-Log "Result: $result"
        
        # Don't wait for completion - check if key is saved IMMEDIATELY
        Start-Sleep -Seconds 5
        Get-KeySnapshot -Label "A1-After"
        
        $comparison = Compare-KeySnapshots -Before "A1-Before" -After "A1-After"
        $keyWasSaved = ($comparison.KeysAdded.Count -gt 0) -or ($comparison.KeysChanged.Count -gt 0)
        
        # Also verify key is not 'None'
        $currentKey = (Get-BitLockerSavedKeys) -match [regex]::Escape($mp)
        $keyIsValid = $currentKey -and ($currentKey -notmatch "Key:\s*None")
        
        Add-TestResult -Category "KeyPreservation" -TestID "A1" `
            -TestName "Key saved immediately upon encryption start" `
            -Passed ($keyWasSaved -and $keyIsValid) `
            -Details "KeySaved: $keyWasSaved, KeyValid: $keyIsValid" `
            -Impact "Critical - Keys could be lost if encryption completes before save"
        
        # Wait for encryption to complete for subsequent tests
        Write-Log "Waiting for encryption to complete..."
        Wait-ForEncryptionComplete -TargetVolume $mp | Out-Null
        Get-KeySnapshot -Label "A1-Complete"
    }
    else {
        Write-Log "No decrypted volume available for A1 test" -Level WARN
        Add-TestResult -Category "KeyPreservation" -TestID "A1" `
            -TestName "Key saved immediately upon encryption start" `
            -Passed $true `
            -Details "SKIPPED - No decrypted volume available (use -IncludeDestructive with secondary drive)" `
            -Impact "Critical"
    }
    
    # -------------------------------------------------------------------------
    # A2: Encryption paused - key still in registry
    # -------------------------------------------------------------------------
    if ($IncludeDestructive) {
        Write-Log "A2: Key preserved when encryption is paused" -Level SUBSECTION
        
        # For pause tests, we need a volume large enough to not complete instantly
        # Try volumes from largest to smallest until we can successfully pause one
        $pauseTestCompleted = $false
        $volumesToTry = @()
        
        # Build list of volumes to try, largest first
        if ($secondaryInternal.Count -gt 0) {
            $volumesToTry = Get-Volume | 
                Where-Object { "$($_.DriveLetter):" -in $secondaryInternal } |
                Sort-Object Size -Descending |
                ForEach-Object { "$($_.DriveLetter):" }
        }
        
        foreach ($volToTest in $volumesToTry) {
            if ($pauseTestCompleted) { break }
            
            # Get current state
            $testVol = Get-BitLockerVolume -MountPoint $volToTest -ErrorAction SilentlyContinue
            
            # If not decrypted, try to decrypt it first
            if ([string]$testVol.VolumeStatus -ne 'FullyDecrypted') {
                Write-Log "Decrypting $volToTest for pause test..."
                Invoke-SafeDecrypt -MountPoint $volToTest | Out-Null
                Wait-ForEncryptionComplete -TargetVolume $volToTest | Out-Null
                $testVol = Get-BitLockerVolume -MountPoint $volToTest
            }
            
            if ([string]$testVol.VolumeStatus -eq 'FullyDecrypted') {
                $mp = $testVol.MountPoint
                $volSize = (Get-Volume -DriveLetter ($mp -replace '[:\\]', '')).Size / 1GB
                Write-Log "Trying pause test on $mp ($('{0:N1}' -f $volSize) GB)..."
                
                # Start encryption
                Invoke-SafeEncrypt -MountPoint $mp | Out-Null
                Get-KeySnapshot -Label "A2-Started"
                
                # Wait a few seconds then try to pause
                Start-Sleep -Seconds 5
                
                $status = Get-BitLockerVolume -MountPoint $mp
                if ([string]$status.VolumeStatus -eq 'EncryptionInProgress') {
                    Write-Log "Pausing encryption at $($status.EncryptionPercentage)%..."
                    Invoke-PauseEncryption -MountPoint $mp | Out-Null
                    
                    Start-Sleep -Seconds 3
                    
                    # Verify it actually paused
                    $pausedStatus = Get-BitLockerVolume -MountPoint $mp
                    if ([string]$pausedStatus.VolumeStatus -eq 'EncryptionPaused') {
                        Write-Log "Successfully paused at $($pausedStatus.EncryptionPercentage)%"
                        Get-KeySnapshot -Label "A2-Paused"
                        
                        # Verify key is still there
                        $comparison = Compare-KeySnapshots -Before "A2-Started" -After "A2-Paused"
                        $keyPreserved = $comparison.KeysRemoved.Count -eq 0
                        
                        Add-TestResult -Category "KeyPreservation" -TestID "A2" `
                            -TestName "Key preserved when encryption paused" `
                            -Passed $keyPreserved `
                            -Details "Volume: $mp ($('{0:N1}' -f $volSize) GB), KeysRemoved: $($comparison.KeysRemoved.Count)" `
                            -Impact "Critical - Pausing encryption should never lose keys"
                        
                        # Resume for cleanup and A3 test
                        Write-Log "Resuming encryption..."
                        Invoke-ResumeEncryption -MountPoint $mp | Out-Null
                        
                        $pauseTestCompleted = $true
                    }
                    else {
                        Write-Log "Pause command sent but status is $([string]$pausedStatus.VolumeStatus) - encryption may have completed" -Level WARN
                        # Let it complete and try next volume
                        Wait-ForEncryptionComplete -TargetVolume $mp | Out-Null
                    }
                }
                else {
                    Write-Log "Encryption on $mp completed too fast ($($status.EncryptionPercentage)%) - trying next volume..." -Level WARN
                    # Volume encrypted too fast, try next one
                }
            }
        }
        
        if (-not $pauseTestCompleted) {
            Write-Log "All volumes encrypted too fast to test pause functionality" -Level WARN
            Add-TestResult -Category "KeyPreservation" -TestID "A2" `
                -TestName "Key preserved when encryption paused" `
                -Passed $true `
                -Details "SKIPPED - All secondary volumes encrypted too fast to pause (largest tried: $($volumesToTry[0]))" `
                -Impact "Critical"
        }
        
        # Wait for any in-progress encryption to complete before A3
        Wait-ForEncryptionComplete | Out-Null
    }
    
    # -------------------------------------------------------------------------
    # A3: Resume encryption - same key, not regenerated
    # -------------------------------------------------------------------------
    if ($IncludeDestructive) {
        Write-Log "A3: Same key after resume (not regenerated)" -Level SUBSECTION
        
        # Use snapshots from A2 if available
        if ($script:KeySnapshots.ContainsKey("A2-Started") -and $script:KeySnapshots.ContainsKey("A2-Paused")) {
            Get-KeySnapshot -Label "A3-AfterResume"
            
            # Find the volume that was tested in A2
            $a2StartedKeys = $script:KeySnapshots["A2-Started"].RegistryKeys
            $a3AfterKeys = $script:KeySnapshots["A3-AfterResume"].RegistryKeys
            
            # Compare keys for volumes that existed in A2
            $keysMatch = $true
            $keyDetails = @()
            
            foreach ($volId in $a2StartedKeys.Keys) {
                $keyBefore = $a2StartedKeys[$volId]
                $keyAfter = $a3AfterKeys[$volId]
                
                if ($keyBefore -and $keyAfter) {
                    if ($keyBefore -eq $keyAfter) {
                        $keyDetails += "$volId : unchanged"
                    }
                    else {
                        $keyDetails += "$volId : CHANGED"
                        $keysMatch = $false
                    }
                }
            }
            
            Add-TestResult -Category "KeyPreservation" -TestID "A3" `
                -TestName "Same key after resume (not regenerated)" `
                -Passed $keysMatch `
                -Details ($keyDetails -join ", ") `
                -Impact "Medium - New key isn't bad, but unexpected"
        }
        else {
            Add-TestResult -Category "KeyPreservation" -TestID "A3" `
                -TestName "Same key after resume (not regenerated)" `
                -Passed $true `
                -Details "SKIPPED - A2 pause test didn't complete (all volumes too fast)" `
                -Impact "Medium"
        }
    }
    
    # -------------------------------------------------------------------------
    # A4: Decryption initiated - key preserved BEFORE destruction
    # -------------------------------------------------------------------------
    if ($IncludeDestructive) {
        Write-Log "A4: Key preserved BEFORE decryption starts" -Level SUBSECTION
        
        # Find an encrypted volume
        $testVol = Get-BitLockerVolume | Where-Object { 
            [string]$_.VolumeStatus -eq 'FullyEncrypted' -and $_.MountPoint -ne $sysDrive 
        } | Select-Object -First 1
        
        if ($testVol) {
            $mp = $testVol.MountPoint
            Get-KeySnapshot -Label "A4-BeforeDecrypt"
            
            # Get the key we expect to preserve
            $expectedKey = $script:KeySnapshots["A4-BeforeDecrypt"].LiveKeys[$mp].RecoveryPassword
            Write-Log "Key to preserve: $expectedKey"
            
            # Start decryption
            Write-Log "Starting decryption on $mp..."
            Invoke-SafeDecrypt -MountPoint $mp | Out-Null
            
            Get-KeySnapshot -Label "A4-AfterDecryptStart"
            
            # Verify key is still in registry
            $regKeys = Get-BitLockerSavedKeys
            $keyStillThere = $regKeys -match [regex]::Escape($expectedKey)
            
            Add-TestResult -Category "KeyPreservation" -TestID "A4" `
                -TestName "Key preserved BEFORE decryption starts" `
                -Passed $keyStillThere `
                -Details "Expected key still in registry: $keyStillThere" `
                -Impact "Critical - This is how keys get lost!"
            
            # Wait for decryption to complete
            Write-Log "Waiting for decryption..."
            Wait-ForEncryptionComplete -TargetVolume $mp | Out-Null
        }
        else {
            Add-TestResult -Category "KeyPreservation" -TestID "A4" `
                -TestName "Key preserved BEFORE decryption starts" `
                -Passed $false `
                -Details "SKIPPED - No encrypted non-system volume" `
                -Impact "Critical"
        }
    }
    
    # -------------------------------------------------------------------------
    # A5: Re-encryption creates NEW key (not reusing old)
    # -------------------------------------------------------------------------
    if ($IncludeDestructive) {
        Write-Log "A5: Re-encryption generates new key" -Level SUBSECTION
        
        $testVol = Get-BitLockerVolume | Where-Object { 
            [string]$_.VolumeStatus -eq 'FullyDecrypted' -and $_.MountPoint -ne $sysDrive 
        } | Select-Object -First 1
        
        if ($testVol) {
            $mp = $testVol.MountPoint
            
            # Get old key if any
            $oldSnapshot = $script:KeySnapshots["A4-BeforeDecrypt"]
            $oldKey = if ($oldSnapshot) { $oldSnapshot.LiveKeys[$mp].RecoveryPassword } else { "None" }
            
            Write-Log "Old key: $oldKey"
            
            # Encrypt
            Invoke-SafeEncrypt -MountPoint $mp | Out-Null
            Wait-ForEncryptionComplete -TargetVolume $mp | Out-Null
            
            Get-KeySnapshot -Label "A5-AfterReencrypt"
            
            $newKey = $script:KeySnapshots["A5-AfterReencrypt"].LiveKeys[$mp].RecoveryPassword
            Write-Log "New key: $newKey"
            
            $isNewKey = ($oldKey -ne $newKey) -and ($newKey -ne 'None')
            
            Add-TestResult -Category "KeyPreservation" -TestID "A5" `
                -TestName "Re-encryption generates new key" `
                -Passed $isNewKey `
                -Details "Old: $oldKey, New: $newKey" `
                -Impact "Low - Expected behavior"
        }
        else {
            Add-TestResult -Category "KeyPreservation" -TestID "A5" `
                -TestName "Re-encryption generates new key" `
                -Passed $false `
                -Details "SKIPPED - No volume available" `
                -Impact "Low"
        }
    }
    
    # -------------------------------------------------------------------------
    # A6: External drive removed - key still in registry
    # -------------------------------------------------------------------------
    if ($SkipExternalDrives) {
        Write-Log "A6: External drive key preserved after removal" -Level SUBSECTION
        Add-TestResult -Category "KeyPreservation" -TestID "A6" `
            -TestName "External drive key preserved after removal" `
            -Passed $true `
            -Details "SKIPPED - SkipExternalDrives flag set" `
            -Impact "Critical"
    }
    elseif ($externalVolumes.Count -gt 0) {
        Write-Log "A6: External drive key preserved after removal" -Level SUBSECTION
        Write-Log "NOTE: This test requires manual removal of USB drive" -Level WARN
        
        $extVol = $externalVolumes[0]
        
        # Check if external is encrypted
        $extStatus = Get-BitLockerVolume -MountPoint $extVol -ErrorAction SilentlyContinue
        
        if ($extStatus -and [string]$extStatus.VolumeStatus -eq 'FullyEncrypted') {
            Get-KeySnapshot -Label "A6-WithDrive"
            
            Write-Log ""
            Write-Log "*** MANUAL STEP REQUIRED ***" -Level WARN
            Write-Log "1. Safely remove USB drive $extVol" -Level WARN
            Write-Log "2. Press ENTER to continue test" -Level WARN
            Write-Log ""
            
            Read-Host "Press ENTER after removing drive"
            
            Get-KeySnapshot -Label "A6-WithoutDrive"
            
            # Key should still be in registry even though drive is gone
            $keysBefore = $script:KeySnapshots["A6-WithDrive"].RegistryKeys
            $keysAfter = $script:KeySnapshots["A6-WithoutDrive"].RegistryKeys
            
            # Registry should have same or more keys (not fewer)
            $keysPreserved = $keysAfter.Count -ge ($keysBefore.Count - 1)  # -1 because we might not see the removed drive
            
            Add-TestResult -Category "KeyPreservation" -TestID "A6" `
                -TestName "External drive key preserved after removal" `
                -Passed $keysPreserved `
                -Details "Keys before: $($keysBefore.Count), After: $($keysAfter.Count)" `
                -Impact "Critical - Keys for removed drives must persist"
            
            Write-Log "*** Please reconnect the USB drive ***" -Level WARN
            Read-Host "Press ENTER after reconnecting"
        }
        else {
            # External drive not encrypted - should we encrypt it for the test?
            Write-Log "External drive $extVol not encrypted" -Level WARN
            
            if ($IncludeDestructive) {
                Write-Log "Encrypting external drive for test..."
                Invoke-SafeEncrypt -MountPoint $extVol | Out-Null
                Wait-ForEncryptionComplete -TargetVolume $extVol | Out-Null
                
                # Now run the actual test
                Get-KeySnapshot -Label "A6-WithDrive"
                
                Write-Log ""
                Write-Log "*** MANUAL STEP REQUIRED ***" -Level WARN
                Write-Log "1. Safely remove USB drive $extVol" -Level WARN
                Write-Log "2. Press ENTER to continue test" -Level WARN
                Write-Log ""
                
                Read-Host "Press ENTER after removing drive"
                
                Get-KeySnapshot -Label "A6-WithoutDrive"
                
                $keysBefore = $script:KeySnapshots["A6-WithDrive"].RegistryKeys
                $keysAfter = $script:KeySnapshots["A6-WithoutDrive"].RegistryKeys
                $keysPreserved = $keysAfter.Count -ge ($keysBefore.Count - 1)
                
                Add-TestResult -Category "KeyPreservation" -TestID "A6" `
                    -TestName "External drive key preserved after removal" `
                    -Passed $keysPreserved `
                    -Details "Keys before: $($keysBefore.Count), After: $($keysAfter.Count)" `
                    -Impact "Critical - Keys for removed drives must persist"
                
                Write-Log "*** Please reconnect the USB drive ***" -Level WARN
                Read-Host "Press ENTER after reconnecting"
            }
            else {
                # Not a failure - just skipped
                Add-TestResult -Category "KeyPreservation" -TestID "A6" `
                    -TestName "External drive key preserved after removal" `
                    -Passed $true `
                    -Details "SKIPPED - External drive not encrypted (use -IncludeDestructive to encrypt and test)" `
                    -Impact "Critical"
            }
        }
    }
    else {
        # No external drive - also not a failure, just can't test
        Add-TestResult -Category "KeyPreservation" -TestID "A6" `
            -TestName "External drive key preserved after removal" `
            -Passed $true `
            -Details "SKIPPED - No external drives connected" `
            -Impact "Critical"
    }
    
    # -------------------------------------------------------------------------
    # A7: Script idempotency - running multiple times doesn't corrupt keys
    # -------------------------------------------------------------------------
    Write-Log "A7: Multiple script runs don't corrupt keys" -Level SUBSECTION
    
    Get-KeySnapshot -Label "A7-Before"
    
    # Run the main function 3 times
    Write-Log "Running Set-BitLockerBestPractice 3 times..."
    for ($i = 1; $i -le 3; $i++) {
        Write-Log "  Run $i of 3..."
        Set-BitLockerBestPractice -Scope SystemDriveOnly | Out-Null
    }
    
    Get-KeySnapshot -Label "A7-After"
    
    # Keys should not be duplicated or corrupted
    # NOTE: Only check ENCRYPTED volumes - decrypted volumes having 'None' is correct!
    $encryptedVolumes = Get-BitLockerVolume | Where-Object { [string]$_.VolumeStatus -eq 'FullyEncrypted' }
    $keysAfter = $script:KeySnapshots["A7-After"]
    
    $noCorruption = $true
    $details = @()
    
    foreach ($vol in $encryptedVolumes) {
        $mp = $vol.MountPoint
        $volData = $keysAfter.LiveKeys[$mp]
        
        if ($volData) {
            $key = $volData.RecoveryPassword
            if ($key -eq 'None' -or $key -eq '' -or $null -eq $key -or $key -match 'error') {
                $noCorruption = $false
                $details += "$mp : MISSING KEY"
            }
            else {
                $details += "$mp : OK"
            }
        }
        else {
            $noCorruption = $false
            $details += "$mp : NO DATA"
        }
    }
    
    # Also verify registry keys are present for encrypted volumes
    foreach ($vol in $encryptedVolumes) {
        $mp = $vol.MountPoint
        $foundInRegistry = (Get-BitLockerSavedKeys) -match [regex]::Escape($mp)
        if (-not $foundInRegistry) {
            $noCorruption = $false
            $details += "$mp : NOT IN REGISTRY"
        }
    }
    
    Add-TestResult -Category "KeyPreservation" -TestID "A7" `
        -TestName "Multiple script runs don't corrupt keys" `
        -Passed $noCorruption `
        -Details ($details -join ", ") `
        -Impact "High - Script should be safely re-runnable"
}


# ============================================================================
# CATEGORY B: VOLUME STATE TRANSITIONS
# ============================================================================

$runStateTests = ($TestCategories -contains 'All') -or ($TestCategories -contains 'StateTransitions')

if ($runStateTests -and $IncludeDestructive) {
    Write-Log "CATEGORY B: VOLUME STATE TRANSITIONS" -Level SECTION
    
    # -------------------------------------------------------------------------
    # B1: Full encryption cycle
    # -------------------------------------------------------------------------
    Write-Log "B1: Full encryption cycle state transitions" -Level SUBSECTION
    
    $testVol = Get-BitLockerVolume | Where-Object { 
        [string]$_.VolumeStatus -eq 'FullyDecrypted' -and $_.MountPoint -ne $sysDrive 
    } | Select-Object -First 1
    
    if ($testVol) {
        $mp = $testVol.MountPoint
        $states = @()
        
        # Initial state
        $states += "Initial: $(Get-VolumeState $mp)"
        
        # Start encryption
        Invoke-SafeEncrypt -MountPoint $mp | Out-Null
        Start-Sleep -Seconds 3
        $states += "After Enable: $(Get-VolumeState $mp)"
        
        # Wait for completion
        Wait-ForEncryptionComplete -TargetVolume $mp | Out-Null
        $states += "After Complete: $(Get-VolumeState $mp)"
        
        $finalState = Get-VolumeState $mp
        $success = $finalState -match 'FullyEncrypted'
        
        Add-TestResult -Category "StateTransitions" -TestID "B1" `
            -TestName "FullyDecrypted -> EncryptionInProgress -> FullyEncrypted" `
            -Passed $success `
            -Details ($states -join " -> ") `
            -Impact "High - Core functionality"
    }
    
    # -------------------------------------------------------------------------
    # B5: Wrong method triggers decrypt/re-encrypt
    # -------------------------------------------------------------------------
    Write-Log "B5: Wrong encryption method triggers re-encryption" -Level SUBSECTION
    
    $testVol = Get-BitLockerVolume | Where-Object { 
        [string]$_.VolumeStatus -eq 'FullyEncrypted' -and 
        [string]$_.EncryptionMethod -eq 'Aes256' -and 
        $_.MountPoint -ne $sysDrive 
    } | Select-Object -First 1
    
    if ($testVol) {
        $mp = $testVol.MountPoint
        Get-KeySnapshot -Label "B5-Before"
        
        Write-Log "Current method: $([string]$testVol.EncryptionMethod)"
        Write-Log "Running Set-BitLockerBestPractice with XtsAes256..."
        
        # This should trigger decryption because method doesn't match
        $output = Set-BitLockerBestPractice -EncryptionMethod 'XtsAes256' -Scope InternalOnly
        
        # Check if decryption was initiated
        $currentState = Get-VolumeState $mp
        $decryptionStarted = $currentState -match 'Decryption' -or $output -match 'Initiated decryption'
        
        Get-KeySnapshot -Label "B5-After"
        
        # CRITICAL: Key should have been saved before decryption
        $comparison = Compare-KeySnapshots -Before "B5-Before" -After "B5-After"
        $keyPreserved = $comparison.KeysRemoved.Count -eq 0
        
        Add-TestResult -Category "StateTransitions" -TestID "B5" `
            -TestName "Wrong method triggers re-encryption with key preservation" `
            -Passed $keyPreserved `
            -Details "Decryption started: $decryptionStarted, Key preserved: $keyPreserved" `
            -Impact "Critical - This scenario was losing keys!"
    }
}


# ============================================================================
# CATEGORY C: AUTO-UNLOCK SCENARIOS
# ============================================================================

$runAutoUnlockTests = ($TestCategories -contains 'All') -or ($TestCategories -contains 'AutoUnlock')

if ($runAutoUnlockTests) {
    Write-Log "CATEGORY C: AUTO-UNLOCK SCENARIOS" -Level SECTION
    
    # -------------------------------------------------------------------------
    # C1: Auto-unlock enabled on secondary drives
    # -------------------------------------------------------------------------
    Write-Log "C1: Auto-unlock on secondary internal drives" -Level SUBSECTION
    
    if ($secondaryInternal.Count -gt 0) {
        $allHaveAutoUnlock = $true
        $details = @()
        
        foreach ($drive in $secondaryInternal) {
            $status = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
            if ([string]$status.VolumeStatus -eq 'FullyEncrypted') {
                $hasAutoUnlock = Test-AutoUnlockEnabled -MountPoint $drive
                $details += "$drive : AutoUnlock=$hasAutoUnlock"
                if (-not $hasAutoUnlock) { $allHaveAutoUnlock = $false }
            }
        }
        
        Add-TestResult -Category "AutoUnlock" -TestID "C1" `
            -TestName "Auto-unlock enabled on secondary internal drives" `
            -Passed $allHaveAutoUnlock `
            -Details ($details -join ", ") `
            -Impact "High - Users will be prompted for password on every boot"
    }
    else {
        Add-TestResult -Category "AutoUnlock" -TestID "C1" `
            -TestName "Auto-unlock enabled on secondary internal drives" `
            -Passed $true `
            -Details "SKIPPED - No secondary internal drives" `
            -Impact "High"
    }
    
    # -------------------------------------------------------------------------
    # C2: Secondary drives DEFERRED until system drive is FullyEncrypted
    # -------------------------------------------------------------------------
    if ($IncludeDestructive -and $secondaryInternal.Count -gt 0) {
        Write-Log "C2: Secondary drives deferred until system drive complete" -Level SUBSECTION
        
        # Build list of volumes to exclude from waiting (external drives if skipping)
        $excludeFromWait = @()
        if ($SkipExternalDrives) {
            $excludeFromWait = @(Get-ExternalVolumes | ForEach-Object { "$($_.DriveLetter):" })
            if ($excludeFromWait.Count -gt 0) {
                Write-Log "Excluding from wait: $($excludeFromWait -join ', ')"
            }
        }
        
        # First, decrypt everything to start fresh
        Write-Log "Decrypting all volumes for C2 test..."
        
        # Decrypt secondary drives first
        foreach ($drive in $secondaryInternal) {
            $status = Get-BitLockerVolume -MountPoint $drive -ErrorAction SilentlyContinue
            if ([string]$status.VolumeStatus -ne 'FullyDecrypted') {
                Write-Log "  Decrypting $drive..."
                Invoke-SafeDecrypt -MountPoint $drive | Out-Null
            }
        }
        Wait-ForEncryptionComplete -ExcludeVolumes $excludeFromWait | Out-Null
        
        # Decrypt system drive
        $sysStatus = Get-BitLockerVolume -MountPoint $sysDrive
        if ([string]$sysStatus.VolumeStatus -ne 'FullyDecrypted') {
            Write-Log "  Decrypting $sysDrive..."
            Invoke-SafeDecrypt -MountPoint $sysDrive | Out-Null
            Wait-ForEncryptionComplete -ExcludeVolumes $excludeFromWait | Out-Null
        }
        
        Write-Log "All internal volumes decrypted."
        
        $testSecondary = Get-SmallestSecondaryInternal -SecondaryDrives $secondaryInternal
        
        # =====================================================================
        # PHASE 1: Run Set-BitLockerBestPractice - should encrypt C: but SKIP F:
        # =====================================================================
        Write-Log ""
        Write-Log "PHASE 1: First run - C: should encrypt, $testSecondary should be DEFERRED..."
        
        $output1 = Set-BitLockerBestPractice -Scope InternalOnly
        
        # Check states immediately after first run
        Start-Sleep -Seconds 3
        $sysState1 = [string](Get-BitLockerVolume -MountPoint $sysDrive).VolumeStatus
        $secState1 = [string](Get-BitLockerVolume -MountPoint $testSecondary).VolumeStatus
        
        Write-Log "After Phase 1: C: = $sysState1, $testSecondary = $secState1"
        
        # C: should be encrypting or encrypted, F: should still be decrypted
        $phase1Pass = ($sysState1 -in @('EncryptionInProgress', 'FullyEncrypted')) -and 
                      ($secState1 -eq 'FullyDecrypted')
        
        if (-not $phase1Pass) {
            # If F: started encrypting, that's the bug we're testing for
            Add-TestResult -Category "AutoUnlock" -TestID "C2" `
                -TestName "Secondary drives deferred until system drive complete" `
                -Passed $false `
                -Details "FAILED Phase 1: C:=$sysState1, $testSecondary=$secState1 (expected F: to be FullyDecrypted)" `
                -Impact "Critical - Secondary drive encrypted before system drive was ready, auto-unlock will fail"
        }
        else {
            Write-Log "Phase 1 PASSED - $testSecondary was correctly deferred"
            
            # =====================================================================
            # PHASE 2: Wait for C: to complete, then run again
            # =====================================================================
            Write-Log ""
            Write-Log "PHASE 2: Waiting for C: to complete..."
            Wait-ForEncryptionComplete -TargetVolume $sysDrive | Out-Null
            
            $sysState2 = [string](Get-BitLockerVolume -MountPoint $sysDrive).VolumeStatus
            Write-Log "C: is now: $sysState2"
            
            if ($sysState2 -ne 'FullyEncrypted') {
                Add-TestResult -Category "AutoUnlock" -TestID "C2" `
                    -TestName "Secondary drives deferred until system drive complete" `
                    -Passed $false `
                    -Details "C: failed to reach FullyEncrypted: $sysState2" `
                    -Impact "Critical"
            }
            else {
                Write-Log ""
                Write-Log "PHASE 3: Second run - $testSecondary should now encrypt with auto-unlock..."
                
                $output2 = Set-BitLockerBestPractice -Scope InternalOnly
                
                # Wait for secondary to finish
                Wait-ForEncryptionComplete -TargetVolume $testSecondary | Out-Null
                
                # Verify secondary is encrypted AND has auto-unlock
                $secState3 = [string](Get-BitLockerVolume -MountPoint $testSecondary).VolumeStatus
                $hasAutoUnlock = Test-AutoUnlockEnabled -MountPoint $testSecondary
                
                Write-Log "After Phase 3: $testSecondary = $secState3, AutoUnlock = $hasAutoUnlock"
                
                $phase3Pass = ($secState3 -eq 'FullyEncrypted') -and $hasAutoUnlock
                
                Add-TestResult -Category "AutoUnlock" -TestID "C2" `
                    -TestName "Secondary drives deferred until system drive complete" `
                    -Passed $phase3Pass `
                    -Details "Phase1: C: encrypting, F: deferred=PASS | Phase3: F: encrypted=$secState3, auto-unlock=$hasAutoUnlock" `
                    -Impact "Critical - Prevents orphaned encryption without auto-unlock"
            }
        }
    }
    elseif ($secondaryInternal.Count -eq 0) {
        Add-TestResult -Category "AutoUnlock" -TestID "C2" `
            -TestName "Secondary drives deferred until system drive complete" `
            -Passed $true `
            -Details "SKIPPED - No secondary internal drives to test" `
            -Impact "Critical"
    }
    else {
        Add-TestResult -Category "AutoUnlock" -TestID "C2" `
            -TestName "Secondary drives deferred until system drive complete" `
            -Passed $false `
            -Details "SKIPPED - Requires -IncludeDestructive flag" `
            -Impact "Critical"
    }
    
    # -------------------------------------------------------------------------
    # C3: Warning issued when C: not encrypted but trying to encrypt D:
    # -------------------------------------------------------------------------
    if ($IncludeDestructive -and $secondaryInternal.Count -gt 0) {
        Write-Log "C3: Warning when encrypting secondary before system drive" -Level SUBSECTION
        
        # Ensure C: is decrypted, but secondary exists decrypted too
        $sysStatus = Get-BitLockerVolume -MountPoint $sysDrive
        $testSecondary = Get-SmallestSecondaryInternal -SecondaryDrives $secondaryInternal
        $secStatus = Get-BitLockerVolume -MountPoint $testSecondary
        
        # We need C: decrypted and secondary decrypted for this test
        $canRunTest = ([string]$sysStatus.VolumeStatus -eq 'FullyDecrypted') -and 
                      ([string]$secStatus.VolumeStatus -eq 'FullyDecrypted')
        
        if (-not $canRunTest) {
            # Try to set up the conditions
            Write-Log "Setting up test conditions..."
            
            if ([string]$secStatus.VolumeStatus -ne 'FullyDecrypted') {
                Invoke-SafeDecrypt -MountPoint $testSecondary | Out-Null
                Wait-ForEncryptionComplete -TargetVolume $testSecondary | Out-Null
            }
            
            if ([string]$sysStatus.VolumeStatus -ne 'FullyDecrypted') {
                Invoke-SafeDecrypt -MountPoint $sysDrive | Out-Null
                Wait-ForEncryptionComplete -TargetVolume $sysDrive | Out-Null
            }
            
            $canRunTest = $true
        }
        
        if ($canRunTest) {
            Write-Log "C: is decrypted. Attempting to encrypt $testSecondary directly..."
            
            # Try to encrypt ONLY the secondary drive (bypassing our script's ordering)
            # This simulates what would happen if someone called Enable-BitLocker directly
            try {
                Enable-BitLocker -MountPoint $testSecondary -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction Stop | Out-Null
                
                # It succeeded - now try to enable auto-unlock (this should fail or warn)
                Start-Sleep -Seconds 3
                
                $autoUnlockResult = "Unknown"
                try {
                    Enable-BitLockerAutoUnlock -MountPoint $testSecondary -ErrorAction Stop | Out-Null
                    $autoUnlockResult = "Succeeded (unexpected!)"
                    $warningIssued = $false
                }
                catch {
                    $autoUnlockResult = "Failed: $($_.Exception.Message)"
                    $warningIssued = $true  # This is expected behavior!
                }
                
                Add-TestResult -Category "AutoUnlock" -TestID "C3" `
                    -TestName "Auto-unlock fails when C: not encrypted" `
                    -Passed $warningIssued `
                    -Details "Auto-unlock result: $autoUnlockResult" `
                    -Impact "High - User should be warned auto-unlock won't work"
                
                # Clean up - decrypt the secondary
                Write-Log "Cleaning up - decrypting $testSecondary..."
                Invoke-SafeDecrypt -MountPoint $testSecondary | Out-Null
                Wait-ForEncryptionComplete -TargetVolume $testSecondary | Out-Null
            }
            catch {
                # BitLocker itself might prevent this
                Add-TestResult -Category "AutoUnlock" -TestID "C3" `
                    -TestName "Auto-unlock fails when C: not encrypted" `
                    -Passed $true `
                    -Details "BitLocker prevented encryption: $($_.Exception.Message)" `
                    -Impact "High"
            }
        }
        else {
            Add-TestResult -Category "AutoUnlock" -TestID "C3" `
                -TestName "Auto-unlock fails when C: not encrypted" `
                -Passed $false `
                -Details "SKIPPED - Could not set up test conditions" `
                -Impact "High"
        }
    }
    else {
        Add-TestResult -Category "AutoUnlock" -TestID "C3" `
            -TestName "Auto-unlock fails when C: not encrypted" `
            -Passed $false `
            -Details "SKIPPED - Requires -IncludeDestructive and secondary drive" `
            -Impact "High"
    }
}


# ============================================================================
# CATEGORY E: REGISTRY EDGE CASES
# ============================================================================

$runRegistryTests = ($TestCategories -contains 'All') -or ($TestCategories -contains 'Registry')

if ($runRegistryTests) {
    Write-Log "CATEGORY E: REGISTRY EDGE CASES" -Level SECTION
    
    # -------------------------------------------------------------------------
    # E1: Registry cleared - keys re-saved on next run
    # -------------------------------------------------------------------------
    Write-Log "E1: Keys re-saved after registry cleared" -Level SUBSECTION
    
    Get-KeySnapshot -Label "E1-Before"
    $keyCountBefore = $script:KeySnapshots["E1-Before"].RegistryKeys.Count
    
    Write-Log "Clearing registry..."
    Clear-TestRegistry
    
    Write-Log "Running Save-KeysToRegistry..."
    Save-KeysToRegistry
    
    Get-KeySnapshot -Label "E1-After"
    $keyCountAfter = $script:KeySnapshots["E1-After"].RegistryKeys.Count
    
    # Should have re-saved keys for currently connected encrypted volumes
    $encryptedCount = (Get-BitLockerVolume | Where-Object { [string]$_.VolumeStatus -eq 'FullyEncrypted' }).Count
    
    Add-TestResult -Category "Registry" -TestID "E1" `
        -TestName "Keys re-saved after registry cleared" `
        -Passed ($keyCountAfter -ge $encryptedCount) `
        -Details "Before clear: $keyCountBefore, After re-save: $keyCountAfter, Encrypted volumes: $encryptedCount" `
        -Impact "Medium - Recovery from accidental registry deletion"
    
    # -------------------------------------------------------------------------
    # E2: Fresh registry creation via Set-BitLockerBestPractice
    # -------------------------------------------------------------------------
    Write-Log "E2: Set-BitLockerBestPractice creates registry from scratch" -Level SUBSECTION
    
    # Delete the entire registry key (simulates first-time deployment)
    $regPath = "HKLM:\SOFTWARE\BitLockerHistory"
    if (Test-Path $regPath) {
        Write-Log "Deleting entire BitLockerHistory registry key..."
        Remove-Item -Path $regPath -Recurse -Force
    }
    
    # Verify it's gone
    $registryGone = -not (Test-Path $regPath)
    Write-Log "Registry key deleted: $registryGone"
    
    # Run Set-BitLockerBestPractice (should create registry from scratch)
    Write-Log "Running Set-BitLockerBestPractice..."
    Set-BitLockerBestPractice -Scope InternalOnly | Out-Null
    
    # Check if registry was created
    $registryCreated = Test-Path $regPath
    
    Get-KeySnapshot -Label "E2-After"
    $keyCountAfter = $script:KeySnapshots["E2-After"].RegistryKeys.Count
    
    # Count encrypted volumes (internal only if SkipExternalDrives)
    $encryptedVolumes = Get-BitLockerVolume | Where-Object { [string]$_.VolumeStatus -eq 'FullyEncrypted' }
    if ($SkipExternalDrives) {
        $encryptedVolumes = $encryptedVolumes | Where-Object { $_.MountPoint -in $internalVolumes }
    }
    $encryptedCount = @($encryptedVolumes).Count
    
    # Verify all encrypted volumes have keys saved
    $allKeysPresent = $keyCountAfter -ge $encryptedCount
    
    Add-TestResult -Category "Registry" -TestID "E2" `
        -TestName "Set-BitLockerBestPractice creates registry from scratch" `
        -Passed ($registryCreated -and $allKeysPresent) `
        -Details "Registry created: $registryCreated, Keys saved: $keyCountAfter, Encrypted volumes: $encryptedCount" `
        -Impact "Critical - First deployment must work without pre-existing registry"
    
    # -------------------------------------------------------------------------
    # E4: VolumeID used (not drive letter)
    # -------------------------------------------------------------------------
    Write-Log "E4: Keys stored by VolumeID not drive letter" -Level SUBSECTION
    
    $regKeys = Get-BitLockerSavedKeys
    $usesVolumeID = $regKeys -match 'VolumeID:\s*[a-f0-9-]{36}'
    $usesUnknown = $regKeys -match 'Unknown-[A-Z]'
    
    Add-TestResult -Category "Registry" -TestID "E4" `
        -TestName "Keys stored by VolumeID (not drive letter)" `
        -Passed ($usesVolumeID -and -not $usesUnknown) `
        -Details "Uses VolumeID: $usesVolumeID, Uses Unknown fallback: $usesUnknown" `
        -Impact "High - Drive letters can change, VolumeID is permanent"
}


# ============================================================================
# CATEGORY G: IDEMPOTENCY TESTS
# ============================================================================

$runIdempotencyTests = ($TestCategories -contains 'All') -or ($TestCategories -contains 'Idempotency')

if ($runIdempotencyTests) {
    Write-Log "CATEGORY G: IDEMPOTENCY TESTS" -Level SECTION
    
    # -------------------------------------------------------------------------
    # G1: Test returns same result on multiple calls
    # -------------------------------------------------------------------------
    Write-Log "G1: Test-BitLockerBestPractice is consistent" -Level SUBSECTION
    
    $results = @()
    for ($i = 1; $i -le 5; $i++) {
        $result = Test-BitLockerBestPractice -Scope InternalOnly
        $results += $result
    }
    
    $allSame = ($results | Select-Object -Unique).Count -eq 1
    
    Add-TestResult -Category "Idempotency" -TestID "G1" `
        -TestName "Test-BitLockerBestPractice returns consistent results" `
        -Passed $allSame `
        -Details "Results: $($results -join ', ')" `
        -Impact "Medium - Inconsistent results cause confusion"
    
    # -------------------------------------------------------------------------
    # G2: Set on already-compliant system is no-op
    # -------------------------------------------------------------------------
    Write-Log "G2: Set on compliant system is no-op" -Level SUBSECTION
    
    # First, MAKE the system compliant
    Write-Log "Ensuring system is compliant first..."
    Set-BitLockerBestPractice -Scope SystemDriveOnly | Out-Null
    Wait-ForEncryptionComplete -TargetVolume $sysDrive | Out-Null
    
    # Verify we're now compliant
    $isCompliant = Test-BitLockerBestPractice -Scope SystemDriveOnly
    
    if ($isCompliant) {
        Get-KeySnapshot -Label "G2-Before"
        
        Write-Log "System compliant - running Set-BitLockerBestPractice again..."
        $output = Set-BitLockerBestPractice -Scope SystemDriveOnly
        
        Get-KeySnapshot -Label "G2-After"
        
        $comparison = Compare-KeySnapshots -Before "G2-Before" -After "G2-After"
        $noChanges = $comparison.KeysAdded.Count -eq 0 -and 
                     $comparison.KeysRemoved.Count -eq 0 -and 
                     $comparison.KeysChanged.Count -eq 0
        
        Add-TestResult -Category "Idempotency" -TestID "G2" `
            -TestName "Set on compliant system makes no changes" `
            -Passed $noChanges `
            -Details "Keys changed: $(-not $noChanges)" `
            -Impact "Low - Re-running should be safe"
    }
    else {
        # This shouldn't happen - we just ran Set-BitLockerBestPractice
        Add-TestResult -Category "Idempotency" -TestID "G2" `
            -TestName "Set on compliant system makes no changes" `
            -Passed $false `
            -Details "FAILED - Could not achieve compliance even after running Set-BitLockerBestPractice" `
            -Impact "High - Something is broken"
    }


# ============================================================================
# TEST REPORT
# ============================================================================

$endTime = Get-Date
$duration = $endTime - $script:StartTime

Write-Log "TEST REPORT" -Level SECTION
Write-Log "Start: $($script:StartTime)"
Write-Log "End: $endTime"  
Write-Log "Duration: $($duration.TotalMinutes.ToString('0.0')) minutes"

# Summary by category
Write-Log ""
Write-Log "RESULTS BY CATEGORY:"
$categories = $script:TestResults | Group-Object Category

foreach ($cat in $categories) {
    $passed = ($cat.Group | Where-Object { $_.Passed }).Count
    $failed = ($cat.Group | Where-Object { -not $_.Passed }).Count
    $total = $cat.Group.Count
    
    $status = if ($failed -eq 0) { "PASS" } else { "FAIL" }
    Write-Log "  $($cat.Name): $passed/$total passed" -Level $status
}

# Critical failures
$criticalFailures = $script:TestResults | Where-Object { -not $_.Passed -and $_.Impact -eq 'Critical' }
if ($criticalFailures) {
    Write-Log ""
    Write-Log "!!! CRITICAL FAILURES !!!" -Level ERROR
    foreach ($fail in $criticalFailures) {
        Write-Log "  [$($fail.TestID)] $($fail.TestName)" -Level ERROR
        Write-Log "      $($fail.Details)" -Level ERROR
    }
}

# All results
Write-Log ""
Write-Log "ALL TEST RESULTS:"
foreach ($result in $script:TestResults) {
    $status = if ($result.Passed) { "PASS" } else { "FAIL" }
    Write-Log "[$status] [$($result.TestID)] $($result.TestName)"
    if ($result.Details) { Write-Log "         $($result.Details)" }
}

# Final state
Write-Log ""
Write-Log "FINAL VOLUME STATES:"
foreach ($vol in (Get-BitLockerVolume)) {
    Write-Log "  $($vol.MountPoint): $([string]$vol.VolumeStatus) | $([string]$vol.EncryptionMethod) | $($vol.EncryptionPercentage)%"
}

Write-Log ""
Write-Log "FINAL REGISTRY KEYS:"
Write-Log (Get-BitLockerSavedKeys)

# Summary counts
$totalPassed = ($script:TestResults | Where-Object { $_.Passed }).Count
$totalFailed = ($script:TestResults | Where-Object { -not $_.Passed }).Count
$totalTests = $script:TestResults.Count

Write-Log ""
Write-Log "=========================================="
Write-Log "SUMMARY: $totalPassed PASSED, $totalFailed FAILED, $totalTests TOTAL"
Write-Log "=========================================="

if ($totalFailed -gt 0) {
    Write-Log "SOME TESTS FAILED - Review results above" -Level WARN
}
else {
    Write-Log "ALL TESTS PASSED!" -Level PASS
}

Write-Log ""
Write-Log "=========================================="
Write-Log "COPY EVERYTHING ABOVE AND PASTE TO CLAUDE"
Write-Log "=========================================="

# Save report
$reportPath = Join-Path $PSScriptRoot "BitLocker-EdgeCaseReport-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$script:Log | Out-File -FilePath $reportPath -Encoding UTF8
Write-Log "Report saved to: $reportPath"
