function Confirm-EncryptionReadiness {
    param (
        [boolean]$Remediate     # Set $true to auto resolve
    )
    if (!(Get-TPMexists)) {
        throw 'TPM does not exist'
    }

    if (!(Get-IsTPMEnabled)) {
        try {
            if ($Remediate) {
                Set-TPMEnabled
                if (!(Get-IsTPMEnabled)) {
                    throw
                }
            } else {
                throw
            }
        } catch {
            return 'TPM is not enabled'
        }
    }

    if (!(Get-IsTPMActivated)) {
        try {
            if ($Remediate) {
                Set-TPMActive
                if (!(Get-IsTPMActivated)) {
                    throw
                }
            } else {
                throw
            }
        } catch {
            return 'TPM is not activated'
        }
    }

    if (!(Get-IsTPMOwned))  {
        try {
            if ($Remediate) {
                Set-TPMOwnership
                if (!(Get-IsTPMOwned)) {
                    throw
                }
            } else {
                throw
            }
        } catch {
            return 'TPM is not owned'
        }
    }

    if (!(Get-IsOSEligible)) {
        throw 'OS is not eligible'
    }
}

function Get-InternalVolumes {
    Get-Disk | Where-Object { $_.BusType -ne 'USB' } | Get-Partition | Get-Volume | Where-Object { $_.DriveType -like 'fixed' -and $_.DriveLetter }
}

function Get-ExternalVolumes {
    Get-Disk | Where-Object { $_.BusType -eq 'USB' } | Get-Partition | Get-Volume | Where { $_.DriveLetter }
}

function Get-TPMexists {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    try {
        if (!$tpm) {
            throw
        } elseif (($tpm.GetPhysicalPresenceConfirmationStatus(5).ConfirmationStatus) -eq 0) {
            throw
        } else {
            return $true
        }
    } catch {
        return $false
    }
}

function Get-IsTPMEnabled {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpmEnabled = $tpm.IsEnabled().isenabled
    if (!$tpmEnabled) {
        return $false
    } else {
        return $true
    }
}

function Set-TPMEnabled {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpm.Enable()
}

function Get-IsTPMActivated {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpmActivated = $tpm.IsActivated().isactivated
    if (!$tpmActivated) {
        return $false
    } else {
        return $true
    }
}

function Set-TPMActive {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpm.Activate()
}

function Get-IsTPMOwned {
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    $tpmOwned = $tpm.IsOwned().isOwned
    if (!$tpmOwned) {
        return $false
    } else {
        return $true
    }
}

function Set-TPMOwnership {
    # Ref: https://deploywindows.com/2017/06/08/whats-the-story-about-tpm-owner-password-and-bitlocker-recovery-password/
    # Ref: https://devblogs.microsoft.com/scripting/powershell-and-bitlocker-part-1/
    
    $tpm = Get-WmiObject -Namespace root\cimv2\security\microsofttpm -class Win32_TPM
    Switch ($tpm.GetPhysicalPresenceConfirmationStatus(5).ConfirmationStatus) {
        4{
            # 4 means that Windows is able to manage the TPM, allowing it to be cleared without requiring a user to be present for approval.
            # Allow the installation of a TPM owner
            $tpm.SetPhysicalPresenceRequest(8) | Out-Null
            # Clear the TPM chip and take ownership
            $tpm.SetPhysicalPresenceRequest(5) | Out-Null
            return 'Ready to encrypt'
        }

        3{
            # 3 means that Windows can manage the TPM, however, the user must be present to approve the change.
            # Provision the TPM to allow clear without the physical presence of the user.
            $tpm.SetPhysicalPresenceRequest(18) | Out-Null
            return 'Reboot required to provision TPM'
        }

        2{
            # 2 means that Windows is unable to manage the TPM, as the BIOS settings prevent this action.
            return 'TPM cannot be managed, BIOS/EUFI manual config required'
        }

        1{
            # 1 means that the BIOS does not permit changes to the TPM from outside the BIOS.
            return 'BIOS/EUFI does not allow control of TPM from the OS, direct BIOS/EUFI config required'
        }
    }
}

function Get-AllUnencryptedVolumes {
    Get-BitLockerVolume | Where-Object { $_.VolumeStatus -ne 'FullyEncrypted' }
}

function Get-UnencryptedInternalVolumes {
    Get-InternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Get-BitLockerVolume -MountPoint $volume
    }
}

function Get-UnencryptedExternalVolumes {
    Get-ExternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Get-BitlockerVolume -MountPoint $volume
    }
}

function Enable-InternalFullDiskEncryption {
    Get-InternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest
        # Removing ':' so values match
        $sysDrive = $env:SystemDrive -replace ':',''
        if ($volume -ne $sysDrive) {
            Enable-BitLockerAutoUnlock -Mountpoint $volume
        }
    }
}

function Enable-InternalUsedSpaceEncryption {
   Get-InternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -UsedSpaceOnly
        # Removing ':' so values match
        $sysDrive = $env:SystemDrive -replace ':',''
        if ($volume -ne $sysDrive) {
            Enable-BitLockerAutoUnlock -Mountpoint $volume
        }
    }
}

function Enable-ExternalFullDiskEncryption {
    Get-ExternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest
        Enable-BitLockerAutoUnlock -Mountpoint $volume
    }
}

function Enable-ExternalUsedSpaceEncryption {
    Get-ExternalVolumes | ForEach {
        $volume = $_.DriveLetter
        Enable-Bitlocker -MountPoint $volume -EncryptionMethod Aes256 -RecoveryPasswordProtector -SkipHardwareTest -UsedSpaceOnly
        Enable-BitLockerAutoUnlock -Mountpoint $volume
    }
}

function Get-IsOSEligible {
    $osInfo = Get-WmiObject win32_operatingsystem
    $osName = $osInfo.Caption
    $osArch = $osInfo.OSArchitecture

    if ($osName -like '*Pro*' -or $osName -like '*Enterprise*' -or $osName -like '*Education*') {
        return $true
    } else {
        return $false
    }
}
