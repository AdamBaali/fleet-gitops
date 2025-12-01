<#
.SYNOPSIS
    Comprehensive Windows 11 CIS Hardening Remediation Script (v2).
    Covers 162+ failing policies including ASR, BitLocker, Firewall, Privacy, and Audit.
    
.DESCRIPTION
    Applies registry keys, service configurations, and audit policies to remediate CIS Level 1 & 2 failures.
    Includes specific fix for WinHttpAutoProxySvc "Access Denied" errors.
    
.NOTES
    Run as Administrator.
    A reboot is required after execution.
#>

# 1. Elevation Check
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "[-] This script must be run as Administrator!"
    exit
}

Write-Host "Starting CIS Remediation (162+ Policies)..." -ForegroundColor Cyan

# -------------------------------------------------------------------------
# Function: Set-RegistryValue
# Purpose: Robustly sets registry values, handling path formatting and creation.
# -------------------------------------------------------------------------
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )

    # Normalize Path
    $CleanPath = $Path -replace ":", "" 
    if ($CleanPath -match "^HKLM") { $Path = $CleanPath -replace "^HKLM", "HKLM:" }
    elseif ($CleanPath -match "^HKEY_LOCAL_MACHINE") { $Path = $CleanPath -replace "^HKEY_LOCAL_MACHINE", "HKLM:" }
    elseif ($CleanPath -match "^HKCU") { $Path = $CleanPath -replace "^HKCU", "HKCU:" }
    elseif ($CleanPath -match "^HKEY_CURRENT_USER") { $Path = $CleanPath -replace "^HKEY_CURRENT_USER", "HKCU:" }
    
    if (-not ($Path.StartsWith("HKLM:") -or $Path.StartsWith("HKCU:"))) {
        $Path = "HKLM:\" + $Path.TrimStart("\")
    }

    # Create Key if missing
    if (!(Test-Path $Path)) {
        try {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Error "Failed to create path: $Path. Error: $_"
            return
        }
    }

    # Update Value
    try {
        $Current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -eq $Current -or $Current.$Name -ne $Value) {
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
            Write-Host "[OK] Set $Name = $Value ($Path)" -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to set $Name at $Path. Error: $_"
    }
}

# -------------------------------------------------------------------------
# Function: Set-UserRegistryValue
# Purpose: Sets registry keys for the Current User AND Default User (for future users).
# -------------------------------------------------------------------------
function Set-UserRegistryValue {
    param (
        [string]$SubPath, # Path after HKCU\
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    
    # 1. Set for Current User
    Set-RegistryValue -Path "HKCU:\$SubPath" -Name $Name -Value $Value -Type $Type

    # 2. Set for Default User (Load Hive, Set, Unload)
    $DefaultUserHive = "HKLM\TempDefaultUser"
    if (!(Test-Path $DefaultUserHive)) {
        reg load "$DefaultUserHive" "C:\Users\Default\NTUSER.DAT" | Out-Null
    }
    
    if (Test-Path "$DefaultUserHive") {
        $FullRegPath = "$DefaultUserHive\$SubPath"
        # PowerShell drive mapping might not exist for the loaded hive, use reg.exe for reliability here
        $TypeMap = @{ "DWord" = "REG_DWORD"; "String" = "REG_SZ"; "MultiString" = "REG_MULTI_SZ" }
        $RegType = $TypeMap[$Type]
        
        cmd /c "reg add `"$FullRegPath`" /v `"$Name`" /t $RegType /d `"$Value`" /f" | Out-Null
    }
    
    # Unload (Garbage collection)
    [gc]::Collect()
    reg unload "$DefaultUserHive" | Out-Null
}

# -------------------------------------------------------------------------
# Function: Disable-ServiceViaRegistry
# Purpose: Hard disables services via Registry to bypass SCM Access Denied errors.
# -------------------------------------------------------------------------
function Disable-ServiceViaRegistry {
    param ([string]$ServiceName)
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (Test-Path $RegPath) {
        Set-RegistryValue -Path $RegPath -Name "Start" -Value 4
        try { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "[SVC] Disabled: $ServiceName" -ForegroundColor Yellow
    }
}

# -------------------------------------------------------------------------
# Function: Set-AuditPolicy
# Purpose: Configures advanced audit policies using auditpol.exe
# -------------------------------------------------------------------------
function Set-AuditPolicy {
    param (
        [string]$SubCategory,
        [string]$Success = "enable",
        [string]$Failure = "enable"
    )
    $Cmd = "auditpol /set /subcategory:`"$SubCategory`" /success:$Success /failure:$Failure"
    Invoke-Expression $Cmd | Out-Null
    Write-Host "[AUDIT] Configured: $SubCategory" -ForegroundColor Cyan
}

# =========================================================================
# SECTION 1: Attack Surface Reduction (ASR) Rules
# =========================================================================
Write-Host "`n[Configuring ASR Rules]..." -ForegroundColor Cyan
$ASR_Rules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1 # Block abuse of exploited vulnerable signed drivers
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1 # Block Adobe Reader child processes
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 1 # Block Office child processes
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1 # Block credential stealing (LSASS)
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1 # Block executable content from email
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = 1 # Block executable files unless trusted
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 1 # Block obfuscated scripts
    "d3e037e1-3eb8-44c8-a917-57927947596d" = 1 # Block JS/VBS launching executables
    "3b576869-a4ec-4529-8536-b80a7769e899" = 1 # Block Office creating executable content
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1 # Block Office code injection
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = 1 # Block Office communication child processes
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1 # Block WMI persistence
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 1 # Block PSExec/WMI process creation
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1 # Block untrusted USB processes
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1 # Block Win32 API from Office macros
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = 1 # Advanced ransomware protection
}
foreach ($guid in $ASR_Rules.Keys) {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager\ASR\Rules" -Name $guid -Value $ASR_Rules[$guid]
}

# =========================================================================
# SECTION 2: BitLocker & Device Encryption
# =========================================================================
Write-Host "`n[Configuring BitLocker]..." -ForegroundColor Cyan
$BitLockerPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# Fixed Drives
Set-RegistryValue -Path $BitLockerPath -Name "FDVRecovery" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "FDVManageDRA" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "FDVActiveDirectoryInfoToStore" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "FDVRequireActiveDirectoryBackup" -Value 0
Set-RegistryValue -Path $BitLockerPath -Name "FDVHideRecoveryPage" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "FDVRecoveryKey" -Value 2
Set-RegistryValue -Path $BitLockerPath -Name "FDVRecoveryPassword" -Value 2
Set-RegistryValue -Path $BitLockerPath -Name "FDVActiveDirectoryBackup" -Value 0
Set-RegistryValue -Path $BitLockerPath -Name "EncryptionMethodWithXtsFdv" -Value 6 # XTS-AES 128

# OS Drives
Set-RegistryValue -Path $BitLockerPath -Name "OSRecovery" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "OSManageDRA" -Value 0
Set-RegistryValue -Path $BitLockerPath -Name "OSActiveDirectoryInfoToStore" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "OSRequireActiveDirectoryBackup" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "OSHideRecoveryPage" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "OSRecoveryKey" -Value 0
Set-RegistryValue -Path $BitLockerPath -Name "OSRecoveryPassword" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "OSActiveDirectoryBackup" -Value 1
Set-RegistryValue -Path $BitLockerPath -Name "OSEncryptionType" -Value 1 # Used Space Only
Set-RegistryValue -Path $BitLockerPath -Name "EncryptionMethodWithXtsOs" -Value 6 # XTS-AES 128

# Removable Drives
Set-RegistryValue -Path $BitLockerPath -Name "EncryptionMethodWithXtsRdv" -Value 6 # XTS-AES 128
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "RDVDenyCrossOrg" -Value 0

# Device Encryption (Silent)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" -Name "RequireDeviceEncryption" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" -Name "AllowWarningForOtherDiskEncryption" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" -Name "AllowStandardUserEncryption" -Value 1

# =========================================================================
# SECTION 3: Network, Firewall & Connectivity
# =========================================================================
Write-Host "`n[Configuring Firewall & Network]..." -ForegroundColor Cyan

# Hardened UNC Paths (ID 9290) - Requires MultiString
$UNCPaths = @("\\*\NETLOGON","RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"),
            @("\\*\SYSVOL","RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1")
foreach ($path in $UNCPaths) {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths" -Name $path[0] -Value $path[1] -Type "String"
}

# Firewall Profiles & Logging
$Profiles = "DomainProfile", "StandardProfile", "PublicProfile"
foreach ($Profile in $Profiles) {
    $FwPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$Profile"
    Set-RegistryValue -Path $FwPath -Name "EnableFirewall" -Value 1
    Set-RegistryValue -Path $FwPath -Name "DefaultInboundAction" -Value 1 # Block
    Set-RegistryValue -Path $FwPath -Name "DisableNotifications" -Value 1
    Set-RegistryValue -Path $FwPath -Name "AllowLocalIPsecPolicyMerge" -Value 0
    Set-RegistryValue -Path $FwPath -Name "AllowLocalPolicyMerge" -Value 0
    
    # Logging
    Set-RegistryValue -Path "$FwPath\Logging" -Name "LogDroppedPackets" -Value 1
    Set-RegistryValue -Path "$FwPath\Logging" -Name "LogSuccessfulConnections" -Value 1
    Set-RegistryValue -Path "$FwPath\Logging" -Name "LogFileSize" -Value 16384
    
    # Profile Specific Names
    if ($Profile -eq "DomainProfile") { $LogName = "domainfw.log" }
    elseif ($Profile -eq "StandardProfile") { $LogName = "privatefw.log" }
    else { $LogName = "publicfw.log" }
    Set-RegistryValue -Path "$FwPath\Logging" -Name "LogFilePath" -Value "%SystemRoot%\System32\logfiles\firewall\$LogName" -Type "ExpandString"
}

# Network Security (NTLM, SAM, RPC)
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictRemoteSAM" -Value "O:BAG:BAD:(A;;RC;;;BA)" -Type "String"
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinClientSec" -Value 537395200
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "NTLMMinServerSec" -Value 537395200
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "UseMachineId" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" -Name "AllowOnlineID" -Value 0
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLmHash" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -Value 2


# Wireless / Connectivity
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI" -Name "DisableWcnUi" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fBlockNonDomain" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -Value 3
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect" -Name "RequirePinForPairing" -Value 2
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value 0


# =========================================================================
# SECTION 4: System Hardening & Privacy
# =========================================================================
Write-Host "`n[Configuring System Hardening & Privacy]..." -ForegroundColor Cyan

# LSA & Credential Guard
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "ConfigureSystemGuardLaunch" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "HypervisorEnforcedCodeIntegrity" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "EnableESSwithSupportedPeripherals" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "RequireSecurityDevice" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\Biometrics" -Name "FacialFeaturesUseEnhancedAntiSpoofing" -Value 1

# Privacy & Telemetry
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerAccountStateContent" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableEnterpriseAuthProxy" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableStoreApps" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableCloudNotifications" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDiagnosticLogCollection" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitDumpCollection" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowSearchToUseLocation" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0 # Search highlights
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSpotlightCollectionOnDesktop" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0 # Widgets

# App Installer & Store
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "DisableMSI" -Value 1 # Block Non-Admin
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableExperimentalFeatures" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableHashOverride" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller" -Name "EnableMSAppInstallerProtocol" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "DisableOSUpgrade" -Value 1

# Windows Update
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetDisablePauseUXAccess" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DeferQualityUpdatesPeriodInDays" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ManagePreviewBuildsPolicyValue" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update" -Name "AllowAutoUpdate" -Value 2 # Auto install and restart
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update" -Name "ConfigRefresh" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\{ProviderGUID}\ConfigRefresh" -Name "Cadence" -Value 90 

# Misc System
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo" -Name "Enabled" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "NoLocalPasswordResetQuestions" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "HideExclusionsFromLocalUsers" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowFontProviders" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" -Name "LsaCfgFlags" -Value 1 # Credential Guard with UEFI Lock

# MSS Settings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value 0
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScreenSaverGracePeriod" -Value 5
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security" -Name "WarningLevel" -Value 90

# Device Installation Restrictions (14273)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyDeviceClasses" -Value 1
$DeviceClassesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
if (!(Test-Path $DeviceClassesPath)) { New-Item -Path $DeviceClassesPath -Force | Out-Null }
Set-RegistryValue -Path $DeviceClassesPath -Name "1" -Value "{d48179be-ec20-11d1-b6b8-00c04fa372a7}" -Type "String"
Set-RegistryValue -Path $DeviceClassesPath -Name "2" -Value "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}" -Type "String"
Set-RegistryValue -Path $DeviceClassesPath -Name "3" -Value "{c06ff265-ae09-48f0-812c-16753d7cba83}" -Type "String"
Set-RegistryValue -Path $DeviceClassesPath -Name "4" -Value "{6bdd1fc1-810f-11d0-bec7-08002be2092f}" -Type "String"

# Defender
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "AllowEmailScanning" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "DaysUntilAggressiveCatchupQuickScan" -Value 7
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "EnableConvertWarnToBlock" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "EnableFileHashComputation" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "EnableNetworkProtection" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "OobeEnableRtpAndSigUpdate" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "PUAProtection" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "QuickScanIncludeExclusions" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "RemoteEncryptionProtectionAggressiveness" -Value 2 # Medium/High
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "RemoteEncryptionProtectionConfiguredState" -Value 2 # Audit
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "LocalSettingOverrideSpynetReporting" -Value 0

# =========================================================================
# SECTION 5: User Policies (HKCU & Default User)
# =========================================================================
Write-Host "`n[Configuring User Policies]..." -ForegroundColor Cyan

# 9350: Prevent file sharing
Set-UserRegistryValue -SubPath "Software\Policies\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInplaceSharing" -Value 1

# 9304: Toast notifications
Set-UserRegistryValue -SubPath "Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoToastApplicationNotificationOnLockScreen" -Value 1

# 9330: Attachment Zone Info
Set-UserRegistryValue -SubPath "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Value 2
Set-UserRegistryValue -SubPath "Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Value 3

# 3440: Help Improvement
Set-UserRegistryValue -SubPath "Software\Policies\Microsoft\Assistance\Client\1.0" -Name "NoImplicitFeedback" -Value 1

# 9503: MSI Always Install Elevated (User)
Set-UserRegistryValue -SubPath "Software\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0

# 3255: Prevent Codec Download
Set-UserRegistryValue -SubPath "Software\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventCodecDownload" -Value 1

# =========================================================================
# SECTION 6: Services (Disabling)
# =========================================================================
Write-Host "`n[Disabling Services]..." -ForegroundColor Cyan
$Services = @(
    "WinHttpAutoProxySvc", "RemoteRegistry", "XboxGipSvc", "XblAuthManager",
    "XblGameSave", "XboxNetApiSvc", "BTAGService", "bthserv", "MapsBroker",
    "lfsvc", "lltdsvc", "MSiSCSI", "Spooler", "wercplsupport", "RasAuto",
    "SessionEnv", "TermService", "UmRdpService", "LanmanServer", "SNMP",
    "WerSvc", "Wecsvc", "WpnService", "PushToInstall", "WinRM", "icssvc",
    "upnphost", "SSDPSRV", "sacsvr", "simptcp", "WMSvc", "WMPNetworkSvc", "IISADMIN", "irmon",
    "RpcLocator", "GameInputSvc"
)
foreach ($Svc in $Services) { Disable-ServiceViaRegistry -ServiceName $Svc }

# =========================================================================
# SECTION 7: Audit Policies
# =========================================================================
Write-Host "`n[Configuring Advanced Audit Policies]..." -ForegroundColor Cyan
Set-AuditPolicy -SubCategory "Authorization Policy Change" -Success "enable"
Set-AuditPolicy -SubCategory "User Account Management" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Application Group Management" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Detailed File Share" -Failure "enable"
Set-AuditPolicy -SubCategory "Other Object Access Events" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Removable Storage" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "MPSSVC Rule-Level Policy Change" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Other Policy Change Events" -Failure "enable"
Set-AuditPolicy -SubCategory "Sensitive Privilege Use" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "IPsec Driver" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Other System Events" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Security State Change" -Success "enable"
Set-AuditPolicy -SubCategory "System Integrity" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Audit User Account Management" -Success "enable" -Failure "enable" # Specific for ID 9381

# =========================================================================
# SECTION 8: LAPS Policies
# =========================================================================
Write-Host "`n[Configuring LAPS Policies]..." -ForegroundColor Cyan
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -Name "BackupDirectory" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -Name "PasswordAgeDays" -Value 30
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -Name "PasswordComplexity" -Value 4
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -Name "PasswordLength" -Value 15
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -Name "PostAuthenticationActions" -Value 3
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Policies\LAPS" -Name "PostAuthenticationResetDelay" -Value 8

Write-Host "`n------------------------------------------------------------------"
Write-Host " CIS Remediation v2 Complete." -ForegroundColor Green
Write-Host " Please RESTART your computer to apply ASR, Service, and Device Guard settings." -ForegroundColor Yellow
Write-Host "------------------------------------------------------------------"
