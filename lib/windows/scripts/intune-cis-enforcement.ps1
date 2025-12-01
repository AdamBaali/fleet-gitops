<#
.SYNOPSIS
    CIS Hardening Remediation Script (v3)
    Targeting 105+ failing policies including User Rights, ASR, and Services.
    
.DESCRIPTION
    - Fixes User Rights Assignment (Access From Network) using secedit.
    - Fixes ASR rules by targeting multiple registry paths.
    - Fixes Service configurations.
    - Fixes Audit policies.
    
.NOTES
    Run as Administrator. Reboot required.
#>

# 1. Elevation Check
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "[-] This script must be run as Administrator!"
    exit
}

Write-Host "Starting CIS Remediation v3..." -ForegroundColor Cyan

# -------------------------------------------------------------------------
# Function: Set-RegistryValue
# Purpose: Sets registry values, creating paths if needed.
# -------------------------------------------------------------------------
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    
    # Normalize Path
    if ($Path -match "^HKLM") { $Path = $Path -replace "^HKLM", "HKLM:" }
    if (-not $Path.StartsWith("HKLM:")) { $Path = "HKLM:\" + $Path.TrimStart("\") }

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force -ErrorAction SilentlyContinue | Out-Null
    }

    try {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[REG] Set $Name = $Value" -ForegroundColor Green
    } catch {
        Write-Host "[ERR] Failed to set $Name" -ForegroundColor Red
    }
}

# -------------------------------------------------------------------------
# Function: Set-UserRight
# Purpose: Configures User Rights Assignment (URA) using secedit.
# -------------------------------------------------------------------------
function Set-UserRight {
    param (
        [string]$Privilege,
        [string]$Principals
    )
    
    $TempPath = "$env:TEMP\secpol.cfg"
    $DbPath = "$env:TEMP\secpol.sdb"
    
    # Export current policy
    secedit /export /cfg $TempPath /quiet
    
    # Read file
    $Content = Get-Content $TempPath
    
    # Check if privilege exists in file
    $Pattern = "^$Privilege\s*=\s*.*"
    $NewLine = "$Privilege = $Principals"
    
    if ($Content -match $Pattern) {
        $Content = $Content -replace $Pattern, $NewLine
    } else {
        # Append to [Privilege Rights] section
        $PrivRightsIndex = $Content.IndexOf("[Privilege Rights]")
        if ($PrivRightsIndex -ge 0) {
            $Content = $Content[0..$PrivRightsIndex] + $NewLine + $Content[($PrivRightsIndex+1)..($Content.Length-1)]
        } else {
            $Content += "[Privilege Rights]"
            $Content += $NewLine
        }
    }
    
    # Write back and import
    $Content | Set-Content $TempPath
    secedit /configure /db $DbPath /cfg $TempPath /areas USER_RIGHTS /quiet
    
    Write-Host "[URA] Configured $Privilege -> $Principals" -ForegroundColor Magenta
    Remove-Item $TempPath -ErrorAction SilentlyContinue
    Remove-Item $DbPath -ErrorAction SilentlyContinue
}

# -------------------------------------------------------------------------
# Function: Set-AuditPolicy
# Purpose: Configures advanced audit policies.
# -------------------------------------------------------------------------
function Set-AuditPolicy {
    param (
        [string]$SubCategory,
        [string]$Success = "enable",
        [string]$Failure = "enable"
    )
    $Cmd = "auditpol /set /subcategory:`"$SubCategory`" /success:$Success /failure:$Failure"
    Invoke-Expression $Cmd | Out-Null
    Write-Host "[AUDIT] Configured $SubCategory" -ForegroundColor Cyan
}

# -------------------------------------------------------------------------
# Function: Disable-Service
# -------------------------------------------------------------------------
function Disable-Service {
    param ([string]$Name)
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (Test-Path $RegPath) {
        Set-RegistryValue -Path $RegPath -Name "Start" -Value 4
        try { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue } catch {}
        Write-Host "[SVC] Disabled $Name" -ForegroundColor Yellow
    }
}

# =========================================================================
# SECTION 1: User Rights Assignment (Fixes IDs 9538, 9552)
# =========================================================================
Write-Host "`n[Configuring User Rights Assignment]..." -ForegroundColor Cyan
# ID 9538: Access From Network -> Admins, Remote Desktop Users
Set-UserRight -Privilege "SeNetworkLogonRight" -Principals "*S-1-5-32-544,*S-1-5-32-555"

# ID 9552: Deny Log On As Service -> Guests
Set-UserRight -Privilege "SeDenyServiceLogonRight" -Principals "*S-1-5-32-546"

# Deny Log On As Batch Job -> Guests
Set-UserRight -Privilege "SeDenyBatchLogonRight" -Principals "*S-1-5-32-546"

# Deny Local Log On -> Guests
Set-UserRight -Privilege "SeDenyInteractiveLogonRight" -Principals "*S-1-5-32-546"

# =========================================================================
# SECTION 2: Services (Disabling Failing Services)
# =========================================================================
Write-Host "`n[Disabling Services]..." -ForegroundColor Cyan
$Services = @(
    "WinHttpAutoProxySvc", "RemoteRegistry", "XboxGipSvc", "XblAuthManager",
    "XblGameSave", "XboxNetApiSvc", "BTAGService", "bthserv", "MapsBroker",
    "lfsvc", "lltdsvc", "MSiSCSI", "Spooler", "wercplsupport", "RasAuto",
    "SessionEnv", "TermService", "UmRdpService", "LanmanServer", "SNMP",
    "WerSvc", "Wecsvc", "WpnService", "PushToInstall", "WinRM", "icssvc",
    "upnphost", "SSDPSRV", "sacsvr", "simptcp", "WMSvc", "WMPNetworkSvc", 
    "IISADMIN", "irmon", "RpcLocator", "GameInputSvc"
)
foreach ($Svc in $Services) { Disable-Service -Name $Svc }

# =========================================================================
# SECTION 3: ASR Rules (Double Targeted)
# =========================================================================
Write-Host "`n[Configuring ASR Rules]..." -ForegroundColor Cyan
$ASR_Rules = @{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = 1 
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = 1 
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = 2 
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = 1 
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = 1 
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = 2 
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = 2 
    "d3e037e1-3eb8-44c8-a917-57927947596d" = 1 
    "3b576869-a4ec-4529-8536-b80a7769e899" = 1 
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = 1 
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = 2 
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = 1 
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = 2 
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = 1 
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = 1 
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = 2 
}

# Target 1: GPO Path
foreach ($guid in $ASR_Rules.Keys) {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -Name $guid -Value $ASR_Rules[$guid]
}
# Target 2: Policy Manager Path (Intune)
foreach ($guid in $ASR_Rules.Keys) {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager\ASR\Rules" -Name $guid -Value $ASR_Rules[$guid]
}

# =========================================================================
# SECTION 4: BitLocker & Security
# =========================================================================
Write-Host "`n[Configuring BitLocker & Security]..." -ForegroundColor Cyan
$BLPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"

# BitLocker Settings
Set-RegistryValue -Path $BLPath -Name "FDVRecovery" -Value 1
Set-RegistryValue -Path $BLPath -Name "FDVManageDRA" -Value 1
Set-RegistryValue -Path $BLPath -Name "FDVActiveDirectoryInfoToStore" -Value 1
Set-RegistryValue -Path $BLPath -Name "FDVRequireActiveDirectoryBackup" -Value 0 # Enabled: False
Set-RegistryValue -Path $BLPath -Name "FDVHideRecoveryPage" -Value 1
Set-RegistryValue -Path $BLPath -Name "FDVRecoveryKey" -Value 2
Set-RegistryValue -Path $BLPath -Name "FDVRecoveryPassword" -Value 2
Set-RegistryValue -Path $BLPath -Name "FDVActiveDirectoryBackup" -Value 0 # Enabled: False
Set-RegistryValue -Path $BLPath -Name "EncryptionMethodWithXtsFdv" -Value 7 # XTS-256
Set-RegistryValue -Path $BLPath -Name "EncryptionMethodWithXtsOs" -Value 7
Set-RegistryValue -Path $BLPath -Name "EncryptionMethodWithXtsRdv" -Value 7
Set-RegistryValue -Path $BLPath -Name "OSRecovery" -Value 1
Set-RegistryValue -Path $BLPath -Name "OSManageDRA" -Value 0 # False
Set-RegistryValue -Path $BLPath -Name "OSActiveDirectoryInfoToStore" -Value 1
Set-RegistryValue -Path $BLPath -Name "OSRequireActiveDirectoryBackup" -Value 1 # True
Set-RegistryValue -Path $BLPath -Name "OSHideRecoveryPage" -Value 1
Set-RegistryValue -Path $BLPath -Name "OSRecoveryKey" -Value 0
Set-RegistryValue -Path $BLPath -Name "OSRecoveryPassword" -Value 1
Set-RegistryValue -Path $BLPath -Name "OSActiveDirectoryBackup" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE" -Name "RDVDenyWriteAccess" -Value 1

# Allow Warning for Other Disk Encryption (14302, 14303)
# To set "Allow Warning" to Disabled, value is 0.
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" -Name "AllowWarningForOtherDiskEncryption" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\BitLocker" -Name "AllowStandardUserEncryption" -Value 1

# =========================================================================
# SECTION 5: Network & Firewall
# =========================================================================
Write-Host "`n[Configuring Network & Firewall]..." -ForegroundColor Cyan
$FwBase = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
$Profiles = "DomainProfile", "StandardProfile", "PublicProfile"

foreach ($P in $Profiles) {
    $Path = "$FwBase\$P"
    Set-RegistryValue -Path $Path -Name "EnableFirewall" -Value 1
    Set-RegistryValue -Path $Path -Name "DefaultInboundAction" -Value 1
    Set-RegistryValue -Path $Path -Name "DisableNotifications" -Value 1
    Set-RegistryValue -Path "$Path\Logging" -Name "LogDroppedPackets" -Value 1
    Set-RegistryValue -Path "$Path\Logging" -Name "LogSuccessfulConnections" -Value 1
    Set-RegistryValue -Path "$Path\Logging" -Name "LogFileSize" -Value 16384
}

# Hardened UNC Paths (Multi-String)
$UncPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
New-Item -Path $UncPath -Force -ErrorAction SilentlyContinue | Out-Null
$Val = "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1"
cmd /c "reg add `"$UncPath`" /v `"\*\NETLOGON`" /t REG_SZ /d `"$Val`" /f" | Out-Null
cmd /c "reg add `"$UncPath`" /v `"\*\SYSVOL`" /t REG_SZ /d `"$Val`" /f" | Out-Null

# =========================================================================
# SECTION 6: Privacy & Misc
# =========================================================================
Write-Host "`n[Configuring Privacy & Misc]..." -ForegroundColor Cyan

# Wi-Fi Sense (9573)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -Value 0

# Camera (3276) - MDM Policy Path
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Camera" -Name "AllowCamera" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Camera" -Name "AllowCamera" -Value 0

# Font Providers (3341)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowFontProviders" -Value 0

# Input Personalization (9504)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -Value 0

# Location (3342)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Value 1

# Message Sync (3573)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging" -Name "AllowMessageSync" -Value 0

# Online Tips (3336)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "AllowOnlineTips" -Value 0

# Search Highlights (3335)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "EnableDynamicContentInWSB" -Value 0

# Ink Workspace (3392)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowSuggestedAppsInWindowsInkWorkspace" -Value 0

# Windows Update (9583) - Allow Auto Update = Enabled (2 = Auto Install/Restart)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 4 # Auto install

# =========================================================================
# SECTION 7: Audit
# =========================================================================
Write-Host "`n[Configuring Audit Policies]..." -ForegroundColor Cyan
Set-AuditPolicy -SubCategory "User Account Management" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Authorization Policy Change" -Success "enable"
Set-AuditPolicy -SubCategory "Other Object Access Events" -Success "enable" -Failure "enable"
Set-AuditPolicy -SubCategory "Process Creation" -Success "enable"

Write-Host "`n------------------------------------------------------------------"
Write-Host " Remediation Complete." -ForegroundColor Green
Write-Host " REBOOT REQUIRED." -ForegroundColor Yellow
Write-Host "------------------------------------------------------------------"
