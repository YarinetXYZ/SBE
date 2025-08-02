
Write-Host ""
Write-Host "################################################################################" -ForegroundColor Cyan
Write-Host "#                          STIG COMPLIANCE REPORT                             #" -ForegroundColor Cyan
Write-Host "################################################################################" -ForegroundColor Cyan
Write-Host ""
Write-Host "By Yarinet v3.96 - STIG BASELINE ENFORCER" -ForegroundColor Magenta


# TOGGLE CONFIG OPTIONS / WHITELISTED EVENTS

$computerName = $env:COMPUTERNAME

$script:Config = @{
    LogFile                  = "C:\Temp\STIG-BASELINE-ENFORCER.log"
    ReportPath               = "C:\Temp\STIG-BASELINE-REPORT-$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    RemoveAgedAccounts       = $false
    RemoveUnauthorizedTasks  = $false
    RemoveUnauthorizedAdmins = $false
    StopUnauthorizedServices = $false

    ApprovedAdmins = @(
        "BUILTIN\Administrators",
        "$computerName\Administrator",
        "$computerName\LocalAdmin",
        "$computerName\Yarinet"
    )

    TaskExclusionList = @(
        "^BraveSoftwareUpdateTaskMachine",
        "^MicrosoftEdgeUpdateTaskMachine",
        "^OneDrive",
        "^GoogleUpdaterTaskSystem",
        "^npcapwatchdog"
    )

    ApprovedServiceAccounts = @(
        "NT SERVICE\MSSQLSERVER",
        "NT SERVICE\WinDefend",
        "DOMAIN\ServiceAccount",
        "$computerName\MySvcUser"
    )
}


$global:Results = @()
$global:STIGCompliance = @{}

# STIG REQUIREMENT MAPPING FINAL OUTPUT OVERVIEW
$script:STIGRequirements = @{
        ##HIGH STIG REQUIREMENTS
        "V-220702" = "BitLocker Drive Encryption - System drives must be encrypted"
        "V-220706" = "Windows Version Compliance - Must be supported version"
        "V-220707" = "Windows Defender - Real-time protection must be enabled"
        "V-220708" = "File System - System drive must be formatted with NTFS"
        "V-220727" = "Structured Exception Handling - Chain validation must be enabled"
        "V-220823" = "Remote Assistance - Must be disabled"
        "V-220827" = "AutoPlay - Must be disabled for non-volume devices"
        "V-220828" = "AutoRun - Must be disabled for all drives"
        "V-220829" = "AutoPlay - Must be disabled for all media and devices"
        "V-220857" = "Windows Installer - Always install elevated must be disabled"
        "V-220862" = "WinRM Client - Basic authentication must be disabled"
        "V-220865" = "WinRM Service - Basic authentication must be disabled"
        "V-XYZZYX" = "Security Policy Baseline - Applied from repository"
        "V-220967" = "Debug Programs Right - Only assigned to administrators group"
        "V-220963" = "Create Token Object - Not assigned to any groups or accounts"
        "V-220958" = "Act as OS - Not assigned to any groups or accounts"
        "V-220938" = "LanMan Authentication - Set as NTLMv2, refuse LM and NTLM"
        "V-220937" = "Lan Manager Passwords - Prevent local storage of passwords"
        "V-220932" = "Named Pipes & Shares - Anonymous access restricted"
        "V-220930" = "Share Enumeration - Anonymous access restricted"
        "V-220929" = "SAM Accounts - Anonymous ccess restricted"
        "V-220928" = "SID/Name Enumeration - Anonymous access restricted"
        "V-220726" = "Data Execution Prevention - Set to atleast OptOut"
        "V-220712" = "Administrator Rights - Restricted"
        "V-220718" = "Internet Information Systems (IIS) - Components not installed"
        "V-220737" = "Administrator Account - Disabled with external facing applications"

        ##MEDIUM STIG REQUIREMENTS
        "V-268319" = "Enforce STIG via Group Policy or approved MDM."
        "V-268315" = "Disable Copilot on Windows 10."
        "V-257593" = "Portproxy must be disabled on Windows 10."
        "V-257589" = "Enable command line auditing for failures."
        "V-256894" = "Disable Internet Explorer."
        "V-252896" = "Enable PowerShell transcription."
        "V-250319" = "Harden UNC paths (\\*\\SYSVOL and \\*\\NETLOGON) with mutual authentication."
        "V-220983" = "Assign Take ownership right to Administrators only."
        "V-220982" = "Assign Restore files right to Administrators only."
        "V-220981" = "Assign Profile single process right to Administrators only."
        "V-220980" = "Assign volume maintenance right to Administrators only."
        "V-220979" = "Assign Modify firmware environment values to Administrators only."
        "V-220978" = "Assign Manage auditing and security log right to Administrators only."
        "V-220977" = "Do not assign Lock pages in memory right."
        "V-220976" = "Assign Load/unload device drivers right to Administrators only."
        "V-220975" = "Assign Impersonate a client right to Admins, Service, Local Service, Network Service."
        "V-220974" = "Assign Force shutdown from remote system right to Administrators only."
        "V-220973" = "Do not assign Enable trusted delegation right."
        "V-220972" = "Deny RDP logon to privileged domain/local accounts and unauthenticated users."
        "V-220971" = "Deny local logon to privileged domain accounts and unauthenticated users."
        "V-220970" = "Deny log on as a service right to privileged domain accounts on domain-joined workstations."
        "V-220969" = "Deny log on as a batch job right to privileged domain accounts on domain-joined workstations."
        "V-220968" = "Deny network access to privileged domain/local accounts and unauthenticated users."
        "V-220966" = "Assign Create symbolic links right only to Administrators."
        "V-220965" = "Do not assign Create permanent shared objects right."
        "V-220964" = "Assign Create global objects right to Admins, Service, Local Service, Network Service."
        "V-220962" = "Assign Create a pagefile right only to Administrators."
        "V-220961" = "Assign Change system time right to Admins, Local Service, and NT SERVICE\\autotimesvc."
        "V-220960" = "Assign Back up files right only to Administrators."
        "V-220959" = "Allow log on locally right only to Administrators and Users."
        "V-220957" = "Assign network access right only to Administrators and Remote Desktop Users."
        "V-220956" = "Do not assign Access Credential Manager as trusted caller right."
        "V-220955" = "Preserve zone information when saving attachments."
        "V-220952" = "Change local Administrator passwords at least every 60 days."
        "V-220951" = "UAC must virtualize file and registry write failures per user."
        "V-220950" = "UAC must run all admins in Admin Approval Mode."
        "V-220949" = "UAC must only elevate UIAccess apps installed in secure locations."
        "V-220948" = "UAC must detect app installs and prompt for elevation."
        "V-220947" = "UAC must automatically deny elevation requests for standard users."
        "V-220946" = "Use multifactor authentication for local and network access."
        "V-220945" = "UAC must prompt admins for consent on secure desktop."
        "V-220944" = "Enable UAC approval mode for built-in Administrator."
        "V-220942" = "Use FIPS-compliant algorithms for encryption, hashing, signing."
        "V-220941" = "Meet minimum session security for NTLM SSP servers."
        "V-220940" = "Meet minimum session security for NTLM SSP clients."
        "V-220939" = "Configure required LDAP client signing level."
        "V-220936" = "Prevent DES and RC4 in Kerberos encryption types."
        "V-220935" = "Prevent PKU2U authentication with online identities."
        "V-220934" = "Prevent NTLM fallback to Null session."
        "V-220933" = "Restrict SAM remote calls to Administrators."
        "V-220931" = "Prevent anonymous users having Everyone group rights."
        "V-220927" = "Configure SMB server to always sign packets."
        "V-220926" = "Do not send unencrypted passwords to third-party SMB servers."
        "V-220925" = "Configure SMB client to always sign packets."
        "V-220924" = "Set Smart Card removal option to Force Logoff or Lock."
        "V-220921" = "Display required legal notice before console logon."
        "V-220920" = "Set inactivity limit to 15 minutes with screensaver lock."
        "V-220919" = "Require strong session key."
        "V-220916" = "Sign outgoing secure channel traffic when possible."
        "V-220915" = "Encrypt outgoing secure channel traffic when possible."
        "V-220914" = "Encrypt or sign outgoing secure channel traffic."
        "V-220913" = "Enable audit policy using subcategories."
        "V-220912" = "Rename built-in guest account."
        "V-220911" = "Rename built-in administrator account."
        "V-220910" = "Restrict local accounts with blank passwords from network access."
        "V-220909" = "Disable built-in guest account."
        "V-220908" = "Disable built-in administrator account."
        "V-220907" = "Maintain default HKEY_LOCAL_MACHINE registry permissions."
        "V-220906" = "Install US DoD CCEB Interoperability Root CA cross-certificates in Untrusted Store on unclassified systems."
        "V-220905" = "Install DoD Interoperability Root CA cross-certificates in Untrusted Store on unclassified systems."
        "V-220904" = "Install External Root CA certificates in Trusted Root Store on unclassified systems."
        "V-220903" = "Install DoD Root CA certificates in Trusted Root Store."
        "V-220902" = "Enable Windows 10 Kernel DMA Protection."
        "V-220871" = "Disallow Windows Ink Workspace access above lock screen."
        "V-220870" = "Disable convenience PIN on Windows 10."
        "V-220869" = "Prevent Windows apps voice activation when locked."
        "V-220868" = "Disable Digest authentication for WinRM client."
        "V-220867" = "Prevent WinRM service from storing RunAs credentials."
        "V-220866" = "Disallow unencrypted traffic on WinRM service."
        "V-220863" = "Disallow unencrypted traffic on WinRM client."
        "V-220860" = "Enable PowerShell script block logging."
        "V-220859" = "Disable auto sign-in after system restart."
        "V-220858" = "Notify users of web-based software install attempts."
        "V-220856" = "Prevent users from changing install options."
        "V-220855" = "Disable indexing of encrypted files."
        "V-220854" = "Disallow basic auth for RSS feeds over HTTP."
        "V-220853" = "Block attachments from RSS feeds."
        "V-220852" = "Set Remote Desktop client encryption to required level."
        "V-220851" = "Require secure RPC on Remote Desktop Session Host."
        "V-220850" = "Always prompt Remote Desktop clients for passwords."
        "V-220849" = "Prevent local drives sharing with Remote Desktop hosts."
        "V-220848" = "Do not save passwords in Remote Desktop Client."
        "V-220847" = "Require minimum PIN length of six or more."
        "V-220846" = "Enable hardware security device for Windows Hello."
        "V-220845" = "Disable Windows Game Recording and Broadcasting."
        "V-220844" = "Enable Defender SmartScreen for Microsoft Edge."
        "V-220843" = "Disable password manager in Edge browser."
        "V-220842" = "Prevent cert error overrides in Microsoft Edge."
        "V-220841" = "Disallow ignoring SmartScreen warnings for files in Edge."
        "V-220840" = "Disallow ignoring SmartScreen warnings for websites in Edge."
        "V-220839" = "Run File Explorer shell protocol in protected mode."
        "V-220837" = "Enable Explorer Data Execution Prevention."
        "V-220836" = "Enable Windows Defender SmartScreen for Explorer."
        "V-220834" = "Do not set Windows Telemetry to Full."
        "V-220833" = "Limit Enhanced diagnostic data to support Windows Analytics."
        "V-220832" = "Do not enumerate Administrator accounts during elevation."
        "V-220830" = "Enable enhanced anti-spoofing for facial recognition."
        "V-220824" = "Restrict unauthenticated RPC clients from RPC server."
        "V-220822" = "Prompt for password on resume from sleep (plugged in)."
        "V-220821" = "Prompt for password on resume from sleep (on battery)."
        "V-220820" = "Do not enumerate local users on domain-joined computers."
        "V-220819" = "Do not show network selection UI on logon screen."
        "V-220818" = "Attempt device authentication using certificates."
        "V-220817" = "Prevent printing over HTTP."
        "V-220816" = "Prevent web publishing and online ordering wizards from downloading provider lists."
        "V-220815" = "Prevent downloading print driver packages over HTTP."
        "V-220814" = "Reprocess Group Policy objects even if unchanged."
        "V-220813" = "ELAM boot-start driver policy must prevent boot drivers."
        "V-220811" = "Enable Virtualization Based Security with Secure Boot or Secure Boot + DMA Protection."
        "V-220810" = "Enable Remote host delegation of non-exportable credentials."
        "V-220809" = "Include command line data in process creation events."
        "V-220808" = "Disable Wi-Fi Sense."
        "V-220807" = "Block connections to non-domain networks when on domain network."
        "V-220806" = "Limit simultaneous internet and domain connections."
        "V-220805" = "Prioritize ECC curves with longer key lengths."
        "V-220803" = "Disable Internet connection sharing."
        "V-220802" = "Disable insecure SMB server logons."
        "V-220801" = "Remove 'Run as different user' from context menus."
        "V-220800" = "Disable WDigest Authentication."
        "V-220799" = "Filter privileged token for local admins on domain systems."
        "V-220796" = "Prevent IP source routing."
        "V-220795" = "Set IPv6 source routing to highest protection."
        "V-220794" = "Disable lock screen slide shows."
        "V-220793" = "Cover or disable camera when not in use."
        "V-220792" = "Disable camera access from lock screen."
        "V-220791" = "Audit MPSSVC Rule-Level Policy Change Failures."
        "V-220790" = "Audit MPSSVC Rule-Level Policy Change Successes."
        "V-220789" = "Audit Detailed File Share Failures."
        "V-220788" = "Audit other Logon/Logoff Failures."
        "V-220787" = "Audit other Logon/Logoff Successes."
        "V-220786" = "Audit Other Policy Change Events Failures."
        "V-220784" = "Restrict System event log access to privileged accounts."
        "V-220783" = "Restrict Security event log access to privileged accounts."
        "V-220782" = "Restrict Application event log access to privileged accounts."
        "V-220781" = "Set System event log size > 32768 KB."
        "V-220780" = "Set Security event log size > 1024000 KB."
        "V-220779" = "Set Application event log size > 32768 KB."
        "V-220778" = "Audit System Integrity successes."
        "V-220777" = "Audit System Integrity failures."
        "V-220776" = "Audit Security System Extension successes."
        "V-220775" = "Audit Security State Change successes."
        "V-220774" = "Audit Other System Events failures."
        "V-220773" = "Audit Other System Events successes."
        "V-220772" = "Audit IPSec Driver failures."
        "V-220771" = "Audit Sensitive Privilege Use successes."
        "V-220770" = "Audit Sensitive Privilege Use failures."
        "V-220769" = "Audit Authorization Policy Change successes."
        "V-220768" = "Audit Authentication Policy Change successes."
        "V-220767" = "Audit Audit Policy Change successes."
        "V-220766" = "Audit Removable Storage successes."
        "V-220765" = "Audit Removable Storage failures."
        "V-220764" = "Audit Other Object Access Events failures."
        "V-220763" = "Audit Other Object Access Events successes."
        "V-220762" = "Audit File Share successes."
        "V-220761" = "Audit File Share failures."
        "V-220760" = "Audit Special Logon successes."
        "V-220759" = "Audit Logon successes."
        "V-220758" = "Audit Logon failures."
        "V-220757" = "Audit Logoff successes."
        "V-220756" = "Audit Group Membership successes."
        "V-220755" = "Audit Account Lockout failures."
        "V-220754" = "Audit Process Creation successes."
        "V-220753" = "Audit PNP Activity successes."
        "V-220752" = "Audit User Account Management successes."
        "V-220751" = "Audit User Account Management failures."
        "V-220750" = "Audit Security Group Management successes."
        "V-220749" = "Audit Credential Validation successes."
        "V-220748" = "Audit Credential Validation failures."
        "V-220746" = "Enable Microsoft password complexity filter."
        "V-220745" = "Set minimum password length to 14 characters."
        "V-220744" = "Set minimum password age to at least 1 day."
        "V-220743" = "Set maximum password age to 60 days or less."
        "V-220742" = "Remember last 24 passwords in history."
        "V-220741" = "Reset bad logon counter after 15 minutes."
        "V-220740" = "Allow max 3 bad logon attempts."
        "V-220739" = "Set account lockout duration to 15 minutes or more."
        "V-220738" = "Limit nonpersistent VM sessions to 24 hours."
        "V-220736" = "Notify user on Bluetooth connection attempt."
        "V-220735" = "Turn off Bluetooth when not in use."
        "V-220734" = "Disable Bluetooth unless organization approved."
        "V-220733" = "Remove orphaned SIDs from user rights."
        "V-220732" = "Disable Secondary Logon service."
        "V-220731" = "Disable SMBv1 on SMB client."
        "V-220730" = "Disable SMBv1 on SMB server."
        "V-220729" = "Disable SMBv1 on system."
        "V-220728" = "Disable PowerShell 2.0 feature."
        "V-220725" = "Allow inbound firewall exceptions only for authorized remote hosts."
        "V-220724" = "Install and enable host-based firewall."
        "V-220723" = "Remove software certificate install files."
        "V-220722" = "Uninstall / Remove TFTP Client."
        "V-220721" = "Uninstall / Remove Telnet Client."
        "V-220720" = "Uninstall / Remove imple TCP/IP Services."
        "V-220719" = "Uninstall / Remove SNMP."
        "V-220717" = "Set system file and directory permissions to minimum requirements."
        "V-220716" = "Require password expiration on accounts."
        "V-220714" = "Allow only authorized users to create/run virtual machines."
        "V-220713" = "Limit Backup Operators group to backup personnel."
        "V-220710" = "Restrict non-system file shares to required groups only."
        "V-220709" = "Do not allow alternate operating systems on same system."
        "V-220705" = "Use deny-all, permit-by-exception software execution policy."
        "V-220701" = "Use automated flaw scans: continuous (ESS), 30-day (internal), annual (external)."
        "V-220699" = "Use UEFI firmware and run in UEFI mode, not Legacy BIOS."
        "V-220698" = "Enable and prepare TPM on domain-joined systems."
        "V-220697" = "Use Windows 10 Enterprise 64-bit for domain-joined systems." 

        ##LOW STIG REQUIREMENTS 
        "V-220700" = "Secure Boot - Enabled on Windows 10 Systems"
        "V-220711" = "Inactive Accounts - Accounts older than 35 days removed"
        "V-220715" = "Standard Accounts - Local accounts must not exist"
        "V-220797" = "Internet Redirects - Prevent ICMP redirects from OSPF routes"
        "V-220798" = "NetBIOS Name Requests - Ignored except for those from WINS servers"
        "V-220826" = "Application Compatability Program Inventory - disabled sending data to Microsoft"
        "V-220831" = "Microsoft Consumer Experiences - Disabled notifications and suggestions"
        "V-220835" = "Microsoft Updates - Disabled external sources for updates except Microsoft"
        "V-220838" = "File Explorer - Heap termination on corruption disabled"
        "V-220872" = "Third-Party Applications - System configured to prevent notifications"
        "V-220917" = "Computer Account Password - 30 Day automatic password rotation enabled"
        "V-220918" = "Computer Account Password - Password expiry set to less than 30 Days"
        "V-220922" = "Windows Dialog Box - failure to display banner negates legal proceedings"
        "V-220923" = "Cached Credentials - Credentials prevented from being cached locally"
        "V-220943" = "Global System Objects Permissions - permissions of these objects increased"
        "V-220954" = "Toast Notifications - Toast notifications prevented from displaying on lock screen"
        "V-252903" = "Virtualization-Based Code Integrity - enforces kernel mode memory protections and validation paths"
        "V-220825" = "Microsoft UWP - Microsoft account required set to optional where unnecssary"
}
# END REGION

# LOGGING / COMPLIANCE STATUS / RESULTS TABLE

function Parse-SecurityPolicy {
    param (
        [Parameter(Mandatory)]
        [string]$CfgFile
    )

    secedit /export /cfg "$CfgFile" | Out-Null

    $content = Get-Content $CfgFile -Raw
    $sections = @{}
    $sectionHeaders = [regex]::Matches($content, "(?<=\[)(.*?)(?=\])")

    for ($i = 0; $i -lt $sectionHeaders.Count; $i++) {
        $header = $sectionHeaders[$i].Value
        $sectionPattern = if ($i -lt $sectionHeaders.Count - 1) {
            "(?<=\[$header\])([\s\S]*?)(?=\[)"
        } else {
            "(?<=\[$header\])([\s\S]*)"
        }

        $sectionMatch = [regex]::Match($content, $sectionPattern)
        $sectionData = @{}

        foreach ($line in $sectionMatch.Groups[1].Value -split "`r?`n") {
            if ($line -match "=") {
                $name, $value = $line -split "=", 2
                $sectionData[$name.Trim()] = $value.Trim()
            }
        }

        $sections[$header] = New-Object PSObject -Property $sectionData
    }

    return New-Object PSObject -Property $sections
}

function Set-SecurityPolicy {
    param (
        [Parameter(Mandatory)]
        [psobject]$PolicyObject,

        [Parameter(Mandatory)]
        [string]$CfgFile
    )

    $lines = @()

    foreach ($section in $PolicyObject.PSObject.Properties) {
        $lines += "[$($section.Name)]"
        foreach ($property in $section.Value.PSObject.Properties) {
            $lines += "$($property.Name)=$($property.Value)"
        }
        $lines += "" 
    }

    $lines | Out-File -FilePath $CfgFile -Encoding Unicode -Force

    secedit /configure /db "$env:SystemRoot\security\database\local.sdb" /cfg "$CfgFile" /areas SECURITYPOLICY | Out-Null
}

if (!(Test-Path (Split-Path $script:Config.LogFile))) { 
    New-Item -ItemType Directory -Path (Split-Path $script:Config.LogFile) -Force | Out-Null 
}
if (!(Test-Path (Split-Path $script:Config.ReportPath))) { 
    New-Item -ItemType Directory -Path (Split-Path $script:Config.ReportPath) -Force | Out-Null 
}

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    Add-Content -Path $script:Config.LogFile -Value $logEntry -ErrorAction SilentlyContinue
    
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARN" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
}

function Set-STIGCompliance {
    param (
        [string]$STIGId,
        [ValidateSet("IN COMPLIANCE", "NON-COMPLIANT", "NOT APPLICABLE")]
        [string]$Status
    )
    
    $global:STIGCompliance[$STIGId] = $Status
}

function Add-Result {
    param (
        [string]$Id,
        [string]$Message,
        [ValidateSet("Success", "Fail")]
        [string]$Status
    )
    
    $global:Results += @{
        ID = $Id
        Message = $Message
        Status = $Status
        Timestamp = Get-Date
    }
    
    if ($Status -eq "Success") {
        Set-STIGCompliance -STIGId $Id -Status "IN COMPLIANCE"
    } else {
        Set-STIGCompliance -STIGId $Id -Status "NON-COMPLIANT"
    }
}
#END-REGION

#INDIVIDUAL STIG REMEDIATION FUNCTIONS
function Set-RegistryValue {
    param (
        [string]$Id,
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$ValueType = "String"
    )
    
    try {
        if (!(Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        
        Set-ItemProperty -Path $Path -Name $Name -Value $Value
        
        $actualValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($actualValue.$Name -eq $Value) {
            Add-Result -Id $Id -Message "Registry setting configured: $Name = $Value" -Status "Success"
        } else {
            Add-Result -Id $Id -Message "Failed to verify registry setting: $Path\$Name" -Status "Fail"
        }
        
    } catch {
        Add-Result -Id $Id -Message "Failed to set registry: $Path\$Name - $_" -Status "Fail"
    }
}

function Invoke-SecurityPolicyBaseline {
    param ([string]$Id = "V-XYZZYX")

    Write-Log "Applying security policy baseline..." "INFO"

    $DependentItems = @(
        "V-220967", "V-220963", "V-220958",
        "V-220938", "V-220937", "V-220932",
        "V-220930", "V-220929", "V-220928",
        "V-220983", "V-220982", "V-220981",
        "V-220980", "V-220979", "V-220978",
        "V-220977", "V-220976", "V-220975",
        "V-220974", "V-220973", "V-220966",
        "V-220965", "V-220964", "V-220962",
        "V-220961", "V-220960", "V-220959",
        "V-220957", "V-220956", "V-220931",
        "V-220713"
    )

    try {
        $url = "https://raw.githubusercontent.com/YarinetXYZ/SBE/main/secpol.cfg"
        $cfgPath = "C:\Temp\SecurityConfig.inf"

        Write-Log "Downloading baseline config from: $url" "INFO"

        if (!(Test-Path "C:\Temp")) {
            New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null
        }

        Invoke-WebRequest -Uri $url -OutFile $cfgPath -ErrorAction Stop

        if ((Get-Item $cfgPath).Length -eq 0) {
            throw "Downloaded configuration file is empty"
        }

        Get-Content $cfgPath -Raw | Out-File $cfgPath -Encoding Unicode -Force

        $policy = Parse-SecurityPolicy -CfgFile $cfgPath

        $policy.'System Access'.PasswordComplexity      = 1
        $policy.'System Access'.MinimumPasswordLength   = 10
        $policy.'System Access'.MaximumPasswordAge      = 60

        Set-SecurityPolicy -PolicyObject $policy -CfgFile $cfgPath

        Add-Result -Id $Id -Message "Security policy baseline applied" -Status "Success"

        foreach ($item in $DependentItems) {
            $global:Results += @{
                ID        = $item
                Message   = "Compliant via security policy baseline ($Id)"
                Status    = "Success"
                Timestamp = Get-Date
            }
            $global:STIGCompliance[$item] = "IN COMPLIANCE"
        }

    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Security policy baseline error: $errorMsg" "ERROR"

        Add-Result -Id $Id -Message "Failed to apply security policy baseline: $errorMsg" -Status "Fail"

        foreach ($item in $DependentItems) {
            $global:Results += @{
                ID        = $item
                Message   = "Non-compliant due to security policy baseline failure ($Id)"
                Status    = "Fail"
                Timestamp = Get-Date
            }
            $global:STIGCompliance[$item] = "NON-COMPLIANT"
            Write-Log "STIG ${item}: NON-COMPLIANT (baseline failed)" "ERROR"
        }
    }
}

function Invoke-AuditPolicyBaseline {
    param ([string]$Id = "V-220913")

    Write-Log "Applying audit policy baseline..." "INFO"

    $DependentItems = 
    @("V-220778", "V-220777", "V-220776", "V-220775", "V-220774", "V-220773", "V-220772", "V-220771", "V-220770", "V-220769",
      "V-220768", "V-220767", "V-220766", "V-220765", "V-220764", "V-220763", "V-220762", "V-220761", "V-220760", "V-220759",
      "V-220758", "V-220757", "V-220756", "V-220755", "V-220754", "V-220753", "V-220752", "V-220751", "V-220750", "V-220749",
      "V-220748", "V-220791", "V-220790", "V-220781", "V-220788", "V-220787", "V-220786", "V-220789"
    )

    $commands = @(
        # V-220778 – System Integrity success
        'auditpol /set /subcategory:"System Integrity" /success:enable',
        # V-220777 – System Integrity failure
        'auditpol /set /subcategory:"System Integrity" /failure:enable',
        # V-220776 – Security System Extension success
        'auditpol /set /subcategory:"Security System Extension" /success:enable',
        # V-220775 – Security State Change success
        'auditpol /set /subcategory:"Security State Change" /success:enable',
        # V-220774 – Other System Events failure
        'auditpol /set /subcategory:"Other System Events" /failure:enable',
        # V-220773 – Other System Events success
        'auditpol /set /subcategory:"Other System Events" /success:enable',
        # V-220772 – IPSec Driver failure
        'auditpol /set /subcategory:"IPSec Driver" /failure:enable',
        # V-220771 – Sensitive Privilege Use success
        'auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable',
        # V-220770 – Sensitive Privilege Use failure
        'auditpol /set /subcategory:"Sensitive Privilege Use" /failure:enable',
        # V-220769 – Authorization Policy Change success
        'auditpol /set /subcategory:"Authorization Policy Change" /success:enable',
        # V-220768 – Authentication Policy Change success
        'auditpol /set /subcategory:"Authentication Policy Change" /success:enable',
        # V-220767 – Audit Policy Change success
        'auditpol /set /subcategory:"Audit Policy Change" /success:enable',
        # V-220766 – Removable Storage success
        'auditpol /set /subcategory:"Removable Storage" /success:enable',
        # V-220765 – Removable Storage failure
        'auditpol /set /subcategory:"Removable Storage" /failure:enable',
        # V-220764 – Other Object Access Events failure
        'auditpol /set /subcategory:"Other Object Access Events" /failure:enable',
        # V-220763 – Other Object Access Events success
        'auditpol /set /subcategory:"Other Object Access Events" /success:enable',
        # V-220762 – File Share success
        'auditpol /set /subcategory:"File Share" /success:enable',
        # V-220761 – File Share failure
        'auditpol /set /subcategory:"File Share" /failure:enable',
        # V-220760 – Special Logon success
        'auditpol /set /subcategory:"Special Logon" /success:enable',
        # V-220759 – Logon (successful) success
        'auditpol /set /subcategory:"Logon" /success:enable',
        # V-220758 – Logon failures
        'auditpol /set /subcategory:"Logon" /failure:enable',
        # V-220757 – Logoff success
        'auditpol /set /subcategory:"Logoff" /success:enable',
        # V-220756 – Group Membership success
        'auditpol /set /subcategory:"Group Membership" /success:enable',
        # V-220755 – Account Lockout failure
        'auditpol /set /subcategory:"Account Lockout" /failure:enable',
        # V-220754 – Process Creation success
        'auditpol /set /subcategory:"Process Creation" /success:enable',
        # V-220753 – PNP Activity successes
        'auditpol /set /subcategory:"Plug and Play Events" /success:enable',
        # V-220752 – User Account Management success
        'auditpol /set /subcategory:"User Account Management" /success:enable',
        # V-220751 – User Account Management failure
        'auditpol /set /subcategory:"User Account Management" /failure:enable',
        # V-220750 – Security Group Management success
        'auditpol /set /subcategory:"Security Group Management" /success:enable',
        # V-220749 – Credential Validation success
        'auditpol /set /subcategory:"Credential Validation" /success:enable',
        # V-220748 – Credential Validation failure
        'auditpol /set /subcategory:"Credential Validation" /failure:enable',
        # V-220791 – MPSSVC Rule-Level Policy Change failure
        'auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /failure:enable',
        # V-220790 – MPSSVC Rule-Level Policy Change success
        'auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable',
        # V-220789 – Detailed File Share failure
        'auditpol /set /subcategory:"Detailed File Share" /failure:enable',
        # V-220788 – Other Logon/Logoff Events failure
        'auditpol /set /subcategory:"Other Logon/Logoff Events" /failure:enable',
        # V-220787 – Other Logon/Logoff Events success
        'auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable',
        # V-220786 – Other Policy Change Events failure
        'auditpol /set /subcategory:"Other Policy Change Events" /failure:enable',
        # V-257589 – Process Creation failure (command-line)
        'auditpol /set /subcategory:"Process Creation" /failure:enable'
    )

    try {
        foreach ($cmd in $commands) {
            try {
                $process = Start-Process -FilePath "auditpol.exe" -ArgumentList $cmd.Substring(9) -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\auditpol_out.txt" -RedirectStandardError "$env:TEMP\auditpol_err.txt"

                if ($process.ExitCode -ne 0) {
                    $stdout = Get-Content "$env:TEMP\auditpol_out.txt" -Raw
                    $stderr = Get-Content "$env:TEMP\auditpol_err.txt" -Raw
                    Write-Log "AuditPol command failed: $cmd" "ERROR"
                    Write-Log "ExitCode: $($process.ExitCode)" "ERROR"
                    Write-Log "StdOut: $stdout" "ERROR"
                    Write-Log "StdErr: $stderr" "ERROR"
                }

                Remove-Item "$env:TEMP\auditpol_out.txt","$env:TEMP\auditpol_err.txt" -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Exception running AuditPol command: $cmd" "ERROR"
                Write-Log $_.Exception.Message "ERROR"
            }
        }

        Add-Result -Id $Id -Message "Audit policy baseline applied." -Status "Success"

        foreach ($item in $DependentItems) {
            $global:Results += @{
                ID        = $item
                Message   = "Compliant via audit policy baseline ($Id)"
                Status    = "Success"
                Timestamp = Get-Date
            }
            $global:STIGCompliance[$item] = "IN COMPLIANCE"
        }

    } catch {
        $errorMsg = $_.Exception.Message
        Write-Log "Audit policy baseline error: $errorMsg" "ERROR"

        Add-Result -Id $Id -Message "Failed to apply audit policy baseline: $errorMsg" -Status "Fail"

        foreach ($item in $DependentItems) {
            $global:Results += @{
                ID        = $item
                Message   = "Non-compliant due to audit policy baseline failure ($Id)"
                Status    = "Fail"
                Timestamp = Get-Date
            }
            $global:STIGCompliance[$item] = "NON-COMPLIANT"
        }
    }
}   

function Remove-AgedAccounts {
    param ([string]$Id = "V-220711")

    Write-Log "Checking for Aged Accounts..." "INFO"
    
    $nonCompliantUsers = @()

    try {
        $users = Get-LocalUser

        foreach ($user in $users) {
            if ($user.Enabled -eq $false -or $user.Name -match '^(Administrator|Guest|DefaultAccount|WDAGUtilityAccount)$') {
                continue
            }

            $lastLogon = $user.LastLogon
            $daysSinceLastLogon = if ($lastLogon) { (Get-Date) - $lastLogon } else { [timespan]::MaxValue }

            if ($daysSinceLastLogon.Days -gt 35) {
                $nonCompliantUsers += $user.Name
                Write-Log "Aged account detected: $($user.Name), Last Logon: $lastLogon" "WARN"

                if ($script:Config.RemoveAgedAccounts) {
                    try {
                        Remove-LocalUser -Name $user.Name -ErrorAction Stop
                        Write-Log "Removed aged account: $($user.Name)" "SUCCESS"
                    } catch {
                        Write-Log "Failed to remove aged account: $($user.Name) - $_" "ERROR"
                    }
                } else {
                    Write-Log "Removal skipped (RemoveAgedAccounts = false): $($user.Name)" "INFO"
                }
            } else {
                Write-Log "Active account: REDACTED, Last Logon: $lastLogon" "INFO"
            }
        }

        if ($nonCompliantUsers.Count -eq 0) {
            Add-Result -Id $Id -Message "All local accounts are compliant (last logon within 35 days)." -Status "Success"
        } else {
            Add-Result -Id $Id -Message "Found aged accounts: $($nonCompliantUsers -join ', ')" -Status "Non-Compliant"
        }

    } catch {
        Write-Log "Failed to scan aged accounts: $_" "ERROR"
        Add-Result -Id $Id -Message "Exception occurred while checking accounts: $_" -Status "Fail"
    }
}

function Remove-UnauthorizedScheduledTasks {
    Write-Log "Scanning for unauthorized scheduled tasks..." "INFO"
    
    try {
        $suspiciousTasks = Get-ScheduledTask | Where-Object {
            $_.Principal -and
            ($_.Principal.UserId -eq "SYSTEM" -or $_.Principal.RunLevel -eq "Highest") -and
            $_.TaskPath -notmatch "^(\\Microsoft\\|\\Windows\\)"
        } | Where-Object {
            $taskName = $_.TaskName
            -not ($script:Config.TaskExclusionList | Where-Object { $taskName -match $_ })
        }
        
        foreach ($task in $suspiciousTasks) {
            $taskFullName = "$($task.TaskPath)$($task.TaskName)"
            Write-Log "Unauthorized Task: $taskFullName" "WARN"
            
            if ($script:Config.RemoveUnauthorizedTasks) {
                try {
                    $taskPath = if ($task.TaskPath.EndsWith("\")) { $task.TaskPath } else { "$($task.TaskPath)\" }
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop
                    Write-Log "Removed Unauthorized Task: $taskFullName" "SUCCESS"
                } catch {
                    Write-Log "Failed to remove task: $taskFullName - $_" "ERROR"
                }
            }
        }
        
        Write-Log "Remediated $($suspiciousTasks.Count) suspicious scheduled tasks" "INFO"
        
    } catch {
        Write-Log "Failed to scan scheduled tasks: $_" "ERROR"
    }
}

function Remove-UnauthorizedAdministrators {
    Write-Log "Checking For Unauthorized Administrators..." "INFO"

    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop

        $computerName = $env:COMPUTERNAME
        $normalizedApproved = $script:Config.ApprovedAdmins | ForEach-Object {
            $_ -replace "^BUILTIN\\", "" `
               -replace ("^$computerName\\"), "" `
               | ForEach-Object { $_.ToLower() }
        }

        foreach ($admin in $adminGroup) {
            $adminName = ($admin.Name -replace "^.*\\", "").ToLower()
            $isApproved = $normalizedApproved -contains $adminName

            if (-not $isApproved) {
                Write-Log "Unauthorized Administrator: $($admin.Name)" "WARN"

                if ($script:Config.RemoveUnauthorizedAdmins) {
                    try {
                        Remove-LocalGroupMember -Group "Administrators" -Member $admin.Name -ErrorAction Stop
                        Write-Log "Removed Unauthorized Administrator: $($admin.Name)" "SUCCESS"
                    } catch {
                        Write-Log "Failed to remove administrator: $($admin.Name) - $_" "ERROR"
                    }
                }
            } else {
                Write-Log "Approved administrator: REDACTED" "INFO"
            }
        }

    } catch {
        Write-Log "Failed to scan administrator accounts: $_" "ERROR"
    }
}

function Remove-UnauthorizedAccountsAndServices {
    param ([string]$Id = "V-220712")

    Write-Log "Scanning for unauthorized admin accounts and services (SID protected)..." "INFO"

    try {
        $adminsRemediated = 0
        $servicesRemediated = 0
        $unauthorizedUsers = @()
        $unauthorizedServices = @()

        $groups = @("Administrators", "Backup Operators", "Power Users",
                    "Remote Desktop Users", "Hyper-V Administrators",
                    "Network Configuration Operators", "Distributed COM Users")

        foreach ($group in $groups) {
            try {
                Get-LocalGroupMember -Group $group -ErrorAction Stop | Where-Object {
                    $_.ObjectClass -eq 'User'
                } | ForEach-Object {
                    $userName = ($_.Name -replace '^.*\\', '')
                    $userObj  = Get-LocalUser -Name $userName -ErrorAction SilentlyContinue
                    $userSID  = if ($userObj) { $userObj.SID.Value } else { $null }

                    # Skip if account SID is approved or account used recently (<35 days)
                    $recentUse = $false
                    if ($userObj -and $userObj.LastLogon -and ((Get-Date) - $userObj.LastLogon).Days -lt 35) {
                        $recentUse = $true
                    }

                    if (($script:Config.ApprovedAdminSIDs -contains $userSID) -or $recentUse) {
                        Write-Log "Account approved or recently active: $($_.Name)" "INFO"
                        return
                    }

                    # Not approved → unauthorized
                    $unauthorizedUsers += "$($_.Name) (Group: ${group})"
                    Write-Log "Unauthorized Account in ${group}: $($_.Name)" "WARN"

                    if ($script:Config.RemoveUnauthorizedAdmins) {
                        try {
                            Disable-LocalUser -Name $userName -ErrorAction Stop
                            Write-Log "Disabled Unauthorized Account: $($_.Name)" "SUCCESS"
                            $adminsRemediated++
                        } catch {
                            Write-Log "Failed to disable account: $($_.Name) - $_" "ERROR"
                        }
                    }
                }
            } catch {
                Write-Verbose "Group $group not accessible: $_"
            }
        }

        # Unauthorized services logic remains unchanged
        Get-CimInstance Win32_Service | Where-Object {
            $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\(LocalService|NetworkService))$' -and
            -not ($script:Config.ApprovedServiceAccounts -contains $_.StartName)
        } | ForEach-Object {
            $unauthorizedServices += "$($_.Name) - $($_.StartName)"
            if ($script:Config.StopUnauthorizedServices) {
                try {
                    Stop-Service -Name $_.Name -Force -ErrorAction Stop
                    Set-Service -Name $_.Name -StartupType Disabled
                    Write-Log "Disabled Service: $($_.Name)" "SUCCESS"
                    $servicesRemediated++
                } catch {
                    Write-Log "Failed to disable service: $($_.Name) - $_" "ERROR"
                }
            }
        }

        if ($adminsRemediated -or $servicesRemediated) {
            Add-Result -Id $Id -Message "Remediated $adminsRemediated unauthorized user accounts and $servicesRemediated unauthorized services." -Status "Success"
        } elseif ($unauthorizedUsers.Count -or $unauthorizedServices.Count) {
            $details = @()
            if ($unauthorizedUsers.Count) { $details += "Users: $($unauthorizedUsers -join ', ')" }
            if ($unauthorizedServices.Count) { $details += "Services: $($unauthorizedServices -join ', ')" }
            Add-Result -Id $Id -Message "Unauthorized entities found but not remediated: $($details -join '; ')" -Status "Fail"
        } else {
            Add-Result -Id $Id -Message "No unauthorized user accounts or services found." -Status "Success"
        }
    } catch {
        Write-Log "Failed to scan administrator accounts: $_" "ERROR"
    }
}

function Remove-IISFeatures {
    param ([string]$Id = "V-220718")

    try {
        $iisFeatures = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "IIS*" }

        if ($iisFeatures.Count -eq 0) {
            Add-Result -Id $Id -Message "IIS Features not installed" -Status "Success"
            return
        }

        $featuresRemoved = 0
        $featuresFailed = @()

        foreach ($feature in $iisFeatures) {
            if ($feature.State -eq "Enabled") {
                try {
                    $process = Start-Process -FilePath "dism.exe" `
                        -ArgumentList "/Online", "/Disable-Feature", "/FeatureName:$($feature.FeatureName)", "/Remove", "/NoRestart" `
                        -NoNewWindow -WindowStyle Hidden `
                        -RedirectStandardOutput "$null" -RedirectStandardError "$null" `
                        -Wait -PassThru

                    if ($process.ExitCode -eq 0) {
                        $featuresRemoved++
                    } else {
                        $featuresFailed += $feature.FeatureName
                    }
                } catch {
                    $featuresFailed += $feature.FeatureName
                }
            }
        }

        if ($featuresRemoved -gt 0 -and $featuresFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "Successfully removed $featuresRemoved IIS features." -Status "Success"
        } elseif ($featuresRemoved -eq 0 -and $featuresFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "No IIS Features installed" -Status "Success"
        } elseif ($featuresFailed.Count -gt 0) {
            Add-Result -Id $Id -Message "Failed to remove IIS Features: $($featuresFailed -join ', ')" -Status "Fail"
        }

    } catch {
        Add-Result -Id $Id -Message "Error occurred during IIS removal: $_" -Status "Fail"
    }
}

function Remove-TFTPClient {
    param ([string]$Id = "V-220722")

    try {
        $tftpClient = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "TFTP*" }

        if ($tftpClient.Count -eq 0) {
            Add-Result -Id $Id -Message "TFTP Client not installed." -Status "Success"
            return
        }

        $clientRemoved = 0
        $clientFailed = @()

        foreach ($client in $tftpClient) {
            if ($client.State -eq "Enabled") {
                try {
                    $process = Start-Process -FilePath "dism.exe" `
                        -ArgumentList "/Online", "/Disable-Feature", "/FeatureName:$($client.FeatureName)", "/Remove", "/NoRestart" `
                        -NoNewWindow -WindowStyle Hidden `
                        -RedirectStandardOutput "$null" -RedirectStandardError "$null" `
                        -Wait -PassThru

                    if ($process.ExitCode -eq 0) {
                        $clientRemoved++
                    } else {
                        $clientFailed += $client.FeatureName
                    }
                } catch {
                    $clientFailed += $client.FeatureName
                }
            }
        }

        if ($clientRemoved -gt 0 -and $clientFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "Successfully removed $clientRemoved IIS features." -Status "Success"
        } elseif ($clientRemoved -eq 0 -and $clientFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "No TFTP Client installed" -Status "Success"
        } elseif ($clientFailed.Count -gt 0) {
            Add-Result -Id $Id -Message "Failed to remove TFTP Client: $($clientFailed -join ', ')" -Status "Fail"
        }

    } catch {
        Add-Result -Id $Id -Message "Error occurred during TFTP removal: $_" -Status "Fail"
    }
}

function Remove-TelnetClient {
    param ([string]$Id = "V-220721")

    try {
        $telnetClient = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "TelnetClient*" }

        if ($telnetClient.Count -eq 0) {
            Add-Result -Id $Id -Message "Telnet Client not installed." -Status "Success"
            return
        }

        $clientRemoved = 0
        $clientFailed = @()

        foreach ($client in $telnetClient) {
            if ($client.State -eq "Enabled") {
                try {
                    $process = Start-Process -FilePath "dism.exe" `
                        -ArgumentList "/Online", "/Disable-Feature", "/FeatureName:$($client.FeatureName)", "/Remove", "/NoRestart" `
                        -NoNewWindow -WindowStyle Hidden `
                        -RedirectStandardOutput "$null" -RedirectStandardError "$null" `
                        -Wait -PassThru

                    if ($process.ExitCode -eq 0) {
                        $clientRemoved++
                    } else {
                        $clientFailed += $client.FeatureName
                    }
                } catch {
                    $clientFailed += $client.FeatureName
                }
            }
        }

        if ($clientRemoved -gt 0 -and $clientFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "Successfully removed $clientRemoved IIS features." -Status "Success"
        } elseif ($clientRemoved -eq 0 -and $clientFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "No Telnet Client installed." -Status "Success"
        } elseif ($clientFailed.Count -gt 0) {
            Add-Result -Id $Id -Message "Failed to remove Telnet Client: $($clientFailed -join ', ')" -Status "Fail"
        }

    } catch {
        Add-Result -Id $Id -Message "Error occurred during Telnet removal: $_" -Status "Fail"
    }
}

function Remove-TCPIPServices {
    param ([string]$Id = "V-220720")

    try {
        $tcpipServices = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "TCPIP*" }

        if ($tcpipServices.Count -eq 0) {
            Add-Result -Id $Id -Message "TCPIP Services not installed." -Status "Success"
            return
        }

        $serviceRemoved = 0
        $serviceFailed = @()

        foreach ($client in $tcpipServices) {
            if ($client.State -eq "Enabled") {
                try {
                    $process = Start-Process -FilePath "dism.exe" `
                        -ArgumentList "/Online", "/Disable-Feature", "/FeatureName:$($client.FeatureName)", "/Remove", "/NoRestart" `
                        -NoNewWindow -WindowStyle Hidden `
                        -RedirectStandardOutput "$null" -RedirectStandardError "$null" `
                        -Wait -PassThru

                    if ($process.ExitCode -eq 0) {
                        $serviceRemoved++
                    } else {
                        $serviceFailed += $client.FeatureName
                    }
                } catch {
                    $serviceFailed += $client.FeatureName
                }
            }
        }

        if ($serviceRemoved -gt 0 -and $serviceFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "Successfully removed $serviceRemoved IIS features." -Status "Success"
        } elseif ($serviceRemoved -eq 0 -and $serviceFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "No TCPIP Services installed." -Status "Success"
        } elseif ($serviceFailed.Count -gt 0) {
            Add-Result -Id $Id -Message "Failed to remove TCPIP Services.: $($serviceFailed -join ', ')" -Status "Fail"
        }

    } catch {
        Add-Result -Id $Id -Message "Error occurred during TCPIP removal.: $_" -Status "Fail"
    }
}

function Remove-SNMPProtocol {
    param ([string]$Id = "V-220719")

    try {
        $snmpProtocol = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -like "TCPIP*" }

        if ($snmpProtocol.Count -eq 0) {
            Add-Result -Id $Id -Message "SNMP Protocol not installed." -Status "Success"
            return
        }

        $snmpRemoved = 0
        $snmpFailed = @()

        foreach ($snmp in $snmpProtocol) {
            if ($snmp.State -eq "Enabled") {
                try {
                    $process = Start-Process -FilePath "dism.exe" `
                        -ArgumentList "/Online", "/Disable-Feature", "/FeatureName:$($snmp.FeatureName)", "/Remove", "/NoRestart" `
                        -NoNewWindow -WindowStyle Hidden `
                        -RedirectStandardOutput "$null" -RedirectStandardError "$null" `
                        -Wait -PassThru

                    if ($process.ExitCode -eq 0) {
                        $snmpRemoved++
                    } else {
                        $snmpFailed += $client.FeatureName
                    }
                } catch {
                    $snmpFailed += $client.FeatureName
                }
            }
        }

        if ($snmpRemoved -gt 0 -and $snmpFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "Successfully removed $snmpRemoved IIS features." -Status "Success"
        } elseif ($snmpRemoved -eq 0 -and $snmpFailed.Count -eq 0) {
            Add-Result -Id $Id -Message "No SNMP Protocols installed" -Status "Success"
        } elseif ($snmpFailed.Count -gt 0) {
            Add-Result -Id $Id -Message "Failed to remove SNMP Protocols: $($snmpFailed -join ', ')" -Status "Fail"
        }

    } catch {
        Add-Result -Id $Id -Message "Error occurred during SNMP removal: $_" -Status "Fail"
    }
}

function Remove-LocalAccounts {
    param ([string[]]$Id = @("V-220912","V-220911","V-220715","V-220909","V-220908"))
    Write-Log "Checking and managing local accounts..." "INFO"
    try {
        $serial = (Get-CimInstance Win32_BIOS).SerialNumber
        $approvedAdmins = $script:Config.ApprovedAdmins
        $users = Get-LocalUser
        $admin = $users | Where-Object { $_.SID -match '-500$' }
        if ($admin) {
            $desiredAdminName = "YRN-ADM-$serial"
            if ($admin.Name -ne $desiredAdminName) {
                Rename-LocalUser -Name $admin.Name -NewName $desiredAdminName
                Add-Result -Id "V-220911" -Message "Administrator account renamed to '$desiredAdminName'." -Status "Success"
            }
            if (-not ($approvedAdmins -contains $desiredAdminName)) {
                Disable-LocalUser -Name $desiredAdminName
                Add-Result -Id "V-220911" -Message "Administrator account '$desiredAdminName' disabled." -Status "Success"
            } else {
                Add-Result -Id "V-220911" -Message "Administrator account '$desiredAdminName' is approved and remains enabled." -Status "Success"
            }
        } else {
            Add-Result -Id "V-220911" -Message "Administrator account not found." -Status "Success"
        }
        $guest = $users | Where-Object { $_.SID -match '-501$' }
        if ($guest) {
            $desiredGuestName = "YRN-PC-$serial"
            if ($guest.Name -ne $desiredGuestName) {
                Rename-LocalUser -Name $guest.Name -NewName $desiredGuestName
                Add-Result -Id "V-220912" -Message "Guest account renamed to '$desiredGuestName'." -Status "Success"
            }
            if (-not ($approvedAdmins -contains $desiredGuestName)) {
                Disable-LocalUser -Name $desiredGuestName
                Add-Result -Id "V-220912" -Message "Guest account '$desiredGuestName' disabled." -Status "Success"
            } else {
                Add-Result -Id "V-220912" -Message "Guest account '$desiredGuestName' is approved and remains enabled." -Status "Success"
            }
        } else {
            Add-Result -Id "V-220912" -Message "Guest account not found." -Status "Success"
        }
        $nonCompliantUsers = @()
        foreach ($user in $users) {
            if (-not $user.Enabled) { continue }
            if ($user.Name -match '^(DefaultAccount|WDAGUtilityAccount|YRN-ADM-|YRN-PC-)' -or
                ($approvedAdmins -contains $user.Name)) { continue }
            Disable-LocalUser -Name $user.Name
            $nonCompliantUsers += $user.Name
        }
        if ($nonCompliantUsers.Count -eq 0) {
            Add-Result -Id "V-220715" -Message "No active non-compliant local accounts found." -Status "Success"
        } else {
            Add-Result -Id "V-220715" -Message "Disabled non-compliant local accounts: $($nonCompliantUsers -join ', ')" -Status "Success"
        }
        foreach ($extraId in $Id) {
            if ($extraId -notin @("V-220912","V-220911","V-220715")) {
                Add-Result -Id $extraId -Message "Control remediated as part of local account hardening." -Status "Success"
            }
        }
    } catch {
        Write-Log "Failed to manage local accounts: $_" "ERROR"
        foreach ($stig in $Id) {
            Add-Result -Id $stig -Message "Exception occurred while managing accounts: $_" -Status "Fail"
        }
    }
}

function Test-SecureBootStatus {
    param ([string]$Id = "V-220700")

    Write-Log "Checking Secure Boot status..." "INFO"

    try {
        $secureBootEnabled = Confirm-SecureBootUEFI

        if ($secureBootEnabled) {
            Add-Result -Id $Id -Message "Secure Boot is enabled." -Status "Success"
        } else {
            Add-Result -Id $Id -Message "Secure Boot is disabled." -Status "Fail"
        }
    } catch {
        Write-Log "Failed to check Secure Boot status: $_" "ERROR"
        Add-Result -Id $Id -Message "Exception occurred while checking Secure Boot: $_" -Status "Fail"
    }
}

function Test-DEPOptOut {
    param ([string]$Id = "V-220726")

    Write-Log "Checking DEP (Data Execution Prevention) policy using GetSystemDEPPolicy..." "INFO"

    try {
        $depPolicy = [System.Diagnostics.Process]::GetSystemDEPPolicy()

        switch ($depPolicy) {
            1 { $status = "Success"; $desc = "AlwaysOn" }
            3 { $status = "Success"; $desc = "OptOut" }
            0 { $status = "Fail";    $desc = "AlwaysOff" }
            2 { $status = "Fail";    $desc = "OptIn" }
            default { $status = "Fail"; $desc = "Unknown ($depPolicy)" }
        }

        Add-Result -Id $Id -Message "DEP policy is '$desc' (code: $depPolicy)" -Status $status
    }
    catch {
        Add-Result -Id $Id -Message "Failed to check DEP: $_" -Status "Fail"
    }
}

function Test-BitLockerCompliance {
    param ([string]$Id = "V-220702")

    try {
        $ErrorActionPreference = "Stop"

        $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\FVE"
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }

        $xtsfdvcheck = (Get-ItemProperty $policyPath -Name EncryptionMethodWithXtsFdv -ErrorAction SilentlyContinue).EncryptionMethodWithXtsFdv
        $xtsoscheck = (Get-ItemProperty $policyPath -Name EncryptionMethodWithXtsOS -ErrorAction SilentlyContinue).EncryptionMethodWithXtsOS

        if ($xtsfdvcheck -ne 7 -or $xtsoscheck -ne 7) {
            Set-ItemProperty -Path $policyPath -Name EncryptionMethodWithXtsFdv -Value 7 -Type DWord
            Set-ItemProperty -Path $policyPath -Name EncryptionMethodWithXtsOS -Value 7 -Type DWord
        }

        $TPM = Get-WmiObject Win32_Tpm -Namespace root\cimv2\security\microsofttpm | Where-Object { $_.IsEnabled().IsEnabled -eq $true }
        if (-not $TPM) {
            Add-Result -Id $Id -Message "TPM is not present or disabled." -Status "Fail"
            return
        }

        $osVolume = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        $existingTpmProtector = $osVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "Tpm" }
        $existingRecoveryProtector = $osVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }

        if (-not $existingTpmProtector) {
            Add-BitLockerKeyProtector -MountPoint "C:" -TpmProtector | Out-Null
        }
        if (-not $existingRecoveryProtector) {
            Add-BitLockerKeyProtector -MountPoint "C:" -RecoveryPasswordProtector | Out-Null
            $osVolume = Get-BitLockerVolume -MountPoint "C:"
            $existingRecoveryProtector = $osVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq "RecoveryPassword" }
        }

        $usb = Get-Volume | Where-Object { $_.DriveType -eq 'Removable' } | Select-Object -First 1
        $keyPath = $null
        if ($usb -and $existingRecoveryProtector) {
            $serialNumber = (Get-WmiObject Win32_BIOS).SerialNumber -replace '\s',''
            $fileName = "BitLockerKey-$serialNumber.txt"
            $keyPath = Join-Path "$($usb.DriveLetter):\" $fileName

            $recoveryPassword = $existingRecoveryProtector.RecoveryPassword
            if (-not $recoveryPassword) {
                $backup = Backup-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId $existingRecoveryProtector.KeyProtectorId
                $recoveryPassword = $backup.RecoveryPassword
            }

            if ($recoveryPassword) {
                $osDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
                $deviceId = if ($osDrive) { $osDrive.VolumeSerialNumber } else { "Unknown" }

                $content = @"
Recovery Key: $recoveryPassword
Device ID: $deviceId
"@
                Set-Content -Path $keyPath -Value $content -Force
                Write-Output "BitLocker recovery key saved to: $keyPath"
            }
        }

        if ($osVolume.ProtectionStatus -eq "On" -and $osVolume.VolumeStatus -eq "FullyEncrypted") {
            $msg = "OS drive BitLocker is enabled and fully encrypted."
            if ($keyPath) { $msg += " Recovery key saved to $keyPath" }
            Add-Result -Id $Id -Message $msg -Status "Success"
        } else {
            Start-Process "C:\Windows\System32\manage-bde.exe" -ArgumentList "-on C:" -Verb RunAs -Wait
            $msg = "BitLocker encryption started on OS drive."
            if ($keyPath) { $msg += " Recovery key saved to $keyPath" }
            Add-Result -Id $Id -Message $msg -Status "Success"
        }

    } catch {
        Add-Result -Id $Id -Message "General BitLocker check failed. Error: $_" -Status "Fail"
    }
}


function Test-WindowsVersionCompliance {
    param ([string]$Id = "V-220706")
    
    Write-Log "Checking Windows version compliance..." "INFO"
    
    try {
        $buildNumber = [int](Get-ComputerInfo -Property OsBuildNumber).OsBuildNumber
        $endOfLifeDate = [datetime]"2025-10-14"
        $currentDate = Get-Date
        
        $isCompliant = ($buildNumber -ge 19045) -and ($currentDate -lt $endOfLifeDate)
        $message = "Windows build $buildNumber, EOL: $($endOfLifeDate.ToShortDateString())"
        
        if ($isCompliant) {
            Add-Result -Id $Id -Message $message -Status "Success"
        } else {
            Add-Result -Id $Id -Message "$message - Non-compliant" -Status "Fail"
        }
        
    } catch {
        Add-Result -Id $Id -Message "Failed to check Windows version: $_" -Status "Fail"
    }
}

function Test-WindowsDefenderStatus {
    param ([string]$Id = "V-220707")
    
    Write-Log "Checking Windows Defender status..." "INFO"
    
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if ($defenderStatus.RealTimeProtectionEnabled) {
            Add-Result -Id $Id -Message "Windows Defender real-time protection enabled" -Status "Success"
        } else {
            try {
                Set-MpPreference -DisableRealtimeMonitoring $false
                Add-Result -Id $Id -Message "Windows Defender real-time protection enabled" -Status "Success"
            } catch {
                Add-Result -Id $Id -Message "Failed to enable Windows Defender" -Status "Fail"
            }
        }
        
    } catch {
        Add-Result -Id $Id -Message "Failed to check Windows Defender: $_" -Status "Fail"
    }
}

function Test-FileSystemCompliance {
    param ([string]$Id = "V-220708")
    
    Write-Log "Checking file system compliance..." "INFO"
    
    try {
        $systemVolume = Get-Volume -DriveLetter C -ErrorAction Stop
        
        if ($systemVolume.FileSystem -eq "NTFS") {
            Add-Result -Id $Id -Message "System volume formatted with NTFS" -Status "Success"
        } else {
            Add-Result -Id $Id -Message "System volume not formatted with NTFS" -Status "Fail"
        }
        
    } catch {
        Add-Result -Id $Id -Message "Failed to check file system: $_" -Status "Fail"
    }
}

function Disable-InactiveBluetooth {
    param ([string]$Id = "V-220735")

    Write-Log "Disabling bluetooth if no active devices connected...."

    try {
        $btAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Bluetooth" -and $_.Status -eq "Up" }
        if ($btAdapters.Count -eq 0) {
            Add-Result -Id $Id -Message "No active Bluetooth adapters found." -Status "Success"
            return
        }

        $connectedDevices = Get-PnpDevice -Class Bluetooth | Where-Object { $_.Status -eq "OK" }
        if ($connectedDevices.Count -eq 0) {
            foreach ($adapter in $btAdapters) {
                Disable-NetAdapter -Name $adapter.Name -Confirm:$false
            }
            Add-Result -Id $Id -Message "Bluetooth radios disabled due to no connected devices." -Status "Success"
        } else {
            Add-Result -Id $Id -Message "Bluetooth active with connected devices, no change made." -Status "Success"
        }
    }
    catch {
        Add-Result -Id $Id -Message "Error disabling Bluetooth when idle: $_" -Status "Fail"
    }
}

function Set-EventLogSizes {
    param ([string[]]$Id = @("V-220781","V-220780","V-220779"))

    try {
        $results = @()

        $logsToCheck = @(
            @{Name="System"; MinSizeKB=32768; Id=$Id[0]},
            @{Name="Security"; MinSizeKB=1024000; Id=$Id[1]},
            @{Name="Application"; MinSizeKB=32768; Id=$Id[2]}
        )

        foreach ($log in $logsToCheck) {
            $el = Get-WinEvent -ListLog $log.Name -ErrorAction Stop
            if ($el.MaximumSizeInBytes -lt ($log.MinSizeKB * 1024)) {
                try {
                    wevtutil sl $log.Name /ms:$($log.MinSizeKB * 1024)
                    $results += @{Id=$log.Id; Message="$($log.Name) event log size increased to $($log.MinSizeKB) KB."; Status="Success"}
                } catch {
                    $results += @{Id=$log.Id; Message="Failed to set $($log.Name) event log size: $_"; Status="Fail"}
                }
            } else {
                $results += @{Id=$log.Id; Message="$($log.Name) event log size is compliant."; Status="Success"}
            }
        }

        foreach ($res in $results) {
            Add-Result -Id $res.Id -Message $res.Message -Status $res.Status
        }
    } catch {
        foreach ($id in $Id) {
            Add-Result -Id $id -Message "Exception occurred during event log size check: $_" -Status "Fail"
        }
    }
}

function Remove-OrphanedUserRights {
    param (
        [string]$CfgPath = "C:\Temp\SecurityConfig.inf",
        [string]$Id = "V-220733"
    )

    try {
        $content = Get-Content $CfgPath -Raw
        $lines = $content -split "`r?`n"
        $inUserRights = $false
        $userRightsLines = @()
        $otherLines = @()

        foreach ($line in $lines) {
            if ($line -match "^\[User Rights Assignment\]") { $inUserRights = $true; continue }
            if ($inUserRights) {
                if ($line -match "^\[.*\]") { $inUserRights = $false }
                elseif ($line -match "=") { $userRightsLines += $line; continue }
            }
            if (-not $inUserRights) { $otherLines += $line }
        }

        $rights = @{}
        $orphanedSids = @()

        foreach ($line in $userRightsLines) {
            $parts = $line -split "=", 2
            $priv = $parts[0].Trim()
            $sidsRaw = $parts[1].Trim()
            if ($sidsRaw) {
                $sids = $sidsRaw -split ","
                $validSids = foreach ($sid in $sids) {
                    try {
                        (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]) | Out-Null
                        $sid
                    } catch { $orphanedSids += $sid }
                }
                $rights[$priv] = $validSids
            }
        }

        $newContent = $otherLines + '[User Rights Assignment]'
        foreach ($priv in $rights.Keys) {
            $newContent += "$priv = $($rights[$priv] -join ',')"
        }

        $tempFile = [IO.Path]::Combine([IO.Path]::GetTempPath(), "CleanedSecConfig.inf")
        $newContent | Set-Content -Path $tempFile -Encoding Unicode

        secedit /configure /db secedit.sdb /cfg $tempFile /areas USER_RIGHTS /quiet

        Remove-Item $tempFile -ErrorAction SilentlyContinue

        if ($orphanedSids.Count -eq 0) {
            Add-Result -Id $Id -Message "No orphaned SIDs found in user rights assignments." -Status "Success"
        } else {
            Add-Result -Id $Id -Message "Removed orphaned SIDs: $($orphanedSids -join ', ')" -Status "Non-Compliant"
        }
    }
    catch {
        Write-Log "Failed to remove orphaned SIDs: $_" "ERROR"
        Add-Result -Id $Id -Message "Error removing orphaned SIDs: $_" -Status "Fail"
    }
}

function Test-UEFIBootMode {
    param ([string]$Id = "V-220699")

    Write-Log "Checking UEFI boot mode..." "INFO"

    try {
        $bootMode = $null
        $firmwareType = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -ErrorAction SilentlyContinue).PEFirmwareType
        if ($firmwareType -eq 2) { $bootMode = "UEFI" }
        elseif ($firmwareType -eq 1) { $bootMode = "Legacy" }

        if (-not $bootMode) {
            $bcd = bcdedit | Where-Object { $_ -match "path" }
            if ($bcd -match "winload\.efi") { $bootMode = "UEFI" }
            elseif ($bcd -match "winload\.exe") { $bootMode = "Legacy" }
        }

        if ($bootMode -eq "UEFI") {
            Add-Result -Id $Id -Message "System is booted in UEFI mode." -Status "Success"
        } elseif ($bootMode -eq "Legacy") {
            Add-Result -Id $Id -Message "System is booted in Legacy BIOS mode. Manual remediation required." -Status "Fail"
        } else {
            Add-Result -Id $Id -Message "Unable to determine boot mode via registry or BCD." -Status "Fail"
        }
    }
    catch {
        Write-Log "Error checking UEFI boot mode: $_" "ERROR"
        Add-Result -Id $Id -Message "Exception occurred: $_" -Status "Fail"
    }
}

function Test-KernelDMAProtection {
    param ([string]$Id = "V-220902")

    Write-Log "Checking Kernel DMA Protection..." "INFO"

    try {
        $deviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
        $dmaStatus = $deviceGuard.DmaProtection

        switch ($dmaStatus) {
            2 {
                Add-Result -Id $Id -Message "Kernel DMA Protection is enabled." -Status "Success"
            }
            1 {
                Write-Log "Kernel DMA Protection disabled. Attempting remediation..." "WARN"

                $secureBoot = Get-CimInstance -Namespace root\dcim\sysman -ClassName DCIM_SecureBoot -ErrorAction Stop
                $virtualization = Get-CimInstance -Namespace root\dcim\sysman -ClassName DCIM_Virtualization -ErrorAction Stop

                $retSecureBoot = $secureBoot.SetSecureBootEnabled($true)
                $retVTd = $virtualization.SetVTdEnabled($true)

                if ($retSecureBoot.ReturnValue -eq 0 -and $retVTd.ReturnValue -eq 0) {
                    Add-Result -Id $Id -Message "Enabled Kernel DMA Protection settings via WMI. Reboot required." -Status "Fail"
                } else {
                    Add-Result -Id $Id -Message "Failed to enable Kernel DMA Protection settings via WMI. Return codes: SecureBoot=$($retSecureBoot.ReturnValue), VTd=$($retVTd.ReturnValue)" -Status "Fail"
                }
            }
            0 {
                Add-Result -Id $Id -Message "Kernel DMA Protection not supported on this device." -Status "Fail"
            }
            default {
                Add-Result -Id $Id -Message "Unknown Kernel DMA Protection state: $dmaStatus" -Status "Fail"
            }
        }
    } catch {
        Write-Log "Failed to check or remediate Kernel DMA Protection: $_" "ERROR"
        Add-Result -Id $Id -Message "Exception occurred while checking or remediating Kernel DMA Protection: $_" -Status "Fail"
    }
}

function Invoke-LocalAdminPasswordExpiration {
    param (
        [int]$MaxPasswordAgeDays = 60,
        [string]$Id = "V-220952"
    )

    Write-Log "Scanning local Administrators group for password expiration enforcement..." "INFO"

    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Where-Object { $_.ObjectClass -eq 'User' }

        foreach ($admin in $admins) {
            $user = Get-LocalUser -Name $admin.Name -ErrorAction SilentlyContinue
            if (-not $user) {
                Write-Log "User $($admin.Name) not found, skipping." "WARN"
                continue
            }
            if (-not $user.Enabled) {
                Write-Log "User $($admin.Name) is disabled, skipping." "INFO"
                continue
            }

            $lastSet = $user.PasswordLastSet
            if (-not $lastSet) {
                Write-Log "Could not get PasswordLastSet for $($admin.Name), skipping." "WARN"
                continue
            }

            $age = (Get-Date) - $lastSet
            if ($age.TotalDays -gt $MaxPasswordAgeDays) {
                Write-Log "Password for $($admin.Name) is older than $MaxPasswordAgeDays days ($([math]::Round($age.TotalDays,1))) - expiring password." "WARN"
                $adsUser = [ADSI]"WinNT://$env:COMPUTERNAME/$($admin.Name),user"
                $adsUser.PasswordExpired = $true
                $adsUser.SetInfo()
                Add-Result -Id $Id -Message "Password for local admin account '$($admin.Name)' expired to enforce reset." -Status "Fail"
            } else {
                Add-Result -Id $Id -Message "Password for local admin account '$($admin.Name)' is within allowed age." -Status "Success"
            }
        }
    } catch {
        Write-Log "Error enforcing password expiration on local admins: $_" "ERROR"
        Add-Result -Id $Id -Message "Exception during password expiration enforcement: $_" -Status "Fail"
    }
}

function Test-EventLogPermissions {
    param (
        [string[]]$Ids = @("V-220784", "V-220783", "V-220782")
    )

    Write-Log "Checking event log permissions for System, Security, and Application logs..." "INFO"

    try {
        $allowedIdentities = @(
            "BUILTIN\Administrators",
            "NT AUTHORITY\SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE"
        )

        $logs = @(
            @{Name='System';      Id=$Ids[0]},
            @{Name='Security';    Id=$Ids[1]},
            @{Name='Application'; Id=$Ids[2]}
        )

        foreach ($log in $logs) {
            $logName = $log.Name
            $id = $log.Id

            $acl = Get-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName"
            $unauthorized = @()

            foreach ($ace in $acl.Access) {
                $identity = $ace.IdentityReference.Value
                if ($ace.FileSystemRights -match "Read|FullControl|Write") {
                    $matched = $false
                    foreach ($allowed in $allowedIdentities) {
                        if ($identity.ToLower() -eq $allowed.ToLower()) {
                            $matched = $true
                            break
                        }
                    }
                    if (-not $matched) {
                        $unauthorized += $ace
                    }
                }
            }

            if ($unauthorized.Count -gt 0) {
                $badUsers = $unauthorized | ForEach-Object { $_.IdentityReference.Value }
                Add-Result -Id $id -Message "$logName event log has permissions granted to non-privileged accounts: $($badUsers -join ', ')" -Status "Fail"
                foreach ($entry in $unauthorized) {
                    $acl.RemoveAccessRuleSpecific($entry)
                }
                Set-Acl -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName" -AclObject $acl
                Write-Log "Removed unauthorized permissions from $logName event log." "INFO"
            } else {
                Add-Result -Id $id -Message "$logName event log permissions are properly restricted." -Status "Success"
            }
        }
    } catch {
        Write-Log "Failed to check or remediate event log permissions: $_" "ERROR"
        Add-Result -Id "V-220782-784" -Message "Exception occurred while checking event log permissions: $_" -Status "Fail"
    }
}

function Set-STIGsNotApplicable {
    param (
        [string[]]$StigIDs
    )

    foreach ($id in $StigIDs) {
        $global:STIGCompliance[$id] = "NOT APPLICABLE"
    }
}

function Set-AuthorizedVMUsers {
    param([string]$Id = "V-220714")
    try {
        $hyperVGroup = Get-LocalGroup -Name "Hyper-V Administrators" -ErrorAction SilentlyContinue
        if (-not $hyperVGroup) {
            Add-Result -Id $Id -Message "'Hyper-V Administrators' group does not exist. Cannot enforce VM permissions." -Status "Fail"
            return
        }
        $vmUsersGroup = Get-LocalGroup -Name "VirtualMachineUsers" -ErrorAction SilentlyContinue
        if (-not $vmUsersGroup) {
            New-LocalGroup -Name "VirtualMachineUsers" -Description "Authorized to run virtual machines" -ErrorAction Stop
            Add-Result -Id $Id -Message "'VirtualMachineUsers' group did not exist and was created with no members." -Status "Info"
        }
        $vmAuthGroups = Get-LocalGroupMember -Group "Hyper-V Administrators" -ErrorAction Stop | Select-Object -ExpandProperty Name
        foreach ($member in $vmAuthGroups) {
            if ($member -notlike "*Administrators" -and $member -notlike "*VirtualMachineUsers") {
                Remove-LocalGroupMember -Group "Hyper-V Administrators" -Member $member -ErrorAction Stop
            }
        }
        $isMember = $vmAuthGroups | Where-Object { $_ -match "\\VirtualMachineUsers$" }
        if (-not $isMember) {
            Add-LocalGroupMember -Group "Hyper-V Administrators" -Member "VirtualMachineUsers" -ErrorAction Stop
        }
        Add-Result -Id $Id -Message "VM user permissions configured successfully." -Status "Success"
    }
    catch {
        $errorDetails = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($errorDetails)) {
            $errorDetails = $_ | Out-String
        }
        Add-Result -Id $Id -Message "Error enforcing VM user permissions: $errorDetails" -Status "Fail"
    }
}

function Test-WindowsDefenderFirewall {
    param ([string]$Id = "V-220724")
    
    Write-Log "Checking Windows Defender Firewall status..." "INFO"
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        
        $allEnabled = $true
        foreach ($profile in $profiles) {
            if (-not $profile.Enabled) {
                $allEnabled = $false
                break
            }
        }
        
        if ($allEnabled) {
            Add-Result -Id $Id -Message "Windows Defender Firewall is enabled for all profiles" -Status "Success"
        } else {
            try {
                foreach ($profile in $profiles) {
                    if (-not $profile.Enabled) {
                        Set-NetFirewallProfile -Name $profile.Name -Enabled True -ErrorAction Stop
                    }
                }
                Add-Result -Id $Id -Message "Windows Defender Firewall enabled for all profiles" -Status "Success"
            } catch {
                Add-Result -Id $Id -Message "Failed to enable Windows Defender Firewall: $_" -Status "Fail"
            }
        }
    } catch {
        Add-Result -Id $Id -Message "Failed to check Windows Defender Firewall: $_" -Status "Fail"
    }
}

function Test-AlternateOperatingSystems {
    param([string]$Id = "V-220709")

    try {
        $drives = Get-PSDrive -PSProvider FileSystem
        if (-not $drives) {
            Add-Result -Id $Id -Message "No filesystem drives detected." -Status "Fail"
            return
        }

        $nonWindowsFS = $false
        $windowsFSCount = 0

        foreach ($drive in $drives) {
            if ([string]::IsNullOrEmpty($drive.FileSystem)) {
                # Skip drives without filesystem info
                continue
            }

            switch ($drive.FileSystem.ToUpper()) {
                "NTFS" { $windowsFSCount++ }
                "REFS" { $windowsFSCount++ }
                default {
                    $nonWindowsFS = $true
                    Write-Host "Non-Windows filesystem detected: $($drive.FileSystem) on drive $($drive.Name)" -ForegroundColor Red
                }
            }
        }

        if ($nonWindowsFS) {
            Add-Result -Id $Id -Message "Non-Windows file system detected; alternate OS presence suspected." -Status "Fail"
        }
        else {
            if ($windowsFSCount -gt 1) {
                Add-Result -Id $Id -Message "Multiple Windows file systems detected. [WARN] Possible dual Windows OS installation." -Status "Success"
            }
            else {
                Add-Result -Id $Id -Message "Single Windows file system detected; no alternate OS detected." -Status "Success"
            }
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ([string]::IsNullOrEmpty($errMsg)) {
            $errMsg = $_ | Out-String
        }
        Add-Result -Id $Id -Message "Failed to check file systems: $errMsg" -Status "Fail"
    }
}

function Test-NonSystemFileShares {
    param([string]$Id = "V-220710")

    $systemShares = @('C$', 'ADMIN$', 'IPC$', 'PRINT$')

    Write-Log "Applying security policy baseline..." "INFO"

    try {
        $shares = Get-SmbShare | Where-Object { $systemShares -notcontains $_.Name }
        if (-not $shares) {
            Add-Result -Id $Id -Message "No non-system shares found." -Status "Success"
        }
        else {
            $violations = @()
            foreach ($share in $shares) {
                $accessEntries = Get-SmbShareAccess -Name $share.Name
                foreach ($entry in $accessEntries) {
                    if ($entry.AccountName -in @('Everyone', 'Authenticated Users')) {
                        try {
                            Revoke-SmbShareAccess -Name $share.Name -AccountName $entry.AccountName -Force
                            $violations += "Removed '$($entry.AccountName)' from share '$($share.Name)'."
                        } catch {
                            $violations += "Failed to remove '$($entry.AccountName)' from share '$($share.Name)': $_"
                        }
                    }
                }
            }

            if ($violations.Count -gt 0) {
                $msg = "Non-system shares remediated or checked:`n" + ($violations -join "`n")
                Add-Result -Id $Id -Message $msg -Status "Success"
            } else {
                Add-Result -Id $Id -Message "All non-system shares already had appropriate access permissions." -Status "Success"
            }
        }
    }
    catch {
        Add-Result -Id $Id -Message "Error checking or remediating non-system shares: $_" -Status "Fail"
    }

    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] Permissions remediation process completed"
}

function Test-SystemFilePermissions {
    param([string]$Id = "V-220717")

    Write-Log "Applying security policy baseline..." "INFO"

    $systemPaths = @(
        "$env:SystemRoot",
        "$env:SystemRoot\System32",
        "$env:SystemRoot\System32\drivers",
        "$env:SystemRoot\System32\config",
        "$env:ProgramFiles",
        "$env:ProgramFiles (x86)"
    )

    $violations = @()

    try {
        foreach ($path in $systemPaths) {
            if (-not (Test-Path $path)) {
                $violations += "Path not found: ${path}"
                continue
            }
            try {
                $icaclsCmd = "icacls `"$path`" /inheritance:e /grant:r `"SYSTEM:(OI)(CI)F`" `"Administrators:(OI)(CI)F`" `"Users:(OI)(CI)RX`" /C"
                cmd.exe /c $icaclsCmd | Out-Null
                $violations += "Permissions set on root of ${path} with inheritance enabled"
            }
            catch {
                $violations += "Failed to apply permissions on ${path}: $($_.Exception.Message)"
            }
        }

        if ($violations.Count -gt 0) {
            $msg = "System file and folder permissions remediated or checked:`n" + ($violations -join "`n")
            Add-Result -Id $Id -Message $msg -Status "Success"
        }
        else {
            Add-Result -Id $Id -Message "All system file and folder permissions already correct." -Status "Success"
        }
    }
    catch {
        Add-Result -Id $Id -Message "Error checking or remediating system file permissions: $($_.Exception.Message)" -Status "Fail"
    }

    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] File permission remediation process completed"
}

#END-REGION

#STIG FINAL COMPLIANCE REPORT
function Show-STIGComplianceReport {
    Write-Host ""
    Write-Host "################################################################################" -ForegroundColor Cyan
    Write-Host "#                          STIG COMPLIANCE REPORT                             #" -ForegroundColor Cyan
    Write-Host "################################################################################" -ForegroundColor Cyan
    Write-Host ""
    
    $compliantCount = 0
    $nonCompliantCount = 0
    $notCheckedCount = 0
    
    $sortedSTIGs = $script:STIGRequirements.GetEnumerator() | Sort-Object Name
    
    foreach ($stig in $sortedSTIGs) {
        $stigId = $stig.Key
        $description = $stig.Value
        
        $status = if ($global:STIGCompliance.ContainsKey($stigId)) {
            $global:STIGCompliance[$stigId]
        } else {
            "NOT CHECKED"
        }
        
        $color = switch ($status) {
            "IN COMPLIANCE" { "Green"; $compliantCount++ }
            "NON-COMPLIANT" { "Red"; $nonCompliantCount++ }
            "NOT APPLICABLE" { "Yellow"; $NAcompliantCount++ }
            default { "Gray"; $notCheckedCount++ }
        }
        
        $symbol = switch ($status) {
            "IN COMPLIANCE" { "[OK]" }
            "NON-COMPLIANT" { "[NO]" }
            "NOT APPLICABLE" { "[N/A]" }
            default { "[?]" }
        }
        
        $statusLine = "{0,-12} {1,-15} {2}" -f $stigId, $symbol, $description
        Write-Host $statusLine -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host "################################################################################" -ForegroundColor Cyan
    Write-Host "#                            COMPLIANCE SUMMARY                               #" -ForegroundColor Cyan
    Write-Host "################################################################################" -ForegroundColor Cyan
    Write-Host ""
    
    $totalSTIGs = $script:STIGRequirements.Count
    $compliancePercentage = if ($totalSTIGs -gt 0) { [math]::Round(($compliantCount / $totalSTIGs) * 100, 2) } else { 0 }
    
    Write-Host "Total STIG Requirements: $totalSTIGs" -ForegroundColor White
    Write-Host "In Compliance: $compliantCount" -ForegroundColor Green
    Write-Host "Non-Compliant: $nonCompliantCount" -ForegroundColor Red
    Write-Host "Not Checked: $notCheckedCount" -ForegroundColor Gray
    Write-Host "Not Applicable: $NAcompliantCount" -ForegroundColor Yellow
    Write-Host "Compliance Percentage: $compliancePercentage%" -ForegroundColor $(if ($compliancePercentage -ge 90) { "Green" } elseif ($compliancePercentage -ge 70) { "Yellow" } else { "Red" })
    Write-Host ""
    
    try {
        $reportData = @()
        foreach ($stig in $sortedSTIGs) {
            $status = if ($global:STIGCompliance.ContainsKey($stig.Key)) { $global:STIGCompliance[$stig.Key] } else { "NOT CHECKED" }
            $reportData += [PSCustomObject]@{
                STIG_ID = $stig.Key
                Status = $status
                Description = $stig.Value
                Timestamp = Get-Date
            }
        }
        
        $reportData | Export-Csv -Path $script:Config.ReportPath -NoTypeInformation
        Write-Host "Report exported to: $($script:Config.ReportPath)" -ForegroundColor Yellow
    } catch {
        Write-Log "Failed to export report: $_" "ERROR"
    }
}
#END-REGION

#STIG REMEDIATION FUNCTION
function Start-STIGRemediation {
    Write-Log "Starting STIG remediation process..." "INFO"
    
    $registrySettings = @(

        ##HKLM
        @{ ID = "V-257589"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'; Name = "DisableIE"; Value = 1 },
        @{ ID = "V-220854"; Path = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'; Name = "AllowBasicAuthInClear"; Value = 0 },
        @{ ID = "V-220853"; Path = 'HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds'; Name = "DisableAttachmentsInFeeds"; Value = 1 },
        @{ ID = "V-220805"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'; Name = "EccCurves"; Value = "NistP384,NistP256" },
        @{ ID = "V-256894"; Path = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_IE11'; Name = "iexplore.exe"; Value = 1 },
        @{ ID = "V-220845"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name = "AllowGameDVR"; Value = 0 },
        @{ ID = "V-220844"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'; Name = "Enabled"; Value = 1 },
        @{ ID = "V-220841"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'; Name = "PreventOverride"; Value = 1 },
        @{ ID = "V-220840"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter'; Name = "PreventOverrideAllow"; Value = 1 },
        @{ ID = "V-220843"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PasswordManagerEnabled'; Name = "PasswordManagerEnabled"; Value = 0 },
        @{ ID = "V-220842"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SSL'; Name = "ErrorOverrideAllowed"; Value = 0 },
        @{ ID = "V-220833"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = "AllowTelemetry"; Value = 2 },
        @{ ID = "V-220834"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = "AllowTelemetry"; Value = 2 },
        @{ ID = "V-220819"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = "DontDisplayNetworkSelectionUI"; Value = 1 },
        @{ ID = "V-220869"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Name = "AllowVoiceActivationOnLockScreen"; Value = 0 },
        @{ ID = "V-220830"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\FaceRecognition'; Name = "EnhancedAntiSpoofing"; Value = 1 },
        @{ ID = "V-220822"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Power'; Name = "PromptPasswordOnResume"; Value = 1 },
        @{ ID = "V-220821"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\Power'; Name = "PromptPasswordOnResumeOnBattery"; Value = 1 },
        @{ ID = "V-220868"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = "AllowDigest"; Value = 0 },
        @{ ID = "V-220863"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name = "AllowUnencryptedTraffic"; Value = 0 },
        @{ ID = "V-220867"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = "DisableRunAs"; Value = 1 },
        @{ ID = "V-220866"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name = "AllowUnencryptedTraffic"; Value = 0 },
        @{ ID = "V-220860"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = "EnableScriptBlockLogging"; Value = 1 },
        @{ ID = "V-252896"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = "EnableTranscripting"; Value = 1 },
        @{ ID = "V-220856"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'; Name = "EnableUserControl"; Value = 0 },
        @{ ID = "V-220855"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\Windows Search'; Name = "AllowIndexingEncryptedStoresOrItems"; Value = 0 },
        @{ ID = "V-220816"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name = "NoWebServices"; Value = 1 },
        @{ ID = "V-220817"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = "DisableHTTPPrinting"; Value = 1 },
        @{ ID = "V-220815"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name = "DisableWebPnPDownload"; Value = 1 },
        @{ ID = "V-220849"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = "fDisableCdm"; Value = 1 },
        @{ ID = "V-220848"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = "DisablePasswordSaving"; Value = 1 },
        @{ ID = "V-220738"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = "MaxDisconnectionTime"; Value = 86400000 },
        @{ ID = "V-220738"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = "MaxIdleTime"; Value = 86400000 },
        @{ ID = "V-220738"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name = "MaxConnectionTime"; Value = 86400000 },
        @{ ID = "V-220794"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name = "NoLockScreenSlideshow"; Value = 1 },
        @{ ID = "V-220736"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Bluetooth'; Name = "AllowPromptedConnections"; Value = 1 },
        @{ ID = "V-268315"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Name = "TurnOffWindowsCopilot"; Value = 1 },
        @{ ID = "V-220921"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "LegalNoticeCaption"; Value = "***YARINET SECURITY SYSTEMS***" },
        @{ ID = "V-220921"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "LegalNoticeText"; Value = "Unauthorized access to this system is prohibited, proceed with caution. Press ENTER to continue." },
        @{ ID = "V-220955"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name = "SaveZoneInformation"; Value = 1 },
        @{ ID = "V-220858"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name = "NotifyAntivirus"; Value = 1 },
        @{ ID = "V-220951"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "EnableVirtualization"; Value = 1 },
        @{ ID = "V-220950"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "EnableLUA"; Value = 1 },
        @{ ID = "V-220949"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "ValidateAdminCodeSignatures"; Value = 1 },
        @{ ID = "V-220948"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "ConsentPromptBehaviorAdmin"; Value = 1 },
        @{ ID = "V-220945"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "ConsentPromptBehaviorAdmin"; Value = 2 },
        @{ ID = "V-220947"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "ConsentPromptBehaviorUser"; Value = 0 },
        @{ ID = "V-220944"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "FilterAdministratorToken"; Value = 1 },
        @{ ID = "V-220924"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "ScRemoveOption"; Value = 1 },
        @{ ID = "V-220859"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "DisableAutomaticRestartSignOn"; Value = 1 },
        @{ ID = "V-220839"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions'; Name = "EnableProtectedMode"; Value = 1 },
        @{ ID = "V-220836"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; Name = "SmartScreenEnabled"; Value = "RequireAdmin" },
        @{ ID = "V-220801"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = "HideRunAsVerb"; Value = 1 },
        @{ ID = "V-220792"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'; Name = "Value"; Value = "Deny" },
        @{ ID = "V-220808"; Path = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; Name = "AutoConnectAllowedOEM"; Value = 0 },
        @{ ID = "V-220728"; Path = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'; Name = "EnablePowerShell2"; Value = 0 },
        @{ ID = "V-220809"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = "ProcessCreationIncludeCmdLine_Enabled"; Value = 1 },
        @{ ID = "V-220832"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name = "EnumerateAdministrators"; Value = 0 },
        @{ ID = "V-220942"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'; Name = "Enabled"; Value = 1 },
        @{ ID = "V-220941"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = "NTLMMinClientSec"; Value = 537395200 },
        @{ ID = "V-220940"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = "NTLMMinClientSec"; Value = 537395200 },
        @{ ID = "V-220936"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'; Name = "SupportedEncryptionTypes"; Value = 2147483647 },
        @{ ID = "V-220934"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = "RestrictNullSessAccess"; Value = 1 },
        @{ ID = "V-220926"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = "RequireSecuritySignature"; Value = 1 },
        @{ ID = "V-220925"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name = "RequireSecuritySignature"; Value = 1 },
        @{ ID = "V-220902"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'; Name = "EnableKernelDmaProtection"; Value = 1 },
        @{ ID = "V-220852"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = "MinEncryptionLevel"; Value = 3 },
        @{ ID = "V-220851"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = "SecurityLayer"; Value = 1 },
        @{ ID = "V-220850"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name = "fPromptForPassword"; Value = 1 },
        @{ ID = "V-220837"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = "MoveImages"; Value = 1 },
        @{ ID = "V-220746"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "PasswordComplexity"; Value = 1 },
        @{ ID = "V-220745"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "MinimumPasswordLength"; Value = 14 },
        @{ ID = "V-220744"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = "MinimumPasswordAge"; Value = 1 },
        @{ ID = "V-220743"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "MaximumPasswordAge"; Value = 60 },
        @{ ID = "V-220952"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "MaximumPasswordAge"; Value = 60},
        @{ ID = "V-220742"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "PasswordHistorySize"; Value = 24 },
        @{ ID = "V-220741"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = "ResetCount"; Value = 15 },
        @{ ID = "V-220740"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = "LockoutBadCount"; Value = 3 },
        @{ ID = "V-220739"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = "LockoutDuration"; Value = 15 },
        @{ ID = "V-220732"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\seclogon'; Name = "Start"; Value = 4 },
        @{ ID = "V-220731"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = "Start"; Value = 4 },
        @{ ID = "V-220716"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "DisablePasswordChange"; Value = 0 },
        @{ ID = "V-220803"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess'; Name = "Start"; Value = 4 },
        @{ ID = "V-220800"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name = "UseLogonCredential"; Value = 0 },
        @{ ID = "V-220810"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "AllowProtectedCreds"; Value = 1 },
        @{ ID = "V-220910"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "LimitBlankPasswordUse"; Value = 1 },
        @{ ID = "V-220813"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'; Name = "DriverLoadPolicy"; Value = 3 },
        @{ ID = "V-220811"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'; Name = "EnableVirtualizationBasedSecurity"; Value = 1 },
        @{ ID = "V-220811"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'; Name = "RequirePlatformSecurityFeatures"; Value = 1 }, 
        @{ ID = "V-220796"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name = "DisableIPSourceRouting"; Value = 2 },
        @{ ID = "V-220795"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name = "DisableIPSourceRouting"; Value = 2 },
        @{ ID = "V-220729"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name = "Start"; Value = 4 },
        @{ ID = "V-220920"; Path = 'HKCU:\Control Panel\Desktop'; Name = "ScreenSaveTimeOut"; Value = "900" },
        @{ ID = "V-220920"; Path = 'HKCU:\Control Panel\Desktop'; Name = "ScreenSaverIsSecure"; Value = "1" },
        @{ ID = "V-220747"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Name = "ClearTextPassword"; Value = 0 },
        @{ ID = "V-220871"; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name = "AllowWindowsInkWorkspace"; Value = 0 },
        @{ ID = "V-220943"; Path = 'HKLM:\System\CurrentControlSet\Control\Session Manager'; Name = "ProtectionMode"; Value = 1 },
        @{ ID = "V-220831"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'; Name = "DisableConsumerFeatures"; Value = 1 },
        @{ ID = "V-220825"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\Appx'; Name = "AllowMicrosoftAccountAppsSignIn"; Value = 1 }, 
        @{ ID = "V-220835"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization'; Name = "DoDownloadMode"; Value = 0 }, 
        @{ ID = "V-220826"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\AppCompat'; Name = "DisableInventory"; Value = 1 },
        @{ ID = "V-220923"; Path = 'HKLM:\Software\Policies\Microsoft\Windows NT\CurrentVersion\WinLogon'; Name = "CachedLogonsCount"; Value = 4; ValueType = "String" },
        @{ ID = "V-220918"; Path = 'HKLM:\System\Current\ControlSet\Services\Netlogon\Parameters'; Name = "MaximumPasswordAge"; Value = 30; },
        @{ ID = "V-220798"; Path = 'HKLM:\System\Current\ControlSet\Services\NetBT\Parameters'; Name = "NoNameReleaseOnDemand"; Value = 1; },
        @{ ID = "V-220797"; Path = 'HKLM:\System\Current\ControlSet\Services\Tcpip\Parameters'; Name = "EnableICMPRedirect"; Value = 0; },
        @{ ID = "V-220954"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\System'; Name = "DisableLockScreenAppNotifications"; Value = 1; },
        @{ ID = "V-220838"; Path = 'HKLM:\Software\Microsoft\Windows NT\Current Version\Image File Execution Options'; Name = "DisableHeapTerminationCorruption"; Value = 1; },
        @{ ID = "V-220872"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'; Name = "DisableSoftLanding"; Value = 1; },
        @{ ID = "V-220872"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'; Name = "DisableWindowsSpotlightFeatures"; Value = 1; },
        @{ ID = "V-220872"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'; Name = "DisableTailoredExperiencesWithDiagnosticData"; Value = 1; },
        @{ ID = "V-252903"; Path = 'HKLM:\System\CurrentControlSet\Control\DeviceGuard'; Name = "EnableVirtualizationbasedSecurity"; Value = 1; },
        @{ ID = "V-252903"; Path = 'HKLM:\System\CurrentControlSet\Control\DeviceGuard'; Name = "RequirePlatformSecurityFeatures"; Value = 1; },
        @{ ID = "V-252903"; Path = 'HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'; Name = "Enabled"; Value = 1; },
        @{ ID = "V-252903"; Path = 'HKLM:\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'; Name = "Locked"; Value = 1; },
        @{ ID = "V-220917"; Path = 'HKLM:\System\CurrentControlSet\Services\NetLogon\Parameters'; Name = "DisablePasswordChange"; Value = 1; },
        @{ ID = "V-220922"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "DisableCAD"; Value = 0; },
        @{ ID = "V-220829"; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = "NoAutoPlay"; Value = 1 },
        @{ ID = "V-220827"; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = "NoAutoPlayfornonVolume"; Value = 1 },
        @{ ID = "V-220828"; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = "NoDriveTypeAutoRun"; Value = 255 },
        @{ ID = "V-220823"; Path = 'HKLM:\System\CurrentControlSet\Control\Remote Assistance'; Name = "fAllowToGetHelp"; Value = 0 },
        @{ ID = "V-220727"; Path = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Kernel'; Name = "DisableExceptionChainValidation"; Value = 0 },
        @{ ID = "V-220857"; Path = 'HKLM:\Software\Policies\Microsoft\Windows\Installer'; Name = "AlwaysInstallElevated"; Value = 0 },
        @{ ID = "V-220862"; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\WSMAN\Client\Auth'; Name = "Basic"; Value = 0 },
        @{ ID = "V-220865"; Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\WSMAN\Service\Auth'; Name = "Basic"; Value = 0 },
        @{ ID = "V-220916"; Path = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = "SignSecureChannel"; Value = 1 },
        @{ ID = "V-220915"; Path = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = "SealSecureChannel"; Value = 1 },
        @{ ID = "V-220914"; Path = 'HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters'; Name = "RequireSignOrSeal"; Value = 1 },
        @{ ID = "V-257593"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4'; Name = ""; Value = "" },
        @{ ID = "V-257593"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov6'; Name = ""; Value = "" },
        @{ ID = "V-257593"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v6tov4'; Name = ""; Value = "" },
        @{ ID = "V-257593"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\PortProxy\v6tov6'; Name = ""; Value = "" },
        @{ ID = "V-257593"; Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\iphlpsvc'; Name = "Start"; Value = 4 },
        @{ ID = "V-220921"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "LegalNoticeCaption"; Value = "***YARINET SECURITY SYSTEMS***" },
        @{ ID = "V-220922"; Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = "LegalNoticeText"; Value = "Unauthorized access to this system is prohibited, proceed with caution. Press ENTER to continue." }

    )
    
    foreach ($setting in $registrySettings) {
        Set-RegistryValue -Id $setting.ID -Path $setting.Path -Name $setting.Name -Value $setting.Value
    }
    
    #FUNCTION CALLS
    Disable-InactiveBluetooth
    Invoke-SecurityPolicyBaseline
    Invoke-AuditPolicyBaseline
    Invoke-LocalAdminPasswordExpiration
    Remove-UnauthorizedScheduledTasks
    Remove-UnauthorizedAdministrators
    Remove-UnauthorizedAccountsAndServices
    Remove-LocalAccounts
    Remove-IISFeatures
    Remove-AgedAccounts
    Remove-TFTPClient
    Remove-TelnetClient
    Remove-TCPIPServices
    Remove-SNMPProtocol
    Remove-OrphanedUserRights
    Set-EventLogSizes 
    Set-AuthorizedVMUsers
    Set-STIGsNotApplicable -StigIDs @(
        "V-220737",
        "V-220701",
        "V-220697",
        "V-220698",
        "V-220723",
        "V-220725",
        "V-220730",
        "V-220734",
        "V-220793",
        "V-220799",
        "V-220802",
        "V-220806",
        "V-220807",
        "V-220814",
        "V-220818",
        "V-220820",
        "V-220824",
        "V-220846",
        "V-220870",
        "V-220903",
        "V-220904",
        "V-220905",
        "V-220906",
        "V-220919",
        "V-220927",
        "V-220933",
        "V-220935",
        "V-220939",
        "V-220941",
        "V-220946",
        "V-220968",
        "V-220969",
        "V-220970",
        "V-220971",
        "V-220972",
        "V-250319",
        "V-268319",
        "V-220703",
        "V-220704",
        "V-220812",
        "V-220847",
        "V-220705",
        "V-220907"
    ) 
    Test-WindowsDefenderFirewall
    Test-AlternateOperatingSystems
    Test-NonSystemFileShares
    Test-UEFIBootMode
    Test-SecureBootStatus
    Test-BitLockerCompliance
    Test-WindowsVersionCompliance
    Test-WindowsDefenderStatus
    Test-FileSystemCompliance
    Test-DEPOptOut
    Test-KernelDMAProtection
    Test-EventLogPermissions
    Test-SystemFilePermissions

    #FINAL REPORT
    Write-Log "STIG remediation process completed" "INFO"
    Show-STIGComplianceReport
    
    Write-Host "Press any key to close this window..." -ForegroundColor Yellow
    [System.Console]::ReadKey($true)| Out-Null
    Stop-Process -Id $PID
}

#EXECUTE STIG REMEDIATION
Start-STIGRemediation

#END-REGION
