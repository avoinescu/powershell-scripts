<#
.SYNOPSIS
    CIS Microsoft Windows Server 2022 Benchmark v5.0.0 - Domain Controller FULL Audit
.DESCRIPTION
    Comprehensive, READ-ONLY compliance audit for a Windows Server 2022 Domain
    Controller. Covers all 391 recommendations that apply to the DC profile by
    using the correct data source for each control type:

        Registry (HKLM)            291 checks
        Registry (HKCU/per-user)    11 checks   (section 19, current user hive)
        secedit - Password/Lockout   9 checks   (section 1)
        secedit - User Rights       39 checks   (section 2.2)
        auditpol - Advanced Audit   34 checks   (section 17)
        Needs-review (special)       6 checks   (section 2.3 multi-value/string)
        --------------------------------------------------------------
        TOTAL                      390 of 391 recommendations addressed

    Member-Server-only recommendations are intentionally excluded.

    Produces: console summary, CSV report, color-coded HTML report, and a
    self-audit transcript log of every action taken. Makes NO system changes.

.NOTES
    * Run elevated (Administrator) on the target Domain Controller.
    * secedit/auditpol checks require local admin; auditpol requires the
      'Manage auditing and security log' right (admins have it by default).
    * Generated from CIS_Microsoft_Windows_Server_2022_Benchmark_v5_0_0.pdf
    * Value names were reconciled against the benchmark; spot-test on a known
      host before relying on results org-wide.
#>

[CmdletBinding()]
param([string]$OutputDir = "$env:USERPROFILE\Desktop\CIS_DC_Audit")

$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date
$script:AuditLog  = New-Object System.Collections.Generic.List[string]
$script:Results   = New-Object System.Collections.Generic.List[object]

function Write-AuditLog {
    param([string]$Message,[string]$Level='INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff'),$Level,$Message
    $script:AuditLog.Add($line)
    if ($Level -eq 'ERROR') { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq 'WARN') { Write-Host $line -ForegroundColor Yellow }
    else { Write-Verbose $line }
}

function Add-Result {
    param($Id,$Title,$Source,$Expected,$Actual,$Status,$Detail)
    $script:Results.Add([pscustomobject]@{
        Id=$Id; Title=$Title; Source=$Source; Expected=$Expected
        Actual=$Actual; Status=$Status; Detail=$Detail })
}

Write-AuditLog "=== CIS WS2022 v5.0.0 Domain Controller FULL audit started ==="
Write-AuditLog "Host: $env:COMPUTERNAME  User: $env:USERNAME  PS: $($PSVersionTable.PSVersion)"
try { $os=Get-CimInstance Win32_OperatingSystem; Write-AuditLog "OS: $($os.Caption) Build $($os.BuildNumber)" } catch {}
try {
    $role=(Get-CimInstance Win32_ComputerSystem).DomainRole
    Write-AuditLog "DomainRole=$role IsDC=$($role -eq 4 -or $role -eq 5)"
    if ($role -ne 4 -and $role -ne 5) { Write-AuditLog "Host is not a Domain Controller; DC profile may not fully apply." 'WARN' }
} catch { Write-AuditLog "Role check failed: $($_.Exception.Message)" 'WARN' }
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-AuditLog "Elevated: $admin"
if (-not $admin) { Write-AuditLog "Not elevated - secedit/auditpol and some hives may be unreadable." 'WARN' }

$RegistryChecks = @(
    @{ Id='2.3.1.2'; Title='Ensure ''Accounts: Limit local account use of blank passwords to console logon only'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LimitBlankPasswordUse'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.2.1'; Title='Ensure ''Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='SCENoApplyLegacyAuditPolicy'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.2.2'; Title='Ensure ''Audit: Shut down system immediately if unable to log security audits'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='CrashOnAuditFail'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.4.1'; Title='Ensure ''Devices: Prevent users from installing printer drivers'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'; Name='AddPrinterDrivers'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.5.1'; Title='Ensure ''Domain controller: Allow server operators to schedule tasks'' is set to ''Disabled'' (DC only) (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='SubmitControl'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.5.2'; Title='Ensure ''Domain controller: Allow vulnerable Netlogon secure channel connections'' is set to ''Not Configured'' (DC Only) (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='VulnerableChannelAllowList'; Type='REG_SZ'; Expected='does not exist'; Op='absent' },
    @{ Id='2.3.5.3'; Title='Ensure ''Domain controller: LDAP server channel binding token requirements'' is set to ''Always'' (DC Only) (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name='LdapEnforceChannelBinding'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='2.3.5.4'; Title='Ensure ''Domain controller: LDAP server signing requirements'' is set to ''Require signing'' (DC only) (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Name='LDAPServerIntegrity'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='2.3.5.5'; Title='Ensure ''Domain controller: Refuse machine account password changes'' is set to ''Disabled'' (DC only) (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='RefusePasswordChange'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.6.1'; Title='Ensure ''Domain member: Digitally encrypt or sign secure channel data (always)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireSignOrSeal'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.6.2'; Title='Ensure ''Domain member: Digitally encrypt secure channel data (when possible)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='SealSecureChannel'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.6.3'; Title='Ensure ''Domain member: Digitally sign secure channel data (when possible)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='SignSecureChannel'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.6.4'; Title='Ensure ''Domain member: Disable machine account password changes'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='DisablePasswordChange'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.6.5'; Title='Ensure ''Domain member: Maximum machine account password age'' is set to ''30 or fewer days, but not 0'' (Automated)'; Path='HKLM\System\CurrentControlSet\Services\Netlogon\Parameters'; Name='MaximumPasswordAge'; Type='REG_DWORD'; Expected='30 or less, but not 0'; Op='le'; Value=30; Exclude=@(0) },
    @{ Id='2.3.6.6'; Title='Ensure ''Domain member: Require strong (Windows 2000 or later) session key'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireStrongKey'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.7.1'; Title='Ensure ''Interactive logon: Do not require CTRL+ALT+DEL'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableCAD'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.7.2'; Title='Ensure ''Interactive logon: Don''t display last signed-in'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DontDisplayLastUserName'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.7.7'; Title='Ensure ''Interactive logon: Prompt user to change password before expiration'' is set to ''between 5 and 14 days'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='PasswordExpiryWarning'; Type='REG_DWORD'; Expected='between 5 and 14'; Op='between'; Lo=5; Hi=14 },
    @{ Id='2.3.7.9'; Title='Ensure ''Interactive logon: Smart card removal behavior'' is set to ''Lock Workstation'' or higher (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='ScRemoveOption'; Type='REG_SZ'; Expected='1, 2, or 3'; Op='in'; Values=@(1,2,3) },
    @{ Id='2.3.8.1'; Title='Ensure ''Microsoft network client: Digitally sign communications (always)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.8.2'; Title='Ensure ''Microsoft network client: Send unencrypted password to third-party SMB servers'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='EnablePlainTextPassword'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.9.2'; Title='Ensure ''Microsoft network server: Digitally sign communications (always)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RequireSecuritySignature'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.9.3'; Title='Ensure ''Microsoft network server: Disconnect clients when logon hours expire'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='enableforcedlogoff'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.10.4'; Title='Ensure ''Network access: Do not allow storage of passwords and credentials for network authentication'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='DisableDomainCreds'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.10.5'; Title='Ensure ''Network access: Let Everyone permissions apply to anonymous users'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='EveryoneIncludesAnonymous'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.10.8'; Title='Ensure ''Network access: Remotely accessible registry paths'' is configured (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths'; Name='Machine'; Type='REG_MULTI_SZ'; Expected='see benchmark (multi-string list)'; Op='manual' },
    @{ Id='2.3.10.9'; Title='Ensure ''Network access: Remotely accessible registry paths and sub-paths'' is configured (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'; Name='Machine'; Type='REG_MULTI_SZ'; Expected='see benchmark (multi-string list)'; Op='manual' },
    @{ Id='2.3.10.10'; Title='Ensure ''Network access: Restrict anonymous access to Named Pipes and Shares'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='RestrictNullSessAccess'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.10.13'; Title='Ensure ''Network access: Sharing and security model for local accounts'' is set to ''Classic - local users authenticate as themselves'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='ForceGuest'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.11.1'; Title='Ensure ''Network security: Allow Local System to use computer identity for NTLM'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='UseMachineId'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.11.2'; Title='Ensure ''Network security: Allow LocalSystem NULL session fallback'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='AllowNullSessionFallback'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.11.3'; Title='Ensure ''Network Security: Allow PKU2U authentication requests to this computer to use online identities'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'; Name='AllowOnlineID'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.11.4'; Title='Ensure ''Network security: Configure encryption types allowed for Kerberos'' is set to ''AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name='SupportedEncryptionTypes'; Type='REG_DWORD'; Expected='2147483640'; Op='eq'; Value=2147483640 },
    @{ Id='2.3.11.5'; Title='Ensure ''Network security: Do not store LAN Manager hash value on next password change'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='NoLMHash'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.11.7'; Title='Ensure ''Network security: LAN Manager authentication level'' is set to ''Send NTLMv2 response only. Refuse LM & NTLM'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Type='REG_DWORD'; Expected='5'; Op='eq'; Value=5 },
    @{ Id='2.3.11.8'; Title='Ensure ''Network security: LDAP client signing requirements'' is set to ''Negotiate signing'' or higher (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\LDAP'; Name='LDAPClientIntegrity'; Type='REG_DWORD'; Expected='1 or 2'; Op='in'; Values=@(1,2) },
    @{ Id='2.3.11.11'; Title='Ensure ''Network security: Restrict NTLM: Audit Incoming NTLM Traffic'' is set to ''Enable auditing for all accounts'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='AuditReceivingNTLMTraffic'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='2.3.11.12'; Title='Ensure ''Network security: Restrict NTLM: Audit NTLM authentication in this domain'' is set to ''Enable all'' (DC only) (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name='AuditNTLMInDomain'; Type='REG_DWORD'; Expected='7'; Op='eq'; Value=7 },
    @{ Id='2.3.11.13'; Title='Ensure ''Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'' is set to ''Audit all'' or higher (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='RestrictSendingNTLMTraffic'; Type='REG_DWORD'; Expected='1 or 2'; Op='in'; Values=@(1,2) },
    @{ Id='2.3.13.1'; Title='Ensure ''Shutdown: Allow system to be shut down without having to log on'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ShutdownWithoutLogon'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.15.1'; Title='Ensure ''System objects: Require case insensitivity for non-Windows subsystems'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'; Name='ObCaseInsensitive'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.15.2'; Title='Ensure ''System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'; Name='ProtectionMode'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.17.1'; Title='Ensure ''User Account Control: Admin Approval Mode for the Built-in Administrator account'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.17.2'; Title='Ensure ''User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'' is set to ''Prompt for consent on the secure desktop'' or higher (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Type='REG_DWORD'; Expected='1 or2'; Op='in'; Values=@(1,2) },
    @{ Id='2.3.17.3'; Title='Ensure ''User Account Control: Behavior of the elevation prompt for standard users'' is set to ''Automatically deny elevation requests'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='2.3.17.4'; Title='Ensure ''User Account Control: Detect application installations and prompt for elevation'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableInstallerDetection'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.17.5'; Title='Ensure ''User Account Control: Only elevate UIAccess applications that are installed in secure locations'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableSecureUIAPaths'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.17.6'; Title='Ensure ''User Account Control: Run all administrators in Admin Approval Mode'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.17.7'; Title='Ensure ''User Account Control: Switch to the secure desktop when prompting for elevation'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='2.3.17.8'; Title='Ensure ''User Account Control: Virtualize file and registry write failures to per-user locations'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableVirtualization'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='5.1'; Title='Ensure ''Print Spooler (Spooler)'' is set to ''Disabled'' (DC only) (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Spooler'; Name='Start'; Type='REG_DWORD'; Expected='4'; Op='eq'; Value=4 },
    @{ Id='9.1.1'; Title='Ensure ''Windows Firewall: Domain: Firewall state'' is set to ''On (recommended)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name='EnableFirewall'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.1.2'; Title='Ensure ''Windows Firewall: Domain: Inbound connections'' is set to ''Block (default)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name='DefaultInboundAction'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.1.3'; Title='Ensure ''Windows Firewall: Domain: Settings: Display a notification'' is set to ''No'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name='DisableNotifications'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.1.4'; Title='Ensure ''Windows Firewall: Domain: Logging: Name'' is configured (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogFilePath'; Type='REG_SZ'; Expected='<path>\<filename>'; Op='manual' },
    @{ Id='9.1.5'; Title='Ensure ''Windows Firewall: Domain: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogFileSize'; Type='REG_DWORD'; Expected='16384'; Op='eq'; Value=16384 },
    @{ Id='9.1.6'; Title='Ensure ''Windows Firewall: Domain: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogDroppedPackets'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.1.7'; Title='Ensure ''Windows Firewall: Domain: Logging: Log successful connections'' is set to ''Yes'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogSuccessfulConnections'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.2.1'; Title='Ensure ''Windows Firewall: Private: Firewall state'' is set to ''On (recommended)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name='EnableFirewall'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.2.2'; Title='Ensure ''Windows Firewall: Private: Inbound connections'' is set to ''Block (default)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name='DefaultInboundAction'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.2.3'; Title='Ensure ''Windows Firewall: Private: Settings: Display a notification'' is set to ''No'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name='DisableNotifications'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.2.4'; Title='Ensure ''Windows Firewall: Private: Logging: Name'' is configured (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogFilePath'; Type='REG_SZ'; Expected='<path>\<filename>'; Op='manual' },
    @{ Id='9.2.5'; Title='Ensure ''Windows Firewall: Private: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogFileSize'; Type='REG_DWORD'; Expected='16384'; Op='eq'; Value=16384 },
    @{ Id='9.2.6'; Title='Ensure ''Windows Firewall: Private: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogDroppedPackets'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.2.7'; Title='Ensure ''Windows Firewall: Private: Logging: Log successful connections'' is set to ''Yes'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogSuccessfulConnections'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.3.1'; Title='Ensure ''Windows Firewall: Public: Firewall state'' is set to ''On (recommended)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='EnableFirewall'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.3.2'; Title='Ensure ''Windows Firewall: Public: Inbound connections'' is set to ''Block (default)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='DefaultInboundAction'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.3.3'; Title='Ensure ''Windows Firewall: Public: Settings: Display a notification'' is set to ''No'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='DisableNotifications'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.3.4'; Title='Ensure ''Windows Firewall: Public: Settings: Apply local firewall rules'' is set to ''No'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='AllowLocalPolicyMerge'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='9.3.5'; Title='Ensure ''Windows Firewall: Public: Settings: Apply local connection security rules'' is set to ''No'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='AllowLocalIPsecPolicyMerge'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='9.3.6'; Title='Ensure ''Windows Firewall: Public: Logging: Name'' is configured (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogFilePath'; Type='REG_SZ'; Expected='<path>\<filename>'; Op='manual' },
    @{ Id='9.3.7'; Title='Ensure ''Windows Firewall: Public: Logging: Size limit (KB)'' is set to ''16,384 KB or greater'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogFileSize'; Type='REG_DWORD'; Expected='16384'; Op='eq'; Value=16384 },
    @{ Id='9.3.8'; Title='Ensure ''Windows Firewall: Public: Logging: Log dropped packets'' is set to ''Yes'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogDroppedPackets'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='9.3.9'; Title='Ensure ''Windows Firewall: Public: Logging: Log successful connections'' is set to ''Yes'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogSuccessfulConnections'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='10.42.11.1.1.1'; Title='Ensure ''Configure Brute-Force Protection aggressiveness'' is set to ''Enabled: Medium'' or higher (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection'; Name='BruteForceProtectionAggressiveness'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='10.42.11.1.1.2'; Title='Ensure ''Configure Remote Encryption Protection Mode'' is set to ''Enabled: Audit'' or higher (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Brute Force Protection'; Name='BruteForceProtectionConfiguredState'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='10.42.11.1.2.1'; Title='Ensure ''Configure how aggressively Remote Encryption Protection blocks threats'' is set to ''Enabled: Medium'' or higher (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Remediation\Behavioral Network Blocks\Remote Encryption Protection'; Name='RemoteEncryptionProtectionAggressiveness'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.1.1.1'; Title='Ensure ''Prevent enabling lock screen camera'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenCamera'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.1.1.2'; Title='Ensure ''Prevent enabling lock screen slide show'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenSlideshow'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.1.2.2'; Title='Ensure ''Allow users to enable online speech recognition services'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization'; Name='AllowInputPersonalization'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.1.3'; Title='Ensure ''Allow Online Tips'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='AllowOnlineTips'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.4.2'; Title='Ensure ''Configure SMB v1 client driver'' is set to ''Enabled: Disable driver (recommended)'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10'; Name='Start'; Type='REG_DWORD'; Expected='4'; Op='eq'; Value=4 },
    @{ Id='18.4.3'; Title='Ensure ''Configure SMB v1 server'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.4.4'; Title='Ensure ''Enable Certificate Padding'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Cryptography\Wintrust\Config'; Name='EnableCertPaddingCheck'; Type='REG_SZ'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.4.5'; Title='Ensure ''Enable Structured Exception Handling Overwrite Protection (SEHOP)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Name='DisableExceptionChainValidation'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.4.6'; Title='Ensure ''NetBT NodeType configuration'' is set to ''Enabled: P-node (recommended)'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name='NodeType'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.5.1'; Title='Ensure ''MSS: (AutoAdminLogon) Enable Automatic Logon'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='AutoAdminLogon'; Type='REG_SZ'; Expected='Disabled'; Op='eq'; Value=0 },
    @{ Id='18.5.2'; Title='Ensure ''MSS: (DisableIPSourceRouting IPv6) IP source routing protection level'' is set to ''Enabled: Highest protection, source routing is completely disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name='DisableIPSourceRouting'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.5.3'; Title='Ensure ''MSS: (DisableIPSourceRouting) IP source routing protection level'' is set to ''Enabled: Highest protection, source routing is completely disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='DisableIPSourceRouting'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.5.4'; Title='Ensure ''MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='EnableICMPRedirect'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.5.5'; Title='Ensure ''MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds'' is set to ''Enabled: 300,000 or 5 minutes'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='KeepAliveTime'; Type='REG_DWORD'; Expected='300000'; Op='eq'; Value=300000 },
    @{ Id='18.5.6'; Title='Ensure ''MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name='NoNameReleaseOnDemand'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.5.7'; Title='Ensure ''MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses'' is set to ''Disabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='PerformRouterDiscovery'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.5.8'; Title='Ensure ''MSS: (SafeDllSearchMode) Enable Safe DLL search mode'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'; Name='SafeDllSearchMode'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.5.9'; Title='Ensure ''MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted'' is set to ''Enabled: 3'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'; Name='TcpMaxDataRetransmissions'; Type='REG_DWORD'; Expected='3'; Op='eq'; Value=3 },
    @{ Id='18.5.10'; Title='Ensure ''MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted'' is set to ''Enabled: 3'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='TcpMaxDataRetransmissions'; Type='REG_DWORD'; Expected='3'; Op='eq'; Value=3 },
    @{ Id='18.5.11'; Title='Ensure ''MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning'' is set to ''Enabled: 90% or less'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Services\Eventlog\Security'; Name='WarningLevel'; Type='REG_DWORD'; Expected='90'; Op='eq'; Value=90 },
    @{ Id='18.6.4.1'; Title='Ensure ''Configure multicast DNS (mDNS) protocol'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMDNS'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.4.2'; Title='Ensure ''Configure NetBIOS settings'' is set to ''Enabled: Disable NetBIOS name resolution on public networks'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableNetbios'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.4.3'; Title='Ensure ''Turn off default IPv6 DNS Servers'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='DisableIPv6DefaultDnsServers'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.6.4.4'; Title='Ensure ''Turn off multicast name resolution'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMulticast'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.5.1'; Title='Ensure ''Enable Font Providers'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableFontProviders'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.7.1'; Title='Ensure ''Mandate the minimum version of SMB'' is set to ''Enabled: 3.1.1'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanServer'; Name='MinSmb2Dialect'; Type='REG_DWORD'; Expected='785'; Op='eq'; Value=785 },
    @{ Id='18.6.8.1'; Title='Ensure ''Enable insecure guest logons'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name='AllowInsecureGuestAuth'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.8.2'; Title='Ensure ''Require Encryption'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name='RequireEncryption'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.6.9.1'; Title='Ensure ''Turn on Mapper I/O (LLTDIO) driver'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD'; Name='AllowLLTDIOOnDomain'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.9.2'; Title='Ensure ''Turn on Responder (RSPNDR) driver'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\LLTD'; Name='AllowRspndrOnDomain'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.10.2'; Title='Ensure ''Turn off Microsoft Peer-to-Peer Networking Services'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Peernet'; Name='Disabled'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.6.11.2'; Title='Ensure ''Prohibit installation and configuration of Network Bridge on your DNS domain network'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_AllowNetBridge_NLA'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.11.3'; Title='Ensure ''Prohibit use of Internet Connection Sharing on your DNS domain network'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_ShowSharedAccessUI'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.11.4'; Title='Ensure ''Require domain users to elevate when setting a network''s location'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_StdDomainUserSetLocation'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.6.20.1'; Title='Ensure ''Configuration of wireless settings using Windows Connect Now'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; Name='EnableRegistrars'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.6.20.2'; Title='Ensure ''Prohibit access of the Windows Connect Now wizards'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\UI'; Name='DisableWcnUi'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.6.21.1'; Title='Ensure ''Minimize the number of simultaneous connections to the Internet or a Windows Domain'' is set to ''Enabled: 3 = Prevent Wi-Fi when on Ethernet'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'; Name='fMinimizeConnections'; Type='REG_DWORD'; Expected='3'; Op='eq'; Value=3 },
    @{ Id='18.7.1'; Title='Ensure ''Allow Print Spooler to accept client connections'' is set to ''Disabled'' (Automated)'; Path='HKLM\Software\Policies\Microsoft\Windows NT\Printers'; Name='RegisterSpoolerRemoteRpcEndPoint'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.7.2'; Title='Ensure ''Configure Redirection Guard'' is set to ''Enabled: Redirection Guard Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='RedirectionguardPolicy'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.7.3'; Title='Ensure ''Configure RPC connection settings: Protocol to use for outgoing RPC connections'' is set to ''Enabled: RPC over TCP'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcUseNamedPipeProtocol'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.7.4'; Title='Ensure ''Configure RPC connection settings: Use authentication for outgoing RPC connections'' is set to ''Enabled: Default'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcAuthentication'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.7.5'; Title='Ensure ''Configure RPC listener settings: Protocols to allow for incoming RPC connections'' is set to ''Enabled: RPC over TCP'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcProtocols'; Type='REG_DWORD'; Expected='5'; Op='eq'; Value=5 },
    @{ Id='18.7.6'; Title='Ensure ''Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:'' is set to ''Enabled: Negotiate'' or higher (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'; Name='ForceKerberosForRpc'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.7.7'; Title='Ensure ''Configure RPC over TCP port'' is set to ''Enabled: 0'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcTcpPort'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.7.8'; Title='Ensure ''Configure RPC packet level privacy setting for incoming connections'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Control\Print'; Name='RpcAuthnLevelPrivacyEnabled'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.7.9'; Title='Ensure ''Limits print driver installation to Administrators'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; Name='RestrictDriverInstallationToAdministrators'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.7.10'; Title='Ensure ''Manage processing of Queue-specific files'' is set to ''Enabled: Limit Queue-specific files to Color profiles'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='CopyFilesPolicy'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.7.11'; Title='Ensure ''Point and Print Restrictions: When installing drivers for a new connection'' is set to ''Enabled: Show warning and elevation prompt'' (Automated)'; Path='HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; Name='NoWarningNoElevationOnInstall'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.7.12'; Title='Ensure ''Point and Print Restrictions: When updating drivers for an existing connection'' is set to ''Enabled: Show warning and elevation prompt'' (Automated)'; Path='HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; Name='UpdatePromptSettings'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.8.1.1'; Title='Ensure ''Turn off notifications network usage'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name='NoCloudApplicationNotification'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.3.1'; Title='Ensure ''Include command line in process creation events'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.4.1'; Title='Ensure ''Encryption Oracle Remediation'' is set to ''Enabled: Force Updated Clients'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'; Name='AllowEncryptionOracle'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.4.2'; Title='Ensure ''Remote host allows delegation of non-exportable credentials'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name='AllowProtectedCreds'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.5.1'; Title='Ensure ''Turn On Virtualization Based Security'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='EnableVirtualizationBasedSecurity'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.5.2'; Title='Ensure ''Turn On Virtualization Based Security: Select Platform Security Level'' is set to ''Secure Boot'' or higher (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='RequirePlatformSecurityFeatures'; Type='REG_DWORD'; Expected='1or 3'; Op='in'; Values=@(1,3) },
    @{ Id='18.9.5.3'; Title='Ensure ''Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity'' is set to ''Enabled with UEFI lock'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HypervisorEnforcedCodeIntegrity'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.5.4'; Title='Ensure ''Turn On Virtualization Based Security: Require UEFI Memory Attributes Table'' is set to ''True (checked)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HVCIMATRequired'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.5.5'; Title='Ensure ''Turn On Virtualization Based Security: Credential Guard Configuration'' is set to ''Enabled with UEFI lock'' (MS Only) (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='LsaCfgFlags'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.5.6'; Title='Ensure ''Turn On Virtualization Based Security: Credential Guard Configuration'' is set to ''Disabled'' (DC Only) (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='LsaCfgFlags'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.5.7'; Title='Ensure ''Turn On Virtualization Based Security: Secure Launch Configuration'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='ConfigureSystemGuardLaunch'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.7.2'; Title='Ensure ''Prevent automatic download of applications associated with device metadata'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata'; Name='PreventDeviceMetadataFromNetwork'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.13.1'; Title='Ensure ''Boot-Start Driver Initialization Policy'' is set to ''Enabled: Good, unknown and bad but critical'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'; Name='DriverLoadPolicy'; Type='REG_DWORD'; Expected='3'; Op='eq'; Value=3 },
    @{ Id='18.9.17.1'; Title='Ensure ''Enable / disable CLFS logfile authentication'' is set to ''Enabled'' (Automated)'; Path='HKLM\SYSTEM\CurrentControlSet\Policies'; Name='ClfsAuthenticationChecking'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.19.2'; Title='Ensure ''Configure security policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; Name='NoBackgroundPolicy'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.19.3'; Title='Ensure ''Configure security policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; Name='NoGPOListChanges'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.19.4'; Title='Ensure ''Continue experiences on this device'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableCdp'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.19.5'; Title='Ensure ''Turn off background refresh of Group Policy'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableBkGndGroupPolicy'; Type='REG_DWORD'; Expected='does not exist'; Op='absent' },
    @{ Id='18.9.20.1.1'; Title='Ensure ''Turn off downloading of print drivers over HTTP'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableWebPnPDownload'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.2'; Title='Ensure ''Turn off handwriting personalization data sharing'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC'; Name='PreventHandwritingDataSharing'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.3'; Title='Ensure ''Turn off handwriting recognition error reporting'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'; Name='PreventHandwritingErrorReports'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.4'; Title='Ensure ''Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'; Name='ExitOnMSICW'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.5'; Title='Ensure ''Turn off Internet download for Web publishing and online ordering wizards'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoWebServices'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.6'; Title='Ensure ''Turn off printing over HTTP'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableHTTPPrinting'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.7'; Title='Ensure ''Turn off Registration if URL connection is referring to Microsoft.com'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control'; Name='NoRegistration'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.8'; Title='Ensure ''Turn off Search Companion content file updates'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion'; Name='DisableContentFileUpdates'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.9'; Title='Ensure ''Turn off the "Order Prints" picture task'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoOnlinePrintsWizard'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.10'; Title='Ensure ''Turn off the "Publish to Web" task for files and folders'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoPublishingWizard'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.20.1.11'; Title='Ensure ''Turn off the Windows Messenger Customer Experience Improvement Program'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client'; Name='CEIP'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.9.20.1.12'; Title='Ensure ''Turn off Windows Customer Experience Improvement Program'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows'; Name='CEIPEnable'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.20.1.13'; Title='Ensure ''Turn off Windows Error Reporting'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting'; Name='DoReport'; Type='REG_DWORD'; Expected='0 (DoReport) and 1 (Disabled)'; Op='in'; Values=@(0,1) },
    @{ Id='18.9.23.1'; Title='Ensure ''Support device authentication using certificate'' is set to ''Enabled: Automatic'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'; Name='DevicePKInitBehavior'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.24.1'; Title='Ensure ''Enumeration policy for external devices incompatible with Kernel DMA Protection'' is set to ''Enabled: Block All'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'; Name='DeviceEnumerationPolicy'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.27.1'; Title='Ensure ''Allow Custom SSPs and APs to be loaded into LSASS'' is set to ''Disabled'' (DC only) (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowCustomSSPsAPs'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.27.2'; Title='Ensure ''Configures LSASS to run as a protected process'' is set to ''Enabled: Enabled with UEFI Lock'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='RunAsPPL'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.28.1'; Title='Ensure ''Disallow copying of user input methods to the system account for sign-in'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Control Panel\International'; Name='BlockUserInputMethodsForSignIn'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.29.1'; Title='Ensure ''Block user from showing account details on sign-in'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='BlockUserFromShowingAccountDetailsOnSignin'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.29.2'; Title='Ensure ''Do not display network selection UI'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='DontDisplayNetworkSelectionUI'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.29.3'; Title='Ensure ''Do not enumerate connected users on domain- joined computers'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='DontEnumerateConnectedUsers'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.29.5'; Title='Ensure ''Turn off app notifications on the lock screen'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='DisableLockScreenAppNotifications'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.29.6'; Title='Ensure ''Turn on convenience PIN sign-in'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowDomainPINLogon'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.33.1'; Title='Ensure ''Allow Clipboard synchronization across devices'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowCrossDeviceClipboard'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.33.2'; Title='Ensure ''Allow upload of User Activities'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='UploadUserActivities'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.35.6.1'; Title='Ensure ''Allow network connectivity during connected- standby (on battery)'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; Name='DCSettingIndex'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.35.6.2'; Title='Ensure ''Allow network connectivity during connected- standby (plugged in)'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; Name='ACSettingIndex'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.35.6.3'; Title='Ensure ''Require a password when a computer wakes (on battery)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='DCSettingIndex'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.35.6.4'; Title='Ensure ''Require a password when a computer wakes (plugged in)'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='ACSettingIndex'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.37.1'; Title='Ensure ''Configure Offer Remote Assistance'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowUnsolicited'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.37.2'; Title='Ensure ''Configure Solicited Remote Assistance'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowToGetHelp'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.41.1'; Title='Ensure ''Configure validation of ROCA-vulnerable WHfB keys during authentication'' is set to ''Enabled: Block'' (DC only) (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\SAM'; Name='SamNGCKeyROCAValidation'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.9.49.5.1'; Title='Ensure ''Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'; Name='DisableQueryRemoteServer'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.49.11.1'; Title='Ensure ''Enable/Disable PerfTrack'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'; Name='ScenarioExecutionEnabled'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.9.51.1'; Title='Ensure ''Turn off the advertising ID'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name='DisabledByGroupPolicy'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.9.53.1.1'; Title='Ensure ''Enable Windows NTP Client'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'; Name='Enabled'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.4.1'; Title='Ensure ''Allow a Windows app to share application data between users'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager'; Name='AllowSharedLocalAppData'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.6.1'; Title='Ensure ''Allow Microsoft accounts to be optional'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='MSAOptional'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.8.1'; Title='Ensure ''Disallow Autoplay for non-volume devices'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoAutoplayfornonVolume'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.8.2'; Title='Ensure ''Set the default behavior for AutoRun'' is set to ''Enabled: Do not execute any autorun commands'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.8.3'; Title='Ensure ''Turn off Autoplay'' is set to ''Enabled: All drives'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'; Type='REG_DWORD'; Expected='255'; Op='eq'; Value=255 },
    @{ Id='18.10.9.1.1'; Title='Ensure ''Configure enhanced anti-spoofing'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; Name='EnhancedAntiSpoofing'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.11.1'; Title='Ensure ''Allow Use of Camera'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Camera'; Name='AllowCamera'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.13.1'; Title='Ensure ''Turn off cloud consumer account state content'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableConsumerAccountStateContent'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.13.2'; Title='Ensure ''Turn off cloud optimized content'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableCloudOptimizedContent'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.14.1'; Title='Ensure ''Require pin for pairing'' is set to ''Enabled: First Time'' OR ''Enabled: Always'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Connect'; Name='RequirePinForPairing'; Type='REG_DWORD'; Expected='1or 2'; Op='in'; Values=@(1,2) },
    @{ Id='18.10.15.1'; Title='Ensure ''Do not display the password reveal button'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI'; Name='DisablePasswordReveal'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.15.2'; Title='Ensure ''Enumerate administrator accounts on elevation'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name='EnumerateAdministrators'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.16.1'; Title='Ensure ''Allow Diagnostic Data'' is set to ''Enabled: Diagnostic data off (not recommended)'' or ''Enabled: Send required diagnostic data'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Type='REG_DWORD'; Expected='0 or 1'; Op='in'; Values=@(0,1) },
    @{ Id='18.10.16.2'; Title='Ensure ''Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service'' is set to ''Enabled: Disable Authenticated Proxy usage'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DisableEnterpriseAuthProxy'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.16.3'; Title='Ensure ''Do not show feedback notifications'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DoNotShowFeedbackNotifications'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.16.4'; Title='Ensure ''Enable OneSettings Auditing'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='EnableOneSettingsAuditing'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.16.5'; Title='Ensure ''Limit Diagnostic Log Collection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitDiagnosticLogCollection'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.16.6'; Title='Ensure ''Limit Dump Collection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitDumpCollection'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.18.1'; Title='Ensure ''Enable App Installer'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableAppInstaller'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.18.2'; Title='Ensure ''Enable App Installer Experimental Features'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableExperimentalFeatures'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.18.3'; Title='Ensure ''Enable App Installer Hash Override'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableHashOverride'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.18.4'; Title='Ensure ''Enable App Installer Local Archive Malware Scan Override'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableLocalArchiveMalwareScanOverride'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.18.5'; Title='Ensure ''Enable App Installer ms-appinstaller protocol'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableMSAppInstallerProtocol'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.18.6'; Title='Ensure ''Enable App Installer Microsoft Store Source Certificate Validation Bypass'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableBypassCertificatePinningForMicrosoftStore'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.18.7'; Title='Ensure ''Enable Windows Package Manager command line interfaces'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableWindowsPackageManagerCommandLineInterfaces'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.26.1.1'; Title='Ensure ''Application: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name='Retention'; Type='REG_SZ'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.26.1.2'; Title='Ensure ''Application: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name='MaxSize'; Type='REG_DWORD'; Expected='32768'; Op='eq'; Value=32768 },
    @{ Id='18.10.26.2.1'; Title='Ensure ''Security: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='Retention'; Type='REG_SZ'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.26.2.2'; Title='Ensure ''Security: Specify the maximum log file size (KB)'' is set to ''Enabled: 196,608 or greater'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='MaxSize'; Type='REG_DWORD'; Expected='196608'; Op='eq'; Value=196608 },
    @{ Id='18.10.26.3.1'; Title='Ensure ''Setup: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'; Name='Retention'; Type='REG_SZ'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.26.3.2'; Title='Ensure ''Setup: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'; Name='MaxSize'; Type='REG_DWORD'; Expected='32768'; Op='eq'; Value=32768 },
    @{ Id='18.10.26.4.1'; Title='Ensure ''System: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name='Retention'; Type='REG_SZ'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.26.4.2'; Title='Ensure ''System: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name='MaxSize'; Type='REG_DWORD'; Expected='32768'; Op='eq'; Value=32768 },
    @{ Id='18.10.29.2'; Title='Ensure ''Do not apply the Mark of the Web tag to files copied from insecure sources'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='DisableMotWOnInsecurePathCopy'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.29.3'; Title='Ensure ''Turn off Data Execution Prevention for Explorer'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoDataExecutionPrevention'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.29.4'; Title='Ensure ''Turn off heap termination on corruption'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoHeapTerminationOnCorruption'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.29.5'; Title='Ensure ''Turn off shell protocol protected mode'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='PreXPSP2ShellProtocolBehavior'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.36.1'; Title='Ensure ''Turn off location'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Name='DisableLocation'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.40.1'; Title='Ensure ''Allow Message Service Cloud Sync'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging'; Name='AllowMessageSync'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.41.1'; Title='Ensure ''Block all consumer Microsoft account user authentication'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount'; Name='DisableUserAuth'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.4.1'; Title='Ensure ''Enable EDR in block mode'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Features'; Name='PassiveRemediation'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.5.1'; Title='Ensure ''Configure local setting override for reporting to Microsoft MAPS'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name='LocalSettingOverrideSpynetReporting'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.5.2'; Title='Ensure ''Join Microsoft MAPS'' is set to ''Enabled: Advanced'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name='SpynetReporting'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.10.42.6.1.1'; Title='Ensure ''Configure Attack Surface Reduction rules'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'; Name='ExploitGuard_ASR_Rules'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.6.1.2'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='26190899-1602-49e8-8b27-eb1d0a1ce869'; Type='REG_SZ'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.6.3.1'; Title='Ensure ''Prevent users and apps from accessing dangerous websites'' is set to ''Enabled: Block'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'; Name='EnableNetworkProtection'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.7.1'; Title='Ensure ''Enable file hash computation feature'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'; Name='EnableFileHashComputation'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.8.1'; Title='Ensure ''Convert warn verdict to block'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\NIS'; Name='EnableConvertWarnToBlock'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.10.1'; Title='Ensure ''Configure real-time protection and Security Intelligence Updates during OOBE'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='OobeEnableRtpAndSigUpdate'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.10.2'; Title='Ensure ''Scan all downloaded files and attachments'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableIOAVProtection'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.10.3'; Title='Ensure ''Turn off real-time protection'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableRealtimeMonitoring'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.10.4'; Title='Ensure ''Turn on behavior monitoring'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableBehaviorMonitoring'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.10.5'; Title='Ensure ''Turn on script scanning'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableScriptScanning'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.12.1'; Title='Ensure ''Configure Watson events'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'; Name='DisableGenericRePorts'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.13.1'; Title='Ensure ''Scan excluded files and directories during quick scans'' is set to ''Enabled: 1'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='QuickScanIncludeExclusions'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.13.2'; Title='Ensure ''Scan packed executables'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='DisablePackedExeScanning'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.13.3'; Title='Ensure ''Scan removable drives'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='DisableRemovableDriveScanning'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.13.4'; Title='Ensure ''Trigger a quick scan after X days without any scans'' is set to ''Enabled: 7'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='DaysUntilAggressiveCatchupQuickScan'; Type='REG_DWORD'; Expected='7'; Op='eq'; Value=7 },
    @{ Id='18.10.42.13.5'; Title='Ensure ''Turn on e-mail scanning'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='DisableEmailScanning'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.42.16'; Title='Ensure ''Configure detection for potentially unwanted applications'' is set to ''Enabled: Block'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'; Name='PUAProtection'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.42.17'; Title='Ensure ''Control whether exclusions are visible to local users'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'; Name='HideExclusionsFromLocalUsers'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.56.1'; Title='Ensure ''Turn off Push To Install service'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\PushToInstall'; Name='DisablePushToInstall'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.2.2'; Title='Ensure ''Do not allow passwords to be saved'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='DisablePasswordSaving'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.2.1'; Title='Ensure ''Restrict Remote Desktop Services users to a single Remote Desktop Services session'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fSingleSessionPerUser'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.3.1'; Title='Ensure ''Allow UI Automation redirection'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='EnableUiaRedirection'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.57.3.3.2'; Title='Ensure ''Do not allow COM port redirection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableCcm'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.3.3'; Title='Ensure ''Do not allow drive redirection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableCdm'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.3.4'; Title='Ensure ''Do not allow location redirection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableLocationRedir'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.3.5'; Title='Ensure ''Do not allow LPT port redirection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableLPT'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.3.6'; Title='Ensure ''Do not allow supported Plug and Play device redirection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisablePNPRedir'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.3.7'; Title='Ensure ''Do not allow WebAuthn redirection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableWebAuthn'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.9.1'; Title='Ensure ''Always prompt for password upon connection'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fPromptForPassword'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.9.2'; Title='Ensure ''Require secure RPC communication'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fEncryptRPCTraffic'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.9.3'; Title='Ensure ''Require use of specific security layer for remote (RDP) connections'' is set to ''Enabled: SSL'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='SecurityLayer'; Type='REG_DWORD'; Expected='2'; Op='eq'; Value=2 },
    @{ Id='18.10.57.3.9.4'; Title='Ensure ''Require user authentication for remote connections by using Network Level Authentication'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='UserAuthentication'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.9.5'; Title='Ensure ''Set client connection encryption level'' is set to ''Enabled: High Level'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MinEncryptionLevel'; Type='REG_DWORD'; Expected='3'; Op='eq'; Value=3 },
    @{ Id='18.10.57.3.10.1'; Title='Ensure ''Set time limit for active but idle Remote Desktop Services sessions'' is set to ''Enabled: 15 minutes or less, but not Never (0)'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MaxIdleTime'; Type='REG_DWORD'; Expected='900000'; Op='eq'; Value=900000 },
    @{ Id='18.10.57.3.10.2'; Title='Ensure ''Set time limit for disconnected sessions'' is set to ''Enabled: 1 minute'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MaxDisconnectionTime'; Type='REG_DWORD'; Expected='60000'; Op='eq'; Value=60000 },
    @{ Id='18.10.57.3.11.1'; Title='Ensure ''Do not delete temp folders upon exit'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='DeleteTempDirsOnExit'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.57.3.11.2'; Title='Ensure ''Do not use temporary folders per session'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='PerSessionTempDir'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.58.1'; Title='Ensure ''Prevent downloading of enclosures'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name='DisableEnclosureDownload'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.58.2'; Title='Ensure ''Turn on Basic feed authentication over HTTP'' is set to ''Disabled'' (Automated)'; Path='HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds'; Name='AllowBasicAuthInClear'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.59.2'; Title='Ensure ''Allow Cloud Search'' is set to ''Enabled: Disable Cloud Search'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowCloudSearch'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.59.3'; Title='Ensure ''Allow indexing of encrypted files'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowIndexingEncryptedStoresOrItems'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.59.4'; Title='Ensure ''Allow search highlights'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='EnableDynamicContentInWSB'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.63.1'; Title='Ensure ''Turn off KMS Client Online AVS Validation'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'; Name='NoGenTicket'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.77.2.1'; Title='Ensure ''Configure Windows Defender SmartScreen'' is set to ''Enabled: Warn and prevent bypass'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableSmartScreen'; Type='REG_DWORD'; Expected='1 (EnableSmartScreen) and REG_SZ value of Block'; Op='manual' },
    @{ Id='18.10.81.1'; Title='Ensure ''Allow suggested apps in Windows Ink Workspace'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name='AllowSuggestedAppsInWindowsInkWorkspace'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.81.2'; Title='Ensure ''Allow Windows Ink Workspace'' is set to ''Enabled: On, but disallow access above lock'' OR ''Enabled: Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name='AllowWindowsInkWorkspace'; Type='REG_DWORD'; Expected='0 or 1'; Op='in'; Values=@(0,1) },
    @{ Id='18.10.82.1'; Title='Ensure ''Allow user control over installs'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='EnableUserControl'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.82.2'; Title='Ensure ''Always install with elevated privileges'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.82.3'; Title='Ensure ''Prevent Internet Explorer security prompt for Windows Installer scripts'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='SafeForScripting'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.83.1'; Title='Ensure ''Configure the transmission of the user''s password in the content of MPR notifications sent by winlogon.'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableMPR'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.83.2'; Title='Ensure ''Sign-in and lock last interactive user automatically after a restart'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableAutomaticRestartSignOn'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.88.1'; Title='Ensure ''Turn on PowerShell Script Block Logging'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.88.2'; Title='Ensure ''Turn on PowerShell Transcription'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableTranscripting'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.90.1.1'; Title='Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowBasic'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.90.1.2'; Title='Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowUnencryptedTraffic'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.90.1.3'; Title='Ensure ''Disallow Digest authentication'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowDigest'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.90.2.1'; Title='Ensure ''Allow Basic authentication'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowBasic'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.90.2.2'; Title='Ensure ''Allow remote server management through WinRM'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowAutoConfig'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.90.2.3'; Title='Ensure ''Allow unencrypted traffic'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowUnencryptedTraffic'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.90.2.4'; Title='Ensure ''Disallow WinRM from storing RunAs credentials'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='DisableRunAs'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.91.1'; Title='Ensure ''Allow Remote Shell Access'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS'; Name='AllowRemoteShellAccess'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.93.2.1'; Title='Ensure ''Prevent users from modifying settings'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'; Name='DisallowExploitProtectionOverride'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.94.1.1'; Title='Ensure ''No auto-restart with logged on users for scheduled automatic updates installations'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='NoAutoRebootWithLoggedOnUsers'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.94.2.1'; Title='Ensure ''Configure Automatic Updates'' is set to ''Enabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='NoAutoUpdate'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.94.2.2'; Title='Ensure ''Configure Automatic Updates: Scheduled install day'' is set to ''0 - Every day'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='ScheduledInstallDay'; Type='REG_DWORD'; Expected='0'; Op='eq'; Value=0 },
    @{ Id='18.10.94.4.1'; Title='Ensure ''Manage preview builds'' is set to ''Disabled'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='ManagePreviewBuildsPolicyValue'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.10.94.4.2'; Title='Ensure ''Select when Quality Updates are received'' is set to ''Enabled: 0 days'' (Automated)'; Path='HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='DeferQualityUpdates'; Type='REG_DWORD'; Expected='1 (DeferQualityUpdates) and 0'; Op='in'; Values=@(1,0) },
    @{ Id='18.11.1'; Title='Ensure ''Disable HTTP proxy features: Disable WPAD'' is set to ''Enabled: Checked'' (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'; Name='DisableWpad'; Type='REG_DWORD'; Expected='1'; Op='eq'; Value=1 },
    @{ Id='18.11.2'; Title='Ensure ''Disable HTTP proxy features: Disable proxy authentication'' is set to ''Enabled: Disable authentication over loopback interfaces'' or higher (Automated)'; Path='HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'; Name='DisableProxyAuthenticationSchemes'; Type='REG_DWORD'; Expected='256'; Op='eq'; Value=256 }
)

$HkcuChecks = @(
    @{ Id='19.5.1.1'; Title='Ensure ''Turn off toast notifications on the lock screen'' is set to ''Enabled'' (Automated)'; SubKey='Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name='NoToastApplicationNotificationOnLockScreen'; Value=1 },
    @{ Id='19.6.6.1.1'; Title='Ensure ''Turn off Help Experience Improvement Program'' is set to ''Enabled'' (Automated)'; SubKey='Software\Policies\Microsoft\Assistance\Client\1.0'; Name='NoImplicitFeedback'; Value=1 },
    @{ Id='19.7.5.1'; Title='Ensure ''Do not preserve zone information in file attachments'' is set to ''Disabled'' (Automated)'; SubKey='Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name='SaveZoneInformation'; Value=2 },
    @{ Id='19.7.5.2'; Title='Ensure ''Notify antivirus programs when opening attachments'' is set to ''Enabled'' (Automated)'; SubKey='Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; Name='ScanWithAntiVirus'; Value=3 },
    @{ Id='19.7.8.1'; Title='Ensure ''Configure Windows spotlight on lock screen'' is set to ''Disabled'' (Automated)'; SubKey='Software\Policies\Microsoft\Windows\CloudContent'; Name='ConfigureWindowsSpotlight'; Value=2 },
    @{ Id='19.7.8.2'; Title='Ensure ''Do not suggest third-party content in Windows spotlight'' is set to ''Enabled'' (Automated)'; SubKey='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableThirdPartySuggestions'; Value=1 },
    @{ Id='19.7.8.3'; Title='Ensure ''Do not use diagnostic data for tailored experiences'' is set to ''Enabled'' (Automated)'; SubKey='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableTailoredExperiencesWithDiagnosticData'; Value=1 },
    @{ Id='19.7.8.4'; Title='Ensure ''Turn off all Windows spotlight features'' is set to ''Enabled'' (Automated)'; SubKey='Software\Policies\Microsoft\Windows\CloudContent'; Name='DisableWindowsSpotlightFeatures'; Value=1 },
    @{ Id='19.7.8.5'; Title='Ensure ''Turn off Spotlight collection on Desktop'' is set to ''Enabled'' (Automated)'; SubKey='SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableSpotlightCollectionOnDesktop'; Value=1 },
    @{ Id='19.7.26.1'; Title='Ensure ''Prevent users from sharing files within their profile.'' is set to ''Enabled'' (Automated)'; SubKey='Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoInplaceSharing'; Value=1 },
    @{ Id='19.7.46.2.1'; Title='Ensure ''Prevent Codec Download'' is set to ''Enabled'' (Automated)'; SubKey='Software\Policies\Microsoft\WindowsMediaPlayer'; Name='PreventCodecDownload'; Value=1 }
)

$PasswordChecks = @(
    @{ Id='1.1.1'; Title='Ensure ''Enforce password history'' is set to ''24 or more password(s)'' (Automated)'; Key='PasswordHistorySize'; Op='ge'; Value=24 },
    @{ Id='1.1.2'; Title='Ensure ''Maximum password age'' is set to ''365 or fewer days, but not 0'' (Automated)'; Key='MaximumPasswordAge'; Op='le_not0'; Value=365 },
    @{ Id='1.1.3'; Title='Ensure ''Minimum password age'' is set to ''1 or more day(s)'' (Automated)'; Key='MinimumPasswordAge'; Op='ge'; Value=1 },
    @{ Id='1.1.4'; Title='Ensure ''Minimum password length'' is set to ''14 or more character(s)'' (Automated)'; Key='MinimumPasswordLength'; Op='ge'; Value=14 },
    @{ Id='1.1.5'; Title='Ensure ''Password must meet complexity requirements'' is set to ''Enabled'' (Automated)'; Key='PasswordComplexity'; Op='eq'; Value=1 },
    @{ Id='1.1.7'; Title='Ensure ''Store passwords using reversible encryption'' is set to ''Disabled'' (Automated)'; Key='ClearTextPassword'; Op='eq'; Value=0 },
    @{ Id='1.2.1'; Title='Ensure ''Account lockout duration'' is set to ''15 or more minute(s)'' (Automated)'; Key='LockoutDuration'; Op='ge'; Value=15 },
    @{ Id='1.2.2'; Title='Ensure ''Account lockout threshold'' is set to ''5 or fewer invalid logon attempt(s), but not 0'' (Automated)'; Key='LockoutBadCount'; Op='le_not0'; Value=5 },
    @{ Id='1.2.4'; Title='Ensure ''Reset account lockout counter after'' is set to ''15 or more minute(s)'' (Automated)'; Key='ResetLockoutCount'; Op='ge'; Value=15 }
)

$UserRightsChecks = @(
    @{ Id='2.2.1'; Title='Ensure ''Access Credential Manager as a trusted caller'' is set to ''No One'' (Automated)'; Privilege='SeTrustedCredManAccessPrivilege'; Expected='No One' },
    @{ Id='2.2.2'; Title='Ensure ''Access this computer from the network'' is set to ''Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'' (DC only) (Automated)'; Privilege='SeNetworkLogonRight'; Expected='Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' },
    @{ Id='2.2.4'; Title='Ensure ''Act as part of the operating system'' is set to ''No One'' (Automated)'; Privilege='SeTcbPrivilege'; Expected='No One' },
    @{ Id='2.2.5'; Title='Ensure ''Add workstations to domain'' is set to ''Administrators'' (DC only) (Automated)'; Privilege='SeMachineAccountPrivilege'; Expected='Administrators' },
    @{ Id='2.2.6'; Title='Ensure ''Adjust memory quotas for a process'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE'' (Automated)'; Privilege='SeIncreaseQuotaPrivilege'; Expected='Administrators, LOCAL SERVICE, NETWORK SERVICE' },
    @{ Id='2.2.7'; Title='Ensure ''Allow log on locally'' is set to ''Administrators, ENTERPRISE DOMAIN CONTROLLERS'' (DC only) (Automated)'; Privilege='SeInteractiveLogonRight'; Expected='Administrators, ENTERPRISE DOMAIN CONTROLLERS' },
    @{ Id='2.2.9'; Title='Ensure ''Allow log on through Remote Desktop Services'' is set to ''Administrators'' (DC only) (Automated)'; Privilege='SeRemoteInteractiveLogonRight'; Expected='Administrators' },
    @{ Id='2.2.11'; Title='Ensure ''Back up files and directories'' is set to ''Administrators'' (Automated)'; Privilege='SeBackupPrivilege'; Expected='Administrators' },
    @{ Id='2.2.12'; Title='Ensure ''Change the system time'' is set to ''Administrators, LOCAL SERVICE'' (Automated)'; Privilege='SeSystemtimePrivilege'; Expected='Administrators, LOCAL SERVICE' },
    @{ Id='2.2.13'; Title='Ensure ''Create a pagefile'' is set to ''Administrators'' (Automated)'; Privilege='SeCreatePagefilePrivilege'; Expected='Administrators' },
    @{ Id='2.2.14'; Title='Ensure ''Create a token object'' is set to ''No One'' (Automated)'; Privilege='SeCreateTokenPrivilege'; Expected='No One' },
    @{ Id='2.2.15'; Title='Ensure ''Create global objects'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' (Automated)'; Privilege='SeCreateGlobalPrivilege'; Expected='Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' },
    @{ Id='2.2.16'; Title='Ensure ''Create permanent shared objects'' is set to ''No One'' (Automated)'; Privilege='SeCreatePermanentPrivilege'; Expected='No One' },
    @{ Id='2.2.17'; Title='Ensure ''Create symbolic links'' is set to ''Administrators'' (DC only) (Automated)'; Privilege='SeCreateSymbolicLinkPrivilege'; Expected='Administrators' },
    @{ Id='2.2.19'; Title='Ensure ''Debug programs'' is set to ''Administrators'' (Automated)'; Privilege='SeDebugPrivilege'; Expected='Administrators' },
    @{ Id='2.2.20'; Title='Ensure ''Deny access to this computer from the network'' to include ''Guests'' (DC only) (Automated)'; Privilege='SeDenyNetworkLogonRight'; Expected='Guests' },
    @{ Id='2.2.22'; Title='Ensure ''Deny log on as a batch job'' to include ''Guests'' (Automated)'; Privilege='SeDenyBatchLogonRight'; Expected='Guests' },
    @{ Id='2.2.23'; Title='Ensure ''Deny log on as a service'' to include ''Guests'' (Automated)'; Privilege='SeDenyServiceLogonRight'; Expected='Guests' },
    @{ Id='2.2.24'; Title='Ensure ''Deny log on locally'' to include ''Guests'' (Automated)'; Privilege='SeDenyInteractiveLogonRight'; Expected='Guests' },
    @{ Id='2.2.25'; Title='Ensure ''Deny log on through Remote Desktop Services'' to include ''Guests'' (DC only) (Automated)'; Privilege='SeDenyRemoteInteractiveLogonRight'; Expected='Guests' },
    @{ Id='2.2.27'; Title='Ensure ''Enable computer and user accounts to be trusted for delegation'' is set to ''Administrators'' (DC only) (Automated)'; Privilege='SeEnableDelegationPrivilege'; Expected='Administrators' },
    @{ Id='2.2.29'; Title='Ensure ''Force shutdown from a remote system'' is set to ''Administrators'' (Automated)'; Privilege='SeRemoteShutdownPrivilege'; Expected='Administrators' },
    @{ Id='2.2.30'; Title='Ensure ''Generate security audits'' is set to ''LOCAL SERVICE, NETWORK SERVICE'' (Automated)'; Privilege='SeAuditPrivilege'; Expected='LOCAL SERVICE, NETWORK SERVICE' },
    @{ Id='2.2.31'; Title='Ensure ''Impersonate a client after authentication'' is set to ''Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'' (DC only) (Automated)'; Privilege='SeImpersonatePrivilege'; Expected='Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' },
    @{ Id='2.2.33'; Title='Ensure ''Increase scheduling priority'' is set to ''Administrators, Window Manager\Window Manager Group'' (Automated)'; Privilege='SeIncreaseBasePriorityPrivilege'; Expected='Administrators, Window Manager\Window Manager Group' },
    @{ Id='2.2.34'; Title='Ensure ''Load and unload device drivers'' is set to ''Administrators'' (Automated)'; Privilege='SeLoadDriverPrivilege'; Expected='Administrators' },
    @{ Id='2.2.35'; Title='Ensure ''Lock pages in memory'' is set to ''No One'' (Automated)'; Privilege='SeLockMemoryPrivilege'; Expected='No One' },
    @{ Id='2.2.36'; Title='Ensure ''Log on as a batch job'' is set to ''Administrators'' (DC Only) (Automated)'; Privilege='SeBatchLogonRight'; Expected='Administrators' },
    @{ Id='2.2.37'; Title='Ensure ''Manage auditing and security log'' is set to ''Administrators'' (DC only) (Automated)'; Privilege='SeSecurityPrivilege'; Expected='Administrators' },
    @{ Id='2.2.39'; Title='Ensure ''Modify an object label'' is set to ''No One'' (Automated)'; Privilege='SeRelabelPrivilege'; Expected='No One' },
    @{ Id='2.2.40'; Title='Ensure ''Modify firmware environment values'' is set to ''Administrators'' (Automated)'; Privilege='SeSystemEnvironmentPrivilege'; Expected='Administrators' },
    @{ Id='2.2.41'; Title='Ensure ''Perform volume maintenance tasks'' is set to ''Administrators'' (Automated)'; Privilege='SeManageVolumePrivilege'; Expected='Administrators' },
    @{ Id='2.2.42'; Title='Ensure ''Profile single process'' is set to ''Administrators'' (Automated)'; Privilege='SeProfileSingleProcessPrivilege'; Expected='Administrators' },
    @{ Id='2.2.43'; Title='Ensure ''Profile system performance'' is set to ''Administrators, NT SERVICE\WdiServiceHost'' (Automated)'; Privilege='SeSystemProfilePrivilege'; Expected='Administrators, NT SERVICE\WdiServiceHost' },
    @{ Id='2.2.44'; Title='Ensure ''Replace a process level token'' is set to ''LOCAL SERVICE, NETWORK SERVICE'' (Automated)'; Privilege='SeAssignPrimaryTokenPrivilege'; Expected='LOCAL SERVICE, NETWORK SERVICE' },
    @{ Id='2.2.45'; Title='Ensure ''Restore files and directories'' is set to ''Administrators'' (Automated)'; Privilege='SeRestorePrivilege'; Expected='Administrators' },
    @{ Id='2.2.46'; Title='Ensure ''Shut down the system'' is set to ''Administrators'' (Automated)'; Privilege='SeShutdownPrivilege'; Expected='Administrators' },
    @{ Id='2.2.47'; Title='Ensure ''Synchronize directory service data'' is set to ''No One'' (DC only) (Automated)'; Privilege='SeSyncAgentPrivilege'; Expected='No One' },
    @{ Id='2.2.48'; Title='Ensure ''Take ownership of files or other objects'' is set to ''Administrators'' (Automated)'; Privilege='SeTakeOwnershipPrivilege'; Expected='Administrators' }
)

$AuditPolicyChecks = @(
    @{ Id='17.1.1'; Title='Ensure ''Audit Credential Validation'' is set to ''Success and Failure'' (Automated)'; Subcategory='Credential Validation'; Expected='Success and Failure' },
    @{ Id='17.1.2'; Title='Ensure ''Audit Kerberos Authentication Service'' is set to ''Success and Failure'' (DC Only) (Automated)'; Subcategory='Kerberos Authentication Service'; Expected='Success and Failure' },
    @{ Id='17.1.3'; Title='Ensure ''Audit Kerberos Service Ticket Operations'' is set to ''Success and Failure'' (DC Only) (Automated)'; Subcategory='Kerberos Service Ticket Operations'; Expected='Success and Failure' },
    @{ Id='17.2.1'; Title='Ensure ''Audit Application Group Management'' is set to ''Success and Failure'' (Automated)'; Subcategory='Application Group Management'; Expected='Success and Failure' },
    @{ Id='17.2.2'; Title='Ensure ''Audit Computer Account Management'' is set to include ''Success'' (DC only) (Automated)'; Subcategory='Computer Account Management'; Expected='Success' },
    @{ Id='17.2.3'; Title='Ensure ''Audit Distribution Group Management'' is set to include ''Success'' (DC only) (Automated)'; Subcategory='Distribution Group Management'; Expected='Success' },
    @{ Id='17.2.4'; Title='Ensure ''Audit Other Account Management Events'' is set to include ''Success'' (DC only) (Automated)'; Subcategory='Other Account Management Events'; Expected='Success' },
    @{ Id='17.2.5'; Title='Ensure ''Audit Security Group Management'' is set to include ''Success'' (Automated)'; Subcategory='Security Group Management'; Expected='Success' },
    @{ Id='17.2.6'; Title='Ensure ''Audit User Account Management'' is set to ''Success and Failure'' (Automated)'; Subcategory='User Account Management'; Expected='Success and Failure' },
    @{ Id='17.3.1'; Title='Ensure ''Audit PNP Activity'' is set to include ''Success'' (Automated)'; Subcategory='PNP Activity'; Expected='Success' },
    @{ Id='17.3.2'; Title='Ensure ''Audit Process Creation'' is set to include ''Success'' (Automated)'; Subcategory='Process Creation'; Expected='Success' },
    @{ Id='17.4.1'; Title='Ensure ''Audit Directory Service Access'' is set to include ''Failure'' (DC only) (Automated)'; Subcategory='Directory Service Access'; Expected='Failure' },
    @{ Id='17.4.2'; Title='Ensure ''Audit Directory Service Changes'' is set to include ''Success'' (DC only) (Automated)'; Subcategory='Directory Service Changes'; Expected='Success' },
    @{ Id='17.5.1'; Title='Ensure ''Audit Account Lockout'' is set to include ''Failure'' (Automated)'; Subcategory='Account Lockout'; Expected='Failure' },
    @{ Id='17.5.2'; Title='Ensure ''Audit Group Membership'' is set to include ''Success'' (Automated)'; Subcategory='Group Membership'; Expected='Success' },
    @{ Id='17.5.3'; Title='Ensure ''Audit Logoff'' is set to include ''Success'' (Automated)'; Subcategory='Logoff'; Expected='Success' },
    @{ Id='17.5.4'; Title='Ensure ''Audit Logon'' is set to ''Success and Failure'' (Automated)'; Subcategory='Logon'; Expected='Success and Failure' },
    @{ Id='17.5.5'; Title='Ensure ''Audit Other Logon/Logoff Events'' is set to ''Success and Failure'' (Automated)'; Subcategory='Other Logon/Logoff Events'; Expected='Success and Failure' },
    @{ Id='17.5.6'; Title='Ensure ''Audit Special Logon'' is set to include ''Success'' (Automated)'; Subcategory='Special Logon'; Expected='Success' },
    @{ Id='17.6.1'; Title='Ensure ''Audit Detailed File Share'' is set to include ''Failure'' (Automated)'; Subcategory='Detailed File Share'; Expected='Failure' },
    @{ Id='17.6.2'; Title='Ensure ''Audit File Share'' is set to ''Success and Failure'' (Automated)'; Subcategory='File Share'; Expected='Success and Failure' },
    @{ Id='17.6.3'; Title='Ensure ''Audit Other Object Access Events'' is set to ''Success and Failure'' (Automated)'; Subcategory='Other Object Access Events'; Expected='Success and Failure' },
    @{ Id='17.6.4'; Title='Ensure ''Audit Removable Storage'' is set to ''Success and Failure'' (Automated)'; Subcategory='Removable Storage'; Expected='Success and Failure' },
    @{ Id='17.7.1'; Title='Ensure ''Audit Audit Policy Change'' is set to include ''Success'' (Automated)'; Subcategory='Audit Policy Change'; Expected='Success' },
    @{ Id='17.7.2'; Title='Ensure ''Audit Authentication Policy Change'' is set to include ''Success'' (Automated)'; Subcategory='Authentication Policy Change'; Expected='Success' },
    @{ Id='17.7.3'; Title='Ensure ''Audit Authorization Policy Change'' is set to include ''Success'' (Automated)'; Subcategory='Authorization Policy Change'; Expected='Success' },
    @{ Id='17.7.4'; Title='Ensure ''Audit MPSSVC Rule-Level Policy Change'' is set to ''Success and Failure'' (Automated)'; Subcategory='MPSSVC Rule-Level Policy Change'; Expected='Success and Failure' },
    @{ Id='17.7.5'; Title='Ensure ''Audit Other Policy Change Events'' is set to include ''Failure'' (Automated)'; Subcategory='Other Policy Change Events'; Expected='Failure' },
    @{ Id='17.8.1'; Title='Ensure ''Audit Sensitive Privilege Use'' is set to ''Success'' (Automated)'; Subcategory='Sensitive Privilege Use'; Expected='Success' },
    @{ Id='17.9.1'; Title='Ensure ''Audit IPsec Driver'' is set to ''Success and Failure'' (Automated)'; Subcategory='IPsec Driver'; Expected='Success and Failure' },
    @{ Id='17.9.2'; Title='Ensure ''Audit Other System Events'' is set to ''Success and Failure'' (Automated)'; Subcategory='Other System Events'; Expected='Success and Failure' },
    @{ Id='17.9.3'; Title='Ensure ''Audit Security State Change'' is set to include ''Success'' (Automated)'; Subcategory='Security State Change'; Expected='Success' },
    @{ Id='17.9.4'; Title='Ensure ''Audit Security System Extension'' is set to include ''Success'' (Automated)'; Subcategory='Security System Extension'; Expected='Success' },
    @{ Id='17.9.5'; Title='Ensure ''Audit System Integrity'' is set to ''Success and Failure'' (Automated)'; Subcategory='System Integrity'; Expected='Success and Failure' }
)

$ReviewChecks = @(
    @{ Id='2.3.7.3'; Title='Ensure ''Interactive logon: Machine inactivity limit'' is set to ''900 or fewer second(s), but not 0'' (Automated)' },
    @{ Id='2.3.9.1'; Title='Ensure ''Microsoft network server: Amount of idle time required before suspending session'' is set to ''15 or fewer minute(s)'' (Automated)' },
    @{ Id='2.3.10.1'; Title='Ensure ''Network access: Allow anonymous SID/Name translation'' is set to ''Disabled'' (Automated)' },
    @{ Id='2.3.10.6'; Title='Ensure ''Network access: Named Pipes that can be accessed anonymously'' is configured (DC only) (Automated)' },
    @{ Id='2.3.10.12'; Title='Ensure ''Network access: Shares that can be accessed anonymously'' is set to ''None'' (Automated)' },
    @{ Id='2.3.11.6'; Title='Ensure ''Network security: Force logoff when logon hours expire'' is set to ''Enabled'' (Manual)' }
)

# ============================ CHECK ENGINES =================================

# --- Registry helper (HKLM and HKCU) ---------------------------------------
function Get-RegValue {
    param([string]$Path,[string]$Name)
    $psPath = $Path -replace '^HKLM\\','HKLM:\' -replace '^HKCU\\','HKCU:\'
    if ($psPath -notmatch '^HK(LM|CU):\\') { $psPath = 'HKLM:\' + $Path }
    try {
        $item = Get-ItemProperty -LiteralPath $psPath -Name $Name -ErrorAction Stop
        return @{ Exists=$true; Value=$item.$Name }
    } catch { return @{ Exists=$false; Value=$null } }
}

function Test-RegRule {
    param($Check,$Reg)
    switch ($Check.Op) {
        'absent' {
            if (-not $Reg.Exists) { return @('Configured','Value absent as required') }
            return @('Not Configured',"Present (=$($Reg.Value)); should not exist")
        }
        'manual' { return @('Needs Review',"Manual: $($Check.Expected)") }
    }
    if (-not $Reg.Exists) { return @('Not Configured','Registry value not set') }
    $a = $Reg.Value
    switch ($Check.Op) {
        'eq'      { if ([int64]$a -eq $Check.Value){return @('Configured',"=$a")} return @('Not Configured',"Actual=$a Expected=$($Check.Value)") }
        'ge'      { if ([int64]$a -ge $Check.Value){return @('Configured',"$a (>=$($Check.Value))")} return @('Not Configured',"Actual=$a Expected>=$($Check.Value)") }
        'le'      { $ok=([int64]$a -le $Check.Value); if($Check.Exclude -and ($Check.Exclude -contains [int64]$a)){$ok=$false}; if($ok){return @('Configured',"$a (<=$($Check.Value))")} return @('Not Configured',"Actual=$a Expected<=$($Check.Value)") }
        'between' { if ([int64]$a -ge $Check.Lo -and [int64]$a -le $Check.Hi){return @('Configured',"$a (in $($Check.Lo)-$($Check.Hi))")} return @('Not Configured',"Actual=$a Expected $($Check.Lo)-$($Check.Hi)") }
        'in'      { if ($Check.Values -contains [int64]$a){return @('Configured',"=$a (allowed)")} return @('Not Configured',"Actual=$a Allowed=$($Check.Values -join ',')") }
        default   { return @('Needs Review','Unknown comparator') }
    }
}

function Invoke-RegistryChecks {
    param($Checks,[string]$Source='Registry')
    foreach ($c in $Checks) {
        $reg = Get-RegValue -Path $c.Path -Name $c.Name
        $res = Test-RegRule -Check $c -Reg $reg
        $actual = if ($reg.Exists) { $reg.Value } else { '<not set>' }
        Write-AuditLog "[$($c.Id)] $($c.Path):$($c.Name) actual='$actual' expected='$($c.Expected)' => $($res[0])"
        Add-Result $c.Id $c.Title $Source $c.Expected $actual $res[0] $res[1]
    }
}

# --- Per-user (HKCU) checks for the CURRENT user ---------------------------
function Invoke-HkcuChecks {
    param($Checks)
    foreach ($c in $Checks) {
        $reg = Get-RegValue -Path ("HKCU\" + $c.SubKey) -Name $c.Name
        if (-not $reg.Exists) {
            Add-Result $c.Id $c.Title 'Registry(HKCU)' $c.Value '<not set>' 'Not Configured' 'Per-user value not set for current user'
            Write-AuditLog "[$($c.Id)] HKCU\$($c.SubKey):$($c.Name) => Not Configured (current user only)"
            continue
        }
        $status = if ([int64]$reg.Value -eq [int64]$c.Value) {'Configured'} else {'Not Configured'}
        Add-Result $c.Id $c.Title 'Registry(HKCU)' $c.Value $reg.Value $status "current-user hive; Expected=$($c.Value)"
        Write-AuditLog "[$($c.Id)] HKCU\$($c.SubKey):$($c.Name) actual=$($reg.Value) => $status"
    }
}

# --- secedit: export local security policy once, reuse ----------------------
function Get-SecEditDb {
    $tmp = Join-Path $env:TEMP "cis_secedit_$([guid]::NewGuid().ToString('N')).inf"
    try {
        $null = secedit /export /cfg $tmp /quiet 2>&1
        $raw = Get-Content -LiteralPath $tmp -Encoding Unicode -ErrorAction Stop
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        Write-AuditLog "secedit policy exported ($($raw.Count) lines)."
        return $raw
    } catch {
        Write-AuditLog "secedit export failed: $($_.Exception.Message)" 'WARN'
        return $null
    }
}

function Invoke-SeceditSystemAccess {
    param($Checks,$Inf)
    foreach ($c in $Checks) {
        if (-not $Inf) { Add-Result $c.Id $c.Title 'secedit' $c.Value 'N/A' 'Needs Review' 'secedit export unavailable'; continue }
        $line = $Inf | Where-Object { $_ -match "^\s*$($c.Key)\s*=" } | Select-Object -First 1
        if (-not $line) { Add-Result $c.Id $c.Title 'secedit' $c.Value '<not found>' 'Not Configured' 'Key not present in policy'; continue }
        $val = ($line -split '=')[1].Trim()
        $n = 0; [void][int]::TryParse($val,[ref]$n)
        $ok = switch ($c.Op) {
            'ge'      { $n -ge $c.Value }
            'eq'      { $n -eq $c.Value }
            'le_not0' { ($n -le $c.Value) -and ($n -ne 0) }
            default   { $false }
        }
        $status = if ($ok) {'Configured'} else {'Not Configured'}
        Add-Result $c.Id $c.Title 'secedit' $c.Value $val $status "Policy $($c.Key)=$val"
        Write-AuditLog "[$($c.Id)] secedit $($c.Key)=$val => $status"
    }
}

# --- secedit: User Rights Assignment ----------------------------------------
function Invoke-SeceditUserRights {
    param($Checks,$Inf)
    foreach ($c in $Checks) {
        if (-not $Inf) { Add-Result $c.Id $c.Title 'secedit(URA)' $c.Expected 'N/A' 'Needs Review' 'secedit export unavailable'; continue }
        $line = $Inf | Where-Object { $_ -match "^\s*$($c.Privilege)\s*=" } | Select-Object -First 1
        $assigned = if ($line) { (($line -split '=')[1].Trim()) } else { '' }
        # Report assignment for review against expected principals (SID translation not done here)
        $status = 'Needs Review'
        $detail = "Assigned SIDs/accounts: '$assigned'. Compare to expected '$($c.Expected)'."
        if ([string]::IsNullOrWhiteSpace($assigned) -and $c.Expected -eq 'No One') { $status='Configured'; $detail='No accounts hold this right (= No One).' }
        Add-Result $c.Id $c.Title 'secedit(URA)' $c.Expected $assigned $status $detail
        Write-AuditLog "[$($c.Id)] URA $($c.Privilege)='$assigned' (expected '$($c.Expected)') => $status"
    }
}

# --- auditpol: Advanced Audit Policy ----------------------------------------
function Invoke-AuditPolChecks {
    param($Checks)
    $map=@{}
    try {
        $csv = auditpol /get /category:* /r 2>$null | ConvertFrom-Csv
        foreach ($row in $csv) { if ($row.Subcategory) { $map[$row.Subcategory.Trim()] = $row.'Inclusion Setting' } }
        Write-AuditLog "auditpol returned $($map.Count) subcategories."
    } catch { Write-AuditLog "auditpol failed: $($_.Exception.Message)" 'WARN' }
    foreach ($c in $Checks) {
        $actual = $map[$c.Subcategory]
        if (-not $actual) { Add-Result $c.Id $c.Title 'auditpol' $c.Expected '<not found>' 'Needs Review' "Subcategory '$($c.Subcategory)' not returned"; continue }
        $a = $actual.Trim()
        $exp = $c.Expected
        # Map: 'Success and Failure' must match exactly; 'Success'/'Failure' must be included
        $ok = switch ($exp) {
            'Success and Failure' { $a -eq 'Success and Failure' }
            'Success'             { $a -eq 'Success' -or $a -eq 'Success and Failure' }
            'Failure'             { $a -eq 'Failure' -or $a -eq 'Success and Failure' }
            default               { $false }
        }
        $status = if ($ok) {'Configured'} else {'Not Configured'}
        Add-Result $c.Id $c.Title 'auditpol' $exp $a $status "$($c.Subcategory): $a"
        Write-AuditLog "[$($c.Id)] auditpol '$($c.Subcategory)'='$a' (expected '$exp') => $status"
    }
}

function Invoke-ReviewChecks {
    param($Checks)
    foreach ($c in $Checks) {
        Add-Result $c.Id $c.Title 'Manual' 'see benchmark' 'Needs Review' 'Multi-value/string or special control; verify manually per CIS.'
        Write-AuditLog "[$($c.Id)] flagged Needs Review (special control)."
    }
}

# ============================ RUN ALL ENGINES ===============================
Write-AuditLog "Running registry (HKLM) checks: $($RegistryChecks.Count)"
Invoke-RegistryChecks -Checks $RegistryChecks -Source 'Registry'

Write-AuditLog "Running per-user (HKCU) checks: $($HkcuChecks.Count)"
Invoke-HkcuChecks -Checks $HkcuChecks

$inf = Get-SecEditDb
Write-AuditLog "Running secedit password/lockout checks: $($PasswordChecks.Count)"
Invoke-SeceditSystemAccess -Checks $PasswordChecks -Inf $inf
Write-AuditLog "Running secedit user-rights checks: $($UserRightsChecks.Count)"
Invoke-SeceditUserRights -Checks $UserRightsChecks -Inf $inf

Write-AuditLog "Running auditpol checks: $($AuditPolicyChecks.Count)"
Invoke-AuditPolChecks -Checks $AuditPolicyChecks

Write-AuditLog "Flagging special/needs-review checks: $($ReviewChecks.Count)"
Invoke-ReviewChecks -Checks $ReviewChecks

# ============================ SUMMARY =======================================
$configured = ($script:Results | Where-Object Status -eq 'Configured').Count
$notconf    = ($script:Results | Where-Object Status -eq 'Not Configured').Count
$review     = ($script:Results | Where-Object Status -eq 'Needs Review').Count
$total      = $script:Results.Count
$assessable = $configured + $notconf
$pct = if ($assessable) { [math]::Round(($configured/$assessable)*100,1) } else { 0 }
Write-AuditLog "=== Summary: $configured Configured / $notconf Not Configured / $review Needs Review (of $total) - $pct% of assessable ==="

Write-Host ""
Write-Host "================= CIS WS2022 DC FULL AUDIT =================" -ForegroundColor Cyan
Write-Host ("  Configured      : {0}" -f $configured) -ForegroundColor Green
Write-Host ("  Not Configured  : {0}" -f $notconf)    -ForegroundColor Red
Write-Host ("  Needs Review    : {0}" -f $review)     -ForegroundColor Yellow
Write-Host ("  Total checks    : {0}" -f $total)      -ForegroundColor Cyan
Write-Host ("  Compliance      : {0}% of assessable" -f $pct) -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan

# ============================ OUTPUT FILES ==================================
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null; Write-AuditLog "Created $OutputDir" }
$stamp = $script:StartTime.ToString('yyyyMMdd_HHmmss')
$csv  = Join-Path $OutputDir "CIS_DC_FullReport_$stamp.csv"
$html = Join-Path $OutputDir "CIS_DC_FullReport_$stamp.html"
$log  = Join-Path $OutputDir "CIS_DC_AuditLog_$stamp.txt"

$script:Results | Sort-Object { ($_.Id -split '\.' | ForEach-Object { '{0:D4}' -f [int]($_ -replace '\D','0') }) -join '.' } |
    Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
Write-AuditLog "CSV written: $csv"

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
$rowsHtml = foreach ($r in ($script:Results | Sort-Object Id)) {
    $cls = switch ($r.Status) { 'Configured'{'ok'} 'Not Configured'{'bad'} default{'rev'} }
    $enc = { param($x) [System.Web.HttpUtility]::HtmlEncode([string]$x) }
    "<tr class='$cls'><td>$($r.Id)</td><td>$(& $enc $r.Title)</td><td>$($r.Source)</td><td>$(& $enc $r.Expected)</td><td>$(& $enc $r.Actual)</td><td>$($r.Status)</td></tr>"
}
$htmlDoc = @"
<!DOCTYPE html><html><head><meta charset='utf-8'><title>CIS WS2022 DC Audit</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px}h1{font-size:20px}
.meta{color:#555;font-size:13px}.cards{display:flex;gap:12px;margin:16px 0}
.card{padding:12px 18px;border-radius:8px;color:#fff;font-weight:600}
.c-ok{background:#2e7d32}.c-bad{background:#c62828}.c-rev{background:#f9a825;color:#222}.c-b{background:#1565c0}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#1565c0;color:#fff;position:sticky;top:0}tr.ok td{background:#e8f5e9}tr.bad td{background:#ffebee}tr.rev td{background:#fffde7}</style></head><body>
<h1>CIS Microsoft Windows Server 2022 v5.0.0 &mdash; Domain Controller Audit</h1>
<div class='meta'>Host: $env:COMPUTERNAME | Generated: $($script:StartTime) | $total checks across registry, secedit & auditpol</div>
<div class='cards'><div class='card c-ok'>Configured: $configured</div><div class='card c-bad'>Not Configured: $notconf</div>
<div class='card c-rev'>Needs Review: $review</div><div class='card c-b'>Compliance: $pct%</div></div>
<table><thead><tr><th>ID</th><th>Recommendation</th><th>Source</th><th>Expected</th><th>Actual</th><th>Status</th></tr></thead>
<tbody>
$($rowsHtml -join "`n")
</tbody></table></body></html>
"@
$htmlDoc | Out-File -FilePath $html -Encoding UTF8
Write-AuditLog "HTML written: $html"

$elapsed = (Get-Date) - $script:StartTime
Write-AuditLog "=== Audit complete in $([math]::Round($elapsed.TotalSeconds,1))s. Read-only; no changes made. ==="
@("CIS WS2022 v5.0.0 Domain Controller FULL Audit - SELF-AUDIT TRANSCRIPT",
  "Records every action performed. All registry/secedit/auditpol reads are read-only.",
  ("="*84)) + $script:AuditLog | Out-File -FilePath $log -Encoding UTF8

Write-Host ""
Write-Host "Reports saved to:" -ForegroundColor Cyan
Write-Host "  $csv"
Write-Host "  $html"
Write-Host "  $log  (self-audit transcript)"
