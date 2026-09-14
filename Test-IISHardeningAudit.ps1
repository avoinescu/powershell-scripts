<#
.SYNOPSIS
    Read-only IIS hardening / security baseline audit.

.DESCRIPTION
    Audits a Windows Server IIS installation against a set of hardening
    checks (TLS protocols/ciphers, certificates including bound-cert
    validity, HTTPS bindings, authentication, logging, content location,
    NTFS permissions, application pool identity, HTTP TRACE, security
    headers, SIEM agent presence, ASP.NET debug/customErrors config, and
    Windows patch age) and reports PASS / FAIL / NEEDS REVIEW / INFO per
    control.

    This script performs NO modifications. Every check is read-only
    (Get-*, Test-Path). Nothing is Set, New, Removed, Enabled, or Disabled.

.PARAMETER SiteName
    Optional. Restrict the per-site checks (bindings, auth, logging,
    content location, NTFS, ASP.NET config) to one or more site names.
    Defaults to all sites returned by Get-Website.

.PARAMETER RequireWindowsAuth
    Optional switch. Windows Authentication is only expected on
    intranet / SSO-integrated apps, not on public-facing sites, so by
    default the script reports its state as INFO without judging it.
    Set this switch to instead flag disabled Windows Auth as NEEDS REVIEW.

.PARAMETER ExportPath
    Optional. Folder to export the full results as CSV and HTML
    (e.g. C:\Audits). Created if it doesn't exist. If omitted, results
    are only written to the console. This is the only way the script
    writes anything to disk, and it never touches IIS or Windows config.

.EXAMPLE
    .\Test-IISHardeningAudit.ps1

.EXAMPLE
    .\Test-IISHardeningAudit.ps1 -SiteName "Default Web Site","Intranet App" -RequireWindowsAuth -ExportPath C:\Audits

.NOTES
    Run from an elevated, 64-bit, Windows PowerShell 5.1 session (not
    PowerShell 7 — the WebAdministration module is a legacy binary
    module and its IIS: provider generally does not register cleanly
    under pwsh). Under 32-bit PowerShell on a 64-bit OS,
    HKLM:\SOFTWARE\Microsoft\InetStp can also be WOW6432Node-redirected
    and misreport the IIS version.

    Forced read-only: this script declares SupportsShouldProcess and
    sets $WhatIfPreference = $true itself, so any ShouldProcess-aware
    cmdlet (Set-*/New-*/Remove-*/Enable-*/Disable-*) added here later —
    by accident or otherwise — no-ops and reports what it would have
    done instead of running. This script calls none of those today; the
    setting is defense in depth, not a fix for a real problem.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string[]]$SiteName,
    [switch]$RequireWindowsAuth,
    [string]$ExportPath
)

Set-StrictMode -Version Latest
$WhatIfPreference = $true

Import-Module WebAdministration -ErrorAction SilentlyContinue

$WebAdminAvailable = [bool](Get-Module WebAdministration)

if (-not $WebAdminAvailable) {
    Write-Host ""
    Write-Host "WARNING: The WebAdministration module/provider did not load." -ForegroundColor Red
    Write-Host "  All IIS-dependent checks below will report NEEDS REVIEW (or a" -ForegroundColor Yellow
    Write-Host "  misleading PASS, e.g. 'Default Web Site: Not Present') until this" -ForegroundColor Yellow
    Write-Host "  is resolved. Most common causes, in order of likelihood:" -ForegroundColor Yellow
    Write-Host "    1. This session is not elevated (Run as Administrator)." -ForegroundColor Yellow
    Write-Host "    2. This is PowerShell 7 (pwsh), not Windows PowerShell 5.1." -ForegroundColor Yellow
    Write-Host "       Check with: `$PSVersionTable.PSEdition  (must say 'Desktop')" -ForegroundColor Yellow
    Write-Host "    3. The 'IIS Management Scripts and Tools' feature isn't installed." -ForegroundColor Yellow
    Write-Host ""
}

$Results = @()

function Write-AuditResult {
    param(
        [string]$Control,
        [string]$Status,
        [string]$Details
    )

    $script:Results += [PSCustomObject]@{
        Control = $Control
        Status  = $Status
        Details = $Details
    }
}

Write-Host "Running IIS Hardening Audit..." -ForegroundColor Cyan

# =====================================================
# IIS VERSION
# =====================================================

try {
    $iis = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp
    Write-AuditResult "IIS Version" "PASS" $iis.VersionString
}
catch {
    Write-AuditResult "IIS Version" "NEEDS REVIEW" $_.Exception.Message
}

# =====================================================
# DEFAULT WEBSITE
# =====================================================

try {
    $site = Get-Website "Default Web Site" -ErrorAction Stop

    if ($site.State -eq "Stopped") {
        Write-AuditResult "Default Web Site" "PASS" "Stopped"
    }
    else {
        Write-AuditResult "Default Web Site" "FAIL" "Running"
    }
}
catch {
    Write-AuditResult "Default Web Site" "PASS" "Not Present"
}

# =====================================================
# DIRECTORY BROWSING
# =====================================================

try {
    $dirBrowsing = Get-WebConfigurationProperty `
        -Filter "/system.webServer/directoryBrowse" `
        -Name enabled

    if ($dirBrowsing.Value -eq $false) {
        Write-AuditResult "Directory Browsing" "PASS" "Disabled"
    }
    else {
        Write-AuditResult "Directory Browsing" "FAIL" "Enabled"
    }
}
catch {
    Write-AuditResult "Directory Browsing" "NEEDS REVIEW" "Unable to determine"
}

# =====================================================
# TLS SETTINGS
# =====================================================

$ProtocolBase =
"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

function Get-TLSState {

    param([string]$Protocol)

    $Key = Join-Path $ProtocolBase "$Protocol\Server"

    if (Test-Path $Key) {

        try {
            return (Get-ItemProperty $Key).Enabled
        }
        catch {
            return $null
        }
    }

    return $null
}

$tls10 = Get-TLSState "TLS 1.0"
$tls11 = Get-TLSState "TLS 1.1"
$tls12 = Get-TLSState "TLS 1.2"
$tls13 = Get-TLSState "TLS 1.3"

if ($tls10 -eq 0) {
    Write-AuditResult "TLS 1.0" "PASS" "Disabled"
}
else {
    Write-AuditResult "TLS 1.0" "FAIL" "Enabled"
}

if ($tls11 -eq 0) {
    Write-AuditResult "TLS 1.1" "PASS" "Disabled"
}
else {
    Write-AuditResult "TLS 1.1" "NEEDS REVIEW" "Enabled"
}

if ($tls12 -ne 0) {
    Write-AuditResult "TLS 1.2" "PASS" "Enabled"
}
else {
    Write-AuditResult "TLS 1.2" "FAIL" "Disabled"
}

if ($tls13 -ne 0 -or $null -eq $tls13) {
    Write-AuditResult "TLS 1.3" "PASS" "Available"
}
else {
    Write-AuditResult "TLS 1.3" "NEEDS REVIEW" "Disabled"
}

# =====================================================
# HTTPS BINDINGS
# =====================================================

try {

    $https = @(Get-WebBinding -Protocol https)

    if ($https.Count -gt 0) {
        Write-AuditResult "HTTPS Bindings" "PASS" "$($https.Count) Binding(s)"
    }
    else {
        Write-AuditResult "HTTPS Bindings" "FAIL" "None Found"
    }
}
catch {
    Write-AuditResult "HTTPS Bindings" "NEEDS REVIEW" "Unable to verify"
}

# =====================================================
# WEAK CIPHERS
# =====================================================

try {

    $ciphers = Get-TlsCipherSuite

    if ($ciphers.Name -match "RC4") {
        Write-AuditResult "RC4 Cipher" "FAIL" "Detected"
    }
    else {
        Write-AuditResult "RC4 Cipher" "PASS" "Not Detected"
    }

    if ($ciphers.Name -match "DES|3DES") {
        Write-AuditResult "DES/3DES Cipher" "FAIL" "Detected"
    }
    else {
        Write-AuditResult "DES/3DES Cipher" "PASS" "Not Detected"
    }
}
catch {
    Write-AuditResult "Weak Cipher Audit" "NEEDS REVIEW" "Get-TlsCipherSuite unavailable"
}

# =====================================================
# CERTIFICATES (full LocalMachine\My store)
# =====================================================

try {

    Get-ChildItem Cert:\LocalMachine\My |
    ForEach-Object {

        $DaysLeft = ($_.NotAfter - (Get-Date)).Days

        if ($DaysLeft -lt 0) {

            Write-AuditResult `
            "Certificate $($_.Subject)" `
            "FAIL" `
            "Expired"

        } elseif ($DaysLeft -lt 30) {

            Write-AuditResult `
            "Certificate $($_.Subject)" `
            "NEEDS REVIEW" `
            "$DaysLeft Days Left"

        }
        else {

            Write-AuditResult `
            "Certificate $($_.Subject)" `
            "PASS" `
            "$DaysLeft Days Left"

        }
    }

}
catch {
    Write-AuditResult "Certificate Audit" "NEEDS REVIEW" "Unable to Read Store"
}

# =====================================================
# WINDOWS PATCHING
# =====================================================

try {

    $LastPatch =
    Get-HotFix |
    Sort-Object InstalledOn -Descending |
    Select-Object -First 1

    $PatchAge =
    ((Get-Date) - $LastPatch.InstalledOn).Days

    if ($PatchAge -le 45) {

        Write-AuditResult `
        "Windows Patch Level" `
        "PASS" `
        "Last patch $($LastPatch.InstalledOn.ToShortDateString())"

    }
    else {

        Write-AuditResult `
        "Windows Patch Level" `
        "FAIL" `
        "Patch age $PatchAge days"

    }
}
catch {
    Write-AuditResult "Windows Patch Level" "NEEDS REVIEW" "Unable to Determine"
}

# =====================================================
# WEBSITE AUDITS
# =====================================================

$SitesToAudit = if ($SiteName) {
    Get-Website | Where-Object { $_.Name -in $SiteName }
}
else {
    Get-Website
}

foreach ($Site in $SitesToAudit) {

    $CurrentSiteName = $Site.Name

    $Bindings = Get-WebBinding -Name $CurrentSiteName

    # ----------------------------------------------
    # Host Header Bindings
    # ----------------------------------------------

    foreach ($Binding in $Bindings) {

        if ($Binding.bindingInformation -match '\*\:\d+\:$') {

            Write-AuditResult `
            "$CurrentSiteName Host Header" `
            "FAIL" `
            $Binding.bindingInformation
        }
        else {

            Write-AuditResult `
            "$CurrentSiteName Host Header" `
            "PASS" `
            $Binding.bindingInformation
        }
    }

    # ----------------------------------------------
    # Bound Certificate Validity (per HTTPS binding)
    # ----------------------------------------------

    $HttpsBindings = $Bindings | Where-Object { $_.protocol -eq "https" }

    foreach ($HttpsBinding in $HttpsBindings) {

        try {
            $Hash = $HttpsBinding.certificateHash

            if ([string]::IsNullOrEmpty($Hash)) {
                Write-AuditResult `
                "$CurrentSiteName Bound Certificate" `
                "FAIL" `
                "No certificate bound ($($HttpsBinding.bindingInformation))"
                continue
            }

            $BoundCert = Get-ChildItem Cert:\LocalMachine\My |
                Where-Object { $_.Thumbprint -eq $Hash }

            if (-not $BoundCert) {
                Write-AuditResult `
                "$CurrentSiteName Bound Certificate" `
                "NEEDS REVIEW" `
                "Bound cert hash $Hash not found in LocalMachine\My"
            }
            elseif ($BoundCert.NotAfter -lt (Get-Date)) {
                Write-AuditResult `
                "$CurrentSiteName Bound Certificate" `
                "FAIL" `
                "Expired $($BoundCert.NotAfter.ToShortDateString())"
            }
            else {
                Write-AuditResult `
                "$CurrentSiteName Bound Certificate" `
                "PASS" `
                "Valid until $($BoundCert.NotAfter.ToShortDateString())"
            }
        }
        catch {
            Write-AuditResult `
            "$CurrentSiteName Bound Certificate" `
            "NEEDS REVIEW" `
            "Unable to cross-reference bound certificate"
        }
    }

    # ----------------------------------------------
    # Authentication
    # ----------------------------------------------

    try {

        $Anon =
        Get-WebConfigurationProperty `
        -Location $CurrentSiteName `
        -Filter system.webServer/security/authentication/anonymousAuthentication `
        -Name enabled

        if ($Anon.Value -eq $false) {
            Write-AuditResult "$CurrentSiteName Anonymous Auth" "PASS" "Disabled"
        }
        else {
            Write-AuditResult "$CurrentSiteName Anonymous Auth" "NEEDS REVIEW" "Enabled"
        }

    }
    catch {}

    try {

        $WinAuth =
        Get-WebConfigurationProperty `
        -Location $CurrentSiteName `
        -Filter system.webServer/security/authentication/windowsAuthentication `
        -Name enabled

        if ($RequireWindowsAuth) {

            if ($WinAuth.Value -eq $true) {
                Write-AuditResult "$CurrentSiteName Windows Auth" "PASS" "Enabled"
            }
            else {
                Write-AuditResult "$CurrentSiteName Windows Auth" "NEEDS REVIEW" "Disabled"
            }
        }
        else {
            # No assumption about whether this site should use Windows
            # Auth (only relevant for intranet/SSO apps) — informational only.
            $State = if ($WinAuth.Value -eq $true) { "Enabled" } else { "Disabled" }
            Write-AuditResult "$CurrentSiteName Windows Auth" "INFO" $State
        }

    }
    catch {}

    # ----------------------------------------------
    # Logging
    # ----------------------------------------------

    try {

        if ($Site.logFile.enabled) {
            Write-AuditResult "$CurrentSiteName Logging" "PASS" "Enabled"
        }
        else {
            Write-AuditResult "$CurrentSiteName Logging" "FAIL" "Disabled"
        }

    }
    catch {}

    # ----------------------------------------------
    # Content Location
    # ----------------------------------------------

    if ($Site.PhysicalPath -match "^C:\\inetpub\\wwwroot") {

        Write-AuditResult `
        "$CurrentSiteName Content Location" `
        "FAIL" `
        $Site.PhysicalPath

    }
    else {

        Write-AuditResult `
        "$CurrentSiteName Content Location" `
        "PASS" `
        $Site.PhysicalPath
    }

    # ----------------------------------------------
    # NTFS
    # ----------------------------------------------

    try {

        if (Test-Path $Site.PhysicalPath) {

            $Acl = Get-Acl $Site.PhysicalPath

            $BadEntries = $Acl.Access |
            Where-Object {

                $_.IdentityReference -match
                "Everyone|Users|Authenticated Users" `
                -and
                $_.FileSystemRights -match
                "FullControl|Modify"

            }

            if ($BadEntries) {

                Write-AuditResult `
                "$CurrentSiteName NTFS Permissions" `
                "FAIL" `
                "Broad permissions detected"
            }
            else {

                Write-AuditResult `
                "$CurrentSiteName NTFS Permissions" `
                "PASS" `
                "No obvious issues"
            }
        }

    }
    catch {
        Write-AuditResult "$CurrentSiteName NTFS Permissions" `
        "NEEDS REVIEW" `
        "Unable to read ACL"
    }
}

# =====================================================
# APPLICATION POOLS
# =====================================================

Get-ChildItem IIS:\AppPools |
ForEach-Object {

    $Pool = $_.Name
    $Identity = $_.processModel.identityType

    if ($Identity -eq "ApplicationPoolIdentity") {

        Write-AuditResult `
        "App Pool [$Pool]" `
        "PASS" `
        $Identity
    }
    else {

        Write-AuditResult `
        "App Pool [$Pool]" `
        "FAIL" `
        $Identity
    }
}

# =====================================================
# TRACE
# =====================================================

try {

    $TraceFound = $false

    $Verbs =
    Get-WebConfiguration `
    -Filter "system.webServer/security/requestFiltering/verbs"

    foreach ($Verb in $Verbs.Collection) {

        if ($Verb.verb -eq "TRACE" -and
           $Verb.allowed -eq $true) {

            $TraceFound = $true
        }

    }

    if ($TraceFound) {
        Write-AuditResult "HTTP TRACE" "FAIL" "Enabled"
    }
    else {
        Write-AuditResult "HTTP TRACE" "PASS" "Disabled"
    }
}
catch {
    Write-AuditResult "HTTP TRACE" "NEEDS REVIEW" "Unable to Verify"
}

# =====================================================
# SECURITY HEADERS
# =====================================================

try {

    $Headers =
    Get-WebConfigurationProperty `
    -Filter "system.webServer/httpProtocol/customHeaders/add" `
    -Name "."

    function HeaderExists($HeaderName) {

        return $Headers |
        Where-Object {$_.Name -eq $HeaderName}
    }

    if (HeaderExists "Strict-Transport-Security") {
        Write-AuditResult "HSTS" "PASS" "Configured"
    }
    else {
        Write-AuditResult "HSTS" "FAIL" "Missing"
    }

    if (HeaderExists "X-Frame-Options") {
        Write-AuditResult "X-Frame-Options" "PASS" "Configured"
    }
    else {
        Write-AuditResult "X-Frame-Options" "FAIL" "Missing"
    }

    if (HeaderExists "X-Content-Type-Options") {
        Write-AuditResult "X-Content-Type-Options" "PASS" "Configured"
    }
    else {
        Write-AuditResult "X-Content-Type-Options" "FAIL" "Missing"
    }

    if (HeaderExists "Content-Security-Policy") {
        Write-AuditResult "Content-Security-Policy" "PASS" "Configured"
    }
    else {
        Write-AuditResult "Content-Security-Policy" "NEEDS REVIEW" "Missing"
    }

}
catch {
    Write-AuditResult "Security Headers" `
    "NEEDS REVIEW" `
    "Unable To Read"
}

# =====================================================
# SPLUNK / SIEM
# =====================================================

$SIEMServices = @(
"SplunkForwarder",
"HealthService",
"AzureMonitorAgent"
)

foreach ($ServiceName in $SIEMServices) {

    $Service =
    Get-Service $ServiceName `
    -ErrorAction SilentlyContinue

    if ($Service) {

        if ($Service.Status -eq "Running") {

            Write-AuditResult `
            "SIEM Agent $ServiceName" `
            "PASS" `
            "Running"

        }
        else {

            Write-AuditResult `
            "SIEM Agent $ServiceName" `
            "FAIL" `
            "Stopped"
        }
    }
}

# =====================================================
# ASP.NET CONFIG REVIEW
# =====================================================

$SitesToAudit | ForEach-Object {

    $CurrentSiteName = $_.Name
    $Path = $_.PhysicalPath

    try {

        Get-ChildItem `
        -Path $Path `
        -Filter web.config `
        -Recurse `
        -ErrorAction SilentlyContinue |
        ForEach-Object {

            try {

                [xml]$Config =
                Get-Content $_.FullName

                $Debug =
                $Config.configuration.'system.web'.compilation.debug

                if ($Debug -eq "false") {

                    Write-AuditResult `
                    "$CurrentSiteName ASP.NET Debug" `
                    "PASS" `
                    $_.FullName
                }
                elseif ($Debug) {

                    Write-AuditResult `
                    "$CurrentSiteName ASP.NET Debug" `
                    "FAIL" `
                    $_.FullName
                }

                $CustomErrors =
                $Config.configuration.'system.web'.customErrors.mode

                switch ($CustomErrors) {

                    "On" {
                        Write-AuditResult `
                        "$CurrentSiteName Custom Errors" `
                        "PASS" `
                        "On"
                    }

                    "RemoteOnly" {
                        Write-AuditResult `
                        "$CurrentSiteName Custom Errors" `
                        "PASS" `
                        "RemoteOnly"
                    }

                    "Off" {
                        Write-AuditResult `
                        "$CurrentSiteName Custom Errors" `
                        "FAIL" `
                        "Off"
                    }
                }

            }
            catch {}
        }

    }
    catch {}
}

# =====================================================
# REPORT
# =====================================================

$Pass =
@($Results | Where-Object Status -eq "PASS").Count

$Fail =
@($Results | Where-Object Status -eq "FAIL").Count

$Review =
@($Results | Where-Object Status -eq "NEEDS REVIEW").Count

$Total = $Results.Count

$Compliance = if ($Total -gt 0) {
    [Math]::Round((($Pass / $Total) * 100), 2)
}
else {
    0
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "           IIS HARDENING AUDIT REPORT"
Write-Host "==================================================" -ForegroundColor Cyan

$Results |
Sort-Object Status,Control |
Format-Table -AutoSize

Write-Host ""
Write-Host "Summary" -ForegroundColor Yellow
Write-Host "PASS          : $Pass" -ForegroundColor Green
Write-Host "FAIL          : $Fail" -ForegroundColor Red
Write-Host "NEEDS REVIEW  : $Review" -ForegroundColor Yellow
Write-Host "Compliance %  : $Compliance"

Write-Host ""
Write-Host "Critical Findings" -ForegroundColor Red

$Results |
Where-Object Status -eq "FAIL" |
Format-Table -AutoSize

# =====================================================
# EXPORT (optional — writes report files only, never touches IIS/Windows config)
# =====================================================

if ($ExportPath) {

    try {

        if (-not (Test-Path $ExportPath)) {
            New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        }

        $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $CsvPath = Join-Path $ExportPath "IISHardeningAudit-$Timestamp.csv"
        $HtmlPath = Join-Path $ExportPath "IISHardeningAudit-$Timestamp.html"

        $Results | Sort-Object Status,Control | Export-Csv -Path $CsvPath -NoTypeInformation

        $Results |
        Sort-Object Status,Control |
        ConvertTo-Html `
            -Title "IIS Hardening Audit Report" `
            -PreContent "<h1>IIS Hardening Audit Report</h1><p>Compliance: $Compliance% ($Pass PASS / $Fail FAIL / $Review NEEDS REVIEW of $Total checks)</p>" |
        Out-File -FilePath $HtmlPath

        Write-Host ""
        Write-Host "Report exported to:" -ForegroundColor Cyan
        Write-Host "  $CsvPath"
        Write-Host "  $HtmlPath"
    }
    catch {
        Write-Host ""
        Write-Host "Export failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}
