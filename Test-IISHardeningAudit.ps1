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
    Run from an elevated, 64-bit PowerShell session. Under 32-bit
    PowerShell on a 64-bit OS, HKLM:\SOFTWARE\Microsoft\InetStp can be
    WOW6432Node-redirected and misreport the IIS version.
#>

[CmdletBinding()]
param(
    [string[]]$SiteName,
    [switch]$RequireWindowsAuth,
    [string]$ExportPath
)

Set-StrictMode -Version Latest
$WhatIfPreference = $true

Import-Module WebAdministration -ErrorAction SilentlyContinue

$Results = @()

function Add-Result {
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
    Add-Result "IIS Version" "PASS" $iis.VersionString
}
catch {
    Add-Result "IIS Version" "NEEDS REVIEW" $_.Exception.Message
}

# =====================================================
# DEFAULT WEBSITE
# =====================================================

try {
    $site = Get-Website "Default Web Site" -ErrorAction Stop

    if ($site.State -eq "Stopped") {
        Add-Result "Default Web Site" "PASS" "Stopped"
    }
    else {
        Add-Result "Default Web Site" "FAIL" "Running"
    }
}
catch {
    Add-Result "Default Web Site" "PASS" "Not Present"
}

# =====================================================
# DIRECTORY BROWSING
# =====================================================

try {
    $dirBrowsing = Get-WebConfigurationProperty `
        -Filter "/system.webServer/directoryBrowse" `
        -Name enabled

    if ($dirBrowsing.Value -eq $false) {
        Add-Result "Directory Browsing" "PASS" "Disabled"
    }
    else {
        Add-Result "Directory Browsing" "FAIL" "Enabled"
    }
}
catch {
    Add-Result "Directory Browsing" "NEEDS REVIEW" "Unable to determine"
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
    Add-Result "TLS 1.0" "PASS" "Disabled"
}
else {
    Add-Result "TLS 1.0" "FAIL" "Enabled"
}

if ($tls11 -eq 0) {
    Add-Result "TLS 1.1" "PASS" "Disabled"
}
else {
    Add-Result "TLS 1.1" "NEEDS REVIEW" "Enabled"
}

if ($tls12 -ne 0) {
    Add-Result "TLS 1.2" "PASS" "Enabled"
}
else {
    Add-Result "TLS 1.2" "FAIL" "Disabled"
}

if ($tls13 -ne 0 -or $null -eq $tls13) {
    Add-Result "TLS 1.3" "PASS" "Available"
}
else {
    Add-Result "TLS 1.3" "NEEDS REVIEW" "Disabled"
}

# =====================================================
# HTTPS BINDINGS
# =====================================================

try {

    $https = Get-WebBinding -Protocol https

    if ($https.Count -gt 0) {
        Add-Result "HTTPS Bindings" "PASS" "$($https.Count) Binding(s)"
    }
    else {
        Add-Result "HTTPS Bindings" "FAIL" "None Found"
    }
}
catch {
    Add-Result "HTTPS Bindings" "NEEDS REVIEW" "Unable to verify"
}

# =====================================================
# WEAK CIPHERS
# =====================================================

try {

    $ciphers = Get-TlsCipherSuite

    if ($ciphers.Name -match "RC4") {
        Add-Result "RC4 Cipher" "FAIL" "Detected"
    }
    else {
        Add-Result "RC4 Cipher" "PASS" "Not Detected"
    }

    if ($ciphers.Name -match "DES|3DES") {
        Add-Result "DES/3DES Cipher" "FAIL" "Detected"
    }
    else {
        Add-Result "DES/3DES Cipher" "PASS" "Not Detected"
    }
}
catch {
    Add-Result "Weak Cipher Audit" "NEEDS REVIEW" "Get-TlsCipherSuite unavailable"
}

# =====================================================
# CERTIFICATES (full LocalMachine\My store)
# =====================================================

try {

    Get-ChildItem Cert:\LocalMachine\My |
    ForEach-Object {

        $DaysLeft = ($_.NotAfter - (Get-Date)).Days

        if ($DaysLeft -lt 0) {

            Add-Result `
            "Certificate $($_.Subject)" `
            "FAIL" `
            "Expired"

        } elseif ($DaysLeft -lt 30) {

            Add-Result `
            "Certificate $($_.Subject)" `
            "NEEDS REVIEW" `
            "$DaysLeft Days Left"

        }
        else {

            Add-Result `
            "Certificate $($_.Subject)" `
            "PASS" `
            "$DaysLeft Days Left"

        }
    }

}
catch {
    Add-Result "Certificate Audit" "NEEDS REVIEW" "Unable to Read Store"
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

        Add-Result `
        "Windows Patch Level" `
        "PASS" `
        "Last patch $($LastPatch.InstalledOn.ToShortDateString())"

    }
    else {

        Add-Result `
        "Windows Patch Level" `
        "FAIL" `
        "Patch age $PatchAge days"

    }
}
catch {
    Add-Result "Windows Patch Level" "NEEDS REVIEW" "Unable to Determine"
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

            Add-Result `
            "$CurrentSiteName Host Header" `
            "FAIL" `
            $Binding.bindingInformation
        }
        else {

            Add-Result `
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
                Add-Result `
                "$CurrentSiteName Bound Certificate" `
                "FAIL" `
                "No certificate bound ($($HttpsBinding.bindingInformation))"
                continue
            }

            $BoundCert = Get-ChildItem Cert:\LocalMachine\My |
                Where-Object { $_.Thumbprint -eq $Hash }

            if (-not $BoundCert) {
                Add-Result `
                "$CurrentSiteName Bound Certificate" `
                "NEEDS REVIEW" `
                "Bound cert hash $Hash not found in LocalMachine\My"
            }
            elseif ($BoundCert.NotAfter -lt (Get-Date)) {
                Add-Result `
                "$CurrentSiteName Bound Certificate" `
                "FAIL" `
                "Expired $($BoundCert.NotAfter.ToShortDateString())"
            }
            else {
                Add-Result `
                "$CurrentSiteName Bound Certificate" `
                "PASS" `
                "Valid until $($BoundCert.NotAfter.ToShortDateString())"
            }
        }
        catch {
            Add-Result `
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
            Add-Result "$CurrentSiteName Anonymous Auth" "PASS" "Disabled"
        }
        else {
            Add-Result "$CurrentSiteName Anonymous Auth" "NEEDS REVIEW" "Enabled"
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
                Add-Result "$CurrentSiteName Windows Auth" "PASS" "Enabled"
            }
            else {
                Add-Result "$CurrentSiteName Windows Auth" "NEEDS REVIEW" "Disabled"
            }
        }
        else {
            # No assumption about whether this site should use Windows
            # Auth (only relevant for intranet/SSO apps) — informational only.
            $State = if ($WinAuth.Value -eq $true) { "Enabled" } else { "Disabled" }
            Add-Result "$CurrentSiteName Windows Auth" "INFO" $State
        }

    }
    catch {}

    # ----------------------------------------------
    # Logging
    # ----------------------------------------------

    try {

        if ($Site.logFile.enabled) {
            Add-Result "$CurrentSiteName Logging" "PASS" "Enabled"
        }
        else {
            Add-Result "$CurrentSiteName Logging" "FAIL" "Disabled"
        }

    }
    catch {}

    # ----------------------------------------------
    # Content Location
    # ----------------------------------------------

    if ($Site.PhysicalPath -match "^C:\\inetpub\\wwwroot") {

        Add-Result `
        "$CurrentSiteName Content Location" `
        "FAIL" `
        $Site.PhysicalPath

    }
    else {

        Add-Result `
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

                Add-Result `
                "$CurrentSiteName NTFS Permissions" `
                "FAIL" `
                "Broad permissions detected"
            }
            else {

                Add-Result `
                "$CurrentSiteName NTFS Permissions" `
                "PASS" `
                "No obvious issues"
            }
        }

    }
    catch {
        Add-Result "$CurrentSiteName NTFS Permissions" `
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

        Add-Result `
        "App Pool [$Pool]" `
        "PASS" `
        $Identity
    }
    else {

        Add-Result `
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
        Add-Result "HTTP TRACE" "FAIL" "Enabled"
    }
    else {
        Add-Result "HTTP TRACE" "PASS" "Disabled"
    }
}
catch {
    Add-Result "HTTP TRACE" "NEEDS REVIEW" "Unable to Verify"
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
        Add-Result "HSTS" "PASS" "Configured"
    }
    else {
        Add-Result "HSTS" "FAIL" "Missing"
    }

    if (HeaderExists "X-Frame-Options") {
        Add-Result "X-Frame-Options" "PASS" "Configured"
    }
    else {
        Add-Result "X-Frame-Options" "FAIL" "Missing"
    }

    if (HeaderExists "X-Content-Type-Options") {
        Add-Result "X-Content-Type-Options" "PASS" "Configured"
    }
    else {
        Add-Result "X-Content-Type-Options" "FAIL" "Missing"
    }

    if (HeaderExists "Content-Security-Policy") {
        Add-Result "Content-Security-Policy" "PASS" "Configured"
    }
    else {
        Add-Result "Content-Security-Policy" "NEEDS REVIEW" "Missing"
    }

}
catch {
    Add-Result "Security Headers" `
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

            Add-Result `
            "SIEM Agent $ServiceName" `
            "PASS" `
            "Running"

        }
        else {

            Add-Result `
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

                    Add-Result `
                    "$CurrentSiteName ASP.NET Debug" `
                    "PASS" `
                    $_.FullName
                }
                elseif ($Debug) {

                    Add-Result `
                    "$CurrentSiteName ASP.NET Debug" `
                    "FAIL" `
                    $_.FullName
                }

                $CustomErrors =
                $Config.configuration.'system.web'.customErrors.mode

                switch ($CustomErrors) {

                    "On" {
                        Add-Result `
                        "$CurrentSiteName Custom Errors" `
                        "PASS" `
                        "On"
                    }

                    "RemoteOnly" {
                        Add-Result `
                        "$CurrentSiteName Custom Errors" `
                        "PASS" `
                        "RemoteOnly"
                    }

                    "Off" {
                        Add-Result `
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
($Results | Where-Object Status -eq "PASS").Count

$Fail =
($Results | Where-Object Status -eq "FAIL").Count

$Review =
($Results | Where-Object Status -eq "NEEDS REVIEW").Count

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
