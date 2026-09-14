# =====================================================
# IIS HARDENING AUDIT SCRIPT (READ ONLY)
# IIS 10 / Windows Server 2022 / 2025
# =====================================================

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

    if(Test-Path $Key) {

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

if($tls10 -eq 0) {
    Add-Result "TLS 1.0" "PASS" "Disabled"
}
else {
    Add-Result "TLS 1.0" "FAIL" "Enabled"
}

if($tls11 -eq 0) {
    Add-Result "TLS 1.1" "PASS" "Disabled"
}
else {
    Add-Result "TLS 1.1" "NEEDS REVIEW" "Enabled"
}

if($tls12 -ne 0) {
    Add-Result "TLS 1.2" "PASS" "Enabled"
}
else {
    Add-Result "TLS 1.2" "FAIL" "Disabled"
}

if($tls13 -ne 0 -or $tls13 -eq $null) {
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

    if($https.Count -gt 0) {
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
# CERTIFICATES
# =====================================================

try {

    Get-ChildItem Cert:\LocalMachine\My |
    ForEach-Object {

        $DaysLeft = ($_.NotAfter - (Get-Date)).Days

        if($DaysLeft -lt 0) {

            Add-Result `
            "Certificate $($_.Subject)" `
            "FAIL" `
            "Expired"

        } elseif($DaysLeft -lt 30) {

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

    if($PatchAge -le 45) {

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

foreach($Site in Get-Website) {

    $SiteName = $Site.Name

    # ----------------------------------------------
    # Host Header Bindings
    # ----------------------------------------------

    $Bindings = Get-WebBinding -Name $SiteName

    foreach($Binding in $Bindings) {

        if($Binding.bindingInformation -match '\*\:\d+\:$') {

            Add-Result `
            "$SiteName Host Header" `
            "FAIL" `
            $Binding.bindingInformation
        }
        else {

            Add-Result `
            "$SiteName Host Header" `
            "PASS" `
            $Binding.bindingInformation
        }
    }

    # ----------------------------------------------
    # Authentication
    # ----------------------------------------------

    try {

        $Anon =
        Get-WebConfigurationProperty `
        -Location $SiteName `
        -Filter system.webServer/security/authentication/anonymousAuthentication `
        -Name enabled

        if($Anon.Value -eq $false) {
            Add-Result "$SiteName Anonymous Auth" "PASS" "Disabled"
        }
        else {
            Add-Result "$SiteName Anonymous Auth" "NEEDS REVIEW" "Enabled"
        }

    }
    catch {}

    try {

        $WinAuth =
        Get-WebConfigurationProperty `
        -Location $SiteName `
        -Filter system.webServer/security/authentication/windowsAuthentication `
        -Name enabled

        if($WinAuth.Value -eq $true) {
            Add-Result "$SiteName Windows Auth" "PASS" "Enabled"
        }
        else {
            Add-Result "$SiteName Windows Auth" "NEEDS REVIEW" "Disabled"
        }

    }
    catch {}

    # ----------------------------------------------
    # Logging
    # ----------------------------------------------

    try {

        if($Site.logFile.enabled) {
            Add-Result "$SiteName Logging" "PASS" "Enabled"
        }
        else {
            Add-Result "$SiteName Logging" "FAIL" "Disabled"
        }

    }
    catch {}

    # ----------------------------------------------
    # Content Location
    # ----------------------------------------------

    if($Site.PhysicalPath -match "^C:\\inetpub\\wwwroot") {

        Add-Result `
        "$SiteName Content Location" `
        "FAIL" `
        $Site.PhysicalPath

    }
    else {

        Add-Result `
        "$SiteName Content Location" `
        "PASS" `
        $Site.PhysicalPath
    }

    # ----------------------------------------------
    # NTFS
    # ----------------------------------------------

    try {

        if(Test-Path $Site.PhysicalPath) {

            $Acl = Get-Acl $Site.PhysicalPath

            $BadEntries = $Acl.Access |
            Where-Object {

                $_.IdentityReference -match
                "Everyone|Users|Authenticated Users" `
                -and
                $_.FileSystemRights -match
                "FullControl|Modify"

            }

            if($BadEntries) {

                Add-Result `
                "$SiteName NTFS Permissions" `
                "FAIL" `
                "Broad permissions detected"
            }
            else {

                Add-Result `
                "$SiteName NTFS Permissions" `
                "PASS" `
                "No obvious issues"
            }
        }

    }
    catch {
        Add-Result "$SiteName NTFS Permissions" `
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

    if($Identity -eq "ApplicationPoolIdentity") {

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

    foreach($Verb in $Verbs.Collection) {

        if($Verb.verb -eq "TRACE" -and
           $Verb.allowed -eq $true) {

            $TraceFound=$true
        }

    }

    if($TraceFound) {
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

    if(HeaderExists "Strict-Transport-Security") {
        Add-Result "HSTS" "PASS" "Configured"
    }
    else {
        Add-Result "HSTS" "FAIL" "Missing"
    }

    if(HeaderExists "X-Frame-Options") {
        Add-Result "X-Frame-Options" "PASS" "Configured"
    }
    else {
        Add-Result "X-Frame-Options" "FAIL" "Missing"
    }

    if(HeaderExists "X-Content-Type-Options") {
        Add-Result "X-Content-Type-Options" "PASS" "Configured"
    }
    else {
        Add-Result "X-Content-Type-Options" "FAIL" "Missing"
    }

    if(HeaderExists "Content-Security-Policy") {
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

foreach($ServiceName in $SIEMServices) {

    $Service =
    Get-Service $ServiceName `
    -ErrorAction SilentlyContinue

    if($Service) {

        if($Service.Status -eq "Running") {

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

Get-Website | ForEach-Object {

    $SiteName = $_.Name
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

                if($Debug -eq "false") {

                    Add-Result `
                    "$SiteName ASP.NET Debug" `
                    "PASS" `
                    $_.FullName
                }
                elseif($Debug) {

                    Add-Result `
                    "$SiteName ASP.NET Debug" `
                    "FAIL" `
                    $_.FullName
                }

                $CustomErrors =
                $Config.configuration.'system.web'.customErrors.mode

                switch($CustomErrors) {

                    "On" {
                        Add-Result `
                        "$SiteName Custom Errors" `
                        "PASS" `
                        "On"
                    }

                    "RemoteOnly" {
                        Add-Result `
                        "$SiteName Custom Errors" `
                        "PASS" `
                        "RemoteOnly"
                    }

                    "Off" {
                        Add-Result `
                        "$SiteName Custom Errors" `
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

$Compliance = :Round(
(($Pass / $Total) * 100),2)

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
