<#
.SYNOPSIS
    Resolves each user's Okta manager (profile.managerEmail) and that manager's own
    manager (skip-level), writing results to a new CSV.

.DESCRIPTION
    Reads a list of logins (pid@subdomain.domain.com) from a CSV, queries the Okta
    Users API for each one's profile.managerEmail attribute, then looks up the
    manager's own managerEmail. Handles:
      - Users not found in Okta
      - Users with no manager assigned
      - Managers not found in Okta / managers with no manager assigned
      - Okta 429 rate limiting (respects Retry-After)
      - Resume after interruption (skips rows already in the output CSV)
      - Caching so each unique person is only queried once, no matter how many
        times they appear as someone's manager

    Two auth modes are supported:
      OAuth (recommended) - client_credentials grant using private_key_jwt.
          Requires an Okta API Services app with the okta.users.read scope
          granted and an admin role assigned to the app.
      SSWS  (fallback)    - a classic SSWS API token.

.PARAMETER InputCsvPath
    CSV with one column containing the user logins. See -LoginColumnName.

.PARAMETER OutputCsvPath
    Where results are written. If this file already exists, already-processed
    logins are skipped (resume behavior) and new rows are appended.

.PARAMETER OktaOrgUrl
    e.g. https://tenant.okta.com  (no trailing slash)

.PARAMETER OktaClientId
    Client ID of the OAuth API Services app. (OAuth mode)

.PARAMETER PrivateKeyJwkPath
    Path to a JSON file containing the private key JWK Okta gave you when you
    generated the key in the app's Client Credentials section. (OAuth mode)

.PARAMETER Scope
    OAuth scope to request. Default: okta.users.read

.PARAMETER OktaApiToken
    Plain-text SSWS API token. (SSWS fallback mode)

.EXAMPLE
    # OAuth (recommended)
    .\Resolve-OktaManagerChain.ps1 `
        -InputCsvPath ".\users.csv" `
        -OutputCsvPath ".\users_with_managers.csv" `
        -OktaOrgUrl "https://tenant.okta.com" `
        -OktaClientId "0oaXXXXXXXXXXXXXXXXX" `
        -PrivateKeyJwkPath "C:\secure\svc-manager-chain-lookup.jwk.json"

.EXAMPLE
    # SSWS fallback
    .\Resolve-OktaManagerChain.ps1 `
        -InputCsvPath ".\users.csv" `
        -OutputCsvPath ".\users_with_managers.csv" `
        -OktaOrgUrl "https://tenant.okta.com" `
        -OktaApiToken $plainTextToken
#>


[CmdletBinding(DefaultParameterSetName = 'OAuth')]
param(
    [Parameter(Mandatory=$true)]
    [string]$InputCsvPath,
 
    [Parameter(Mandatory=$true)]
    [string]$OutputCsvPath,
 
    [Parameter(Mandatory=$true)]
    [string]$OktaOrgUrl,
 
    # --- OAuth (recommended) ---
    [Parameter(Mandatory=$true, ParameterSetName='OAuth')]
    [string]$OktaClientId,
 
    [Parameter(Mandatory=$true, ParameterSetName='OAuth')]
    [string]$PrivateKeyJwkPath,
 
    [Parameter(ParameterSetName='OAuth')]
    [string]$Scope = "okta.users.read",
 
    # --- SSWS (fallback) ---
    [Parameter(Mandatory=$true, ParameterSetName='SSWS')]
    [string]$OktaApiToken,
 
    [string]$LoginColumnName = "login",
 
    # Swiss/German-locale Excel exports use ";" not ",". Set to "," if your file is US-style.
    [string]$Delimiter = ";",
 
    [string]$CachePath = $(if ($PSScriptRoot) { Join-Path $PSScriptRoot "okta_manager_cache.json" } else { ".\okta_manager_cache.json" }),
 
    [int]$MaxRetries = 5,
 
    # Base delay between Okta calls, in milliseconds.
    [int]$ThrottleMs = 150
)
 
$ErrorActionPreference = "Stop"
$OktaOrgUrl = $OktaOrgUrl.TrimEnd('/')
 
# ---------------------------------------------------------------------------
# Base64URL helpers (JWT uses base64url, not standard base64)
# ---------------------------------------------------------------------------
function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    $b64 = [Convert]::ToBase64String($Bytes)
    return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
 
function ConvertFrom-Base64Url {
    param([string]$Base64Url)
    $s = $Base64Url.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) {
        2 { $s += '==' }
        3 { $s += '=' }
    }
    return [Convert]::FromBase64String($s)
}
 
# ---------------------------------------------------------------------------
# OAuth: build an RSA key from the private JWK, sign a client assertion,
# exchange it for an access token, and keep it refreshed.
# ---------------------------------------------------------------------------
function ConvertTo-RsaFromJwk {
    param([PSCustomObject]$Jwk)
 
    $rsaParams = New-Object System.Security.Cryptography.RSAParameters
    $rsaParams.Modulus  = ConvertFrom-Base64Url $Jwk.n
    $rsaParams.Exponent = ConvertFrom-Base64Url $Jwk.e
    $rsaParams.D        = ConvertFrom-Base64Url $Jwk.d
    $rsaParams.P        = ConvertFrom-Base64Url $Jwk.p
    $rsaParams.Q        = ConvertFrom-Base64Url $Jwk.q
    $rsaParams.DP       = ConvertFrom-Base64Url $Jwk.dp
    $rsaParams.DQ       = ConvertFrom-Base64Url $Jwk.dq
    $rsaParams.InverseQ = ConvertFrom-Base64Url $Jwk.qi
 
    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.ImportParameters($rsaParams)
    return $rsa
}
 
function Get-OktaAccessToken {
    param(
        [string]$OktaOrgUrl,
        [string]$ClientId,
        [PSCustomObject]$Jwk,
        [string]$Scope
    )
 
    $tokenEndpoint = "$OktaOrgUrl/oauth2/v1/token"
    $now = [DateTimeOffset]::UtcNow
    $exp = $now.AddMinutes(5)
 
    $header = @{ alg = "RS256"; typ = "JWT" }
    if ($Jwk.kid) { $header.kid = $Jwk.kid }
 
    $payload = @{
        iss = $ClientId
        sub = $ClientId
        aud = $tokenEndpoint
        iat = [long]$now.ToUnixTimeSeconds()
        exp = [long]$exp.ToUnixTimeSeconds()
        jti = [guid]::NewGuid().ToString()
    }
 
    $headerB64  = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes(($header  | ConvertTo-Json -Compress)))
    $payloadB64 = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress)))
    $signingInput = "$headerB64.$payloadB64"
 
    $rsa = ConvertTo-RsaFromJwk -Jwk $Jwk
    $signatureBytes = $rsa.SignData(
        [System.Text.Encoding]::UTF8.GetBytes($signingInput),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $clientAssertion = "$signingInput.$(ConvertTo-Base64Url $signatureBytes)"
 
    $body = @{
        grant_type            = "client_credentials"
        scope                 = $Scope
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion      = $clientAssertion
    }
 
    try {
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    }
    catch {
        $errorBody = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errorBody = $_.ErrorDetails.Message
        }
        elseif ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $stream.Position = 0
                $reader = New-Object System.IO.StreamReader($stream)
                $errorBody = $reader.ReadToEnd()
            } catch { }
        }
        if ($errorBody) {
            Write-Host "--- Okta token endpoint response ---" -ForegroundColor Red
            Write-Host $errorBody -ForegroundColor Red
            Write-Host "-------------------------------------" -ForegroundColor Red
            throw "Okta token request failed: $errorBody"
        }
        throw
    }
 
    return @{
        AccessToken = $response.access_token
        # refresh 60s before actual expiry to avoid edge-of-window failures
        ExpiresAt   = (Get-Date).AddSeconds([int]$response.expires_in - 60)
    }
}
 
# ---------------------------------------------------------------------------
# Auth state - shared across all requests, refreshed transparently
# ---------------------------------------------------------------------------
$Script:AuthState = @{}
 
function Initialize-SswsAuth {
    param([string]$Token)
    $Script:AuthState = @{ Mode = 'SSWS'; Token = $Token }
}
 
function Initialize-OAuthAuth {
    param([string]$OktaOrgUrl, [string]$ClientId, [PSCustomObject]$Jwk, [string]$Scope)
    $Script:AuthState = @{
        Mode = 'OAuth'; OktaOrgUrl = $OktaOrgUrl; ClientId = $ClientId; Jwk = $Jwk; Scope = $Scope
        AccessToken = $null; ExpiresAt = [datetime]::MinValue
    }
    Update-OAuthToken
}
 
function Update-OAuthToken {
    $tokenInfo = Get-OktaAccessToken -OktaOrgUrl $Script:AuthState.OktaOrgUrl `
        -ClientId $Script:AuthState.ClientId -Jwk $Script:AuthState.Jwk -Scope $Script:AuthState.Scope
    $Script:AuthState.AccessToken = $tokenInfo.AccessToken
    $Script:AuthState.ExpiresAt   = $tokenInfo.ExpiresAt
}
 
function Get-AuthHeaders {
    if ($Script:AuthState.Mode -eq 'SSWS') {
        return @{ Authorization = "SSWS $($Script:AuthState.Token)"; Accept = "application/json" }
    }
    if ((Get-Date) -ge $Script:AuthState.ExpiresAt) {
        Write-Host "Refreshing OAuth access token..." -ForegroundColor DarkGray
        Update-OAuthToken
    }
    return @{ Authorization = "Bearer $($Script:AuthState.AccessToken)"; Accept = "application/json" }
}
 
# ---------------------------------------------------------------------------
# Okta request wrapper with 429 / 5xx retry handling
# ---------------------------------------------------------------------------
function Invoke-OktaRequest {
    param([string]$Uri, [int]$MaxRetries)
 
    $attempt = 0
    while ($true) {
        $attempt++
        $headers = Get-AuthHeaders
        try {
            $response = Invoke-WebRequest -Uri $Uri -Headers $headers -Method Get -ErrorAction Stop
            return @{ StatusCode = 200; Content = ($response.Content | ConvertFrom-Json) }
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
 
            if ($statusCode -eq 404) {
                return @{ StatusCode = 404; Content = $null }
            }
            elseif ($statusCode -eq 429) {
                $retryAfter = 10
                try {
                    $header = $_.Exception.Response.Headers["Retry-After"]
                    if ($header) { $retryAfter = [int]$header }
                } catch { }
 
                if ($attempt -ge $MaxRetries) {
                    throw "Rate limited repeatedly on $Uri (gave up after $attempt attempts)."
                }
                Write-Warning "Rate limited (429). Waiting $retryAfter s... (attempt $attempt/$MaxRetries) [$Uri]"
                Start-Sleep -Seconds $retryAfter
                continue
            }
            elseif ($statusCode -eq 401) {
                # Token may have been revoked/expired unexpectedly - force a refresh and retry once
                if ($Script:AuthState.Mode -eq 'OAuth' -and $attempt -lt $MaxRetries) {
                    Write-Warning "401 received, forcing OAuth token refresh and retrying..."
                    Update-OAuthToken
                    continue
                }
                throw "Unauthorized (401) on $Uri : $($_.Exception.Message)"
            }
            elseif ($null -eq $statusCode -or $statusCode -ge 500) {
                if ($attempt -ge $MaxRetries) {
                    throw "Repeated transient failures on $Uri (gave up after $attempt attempts): $($_.Exception.Message)"
                }
                $backoff = [Math]::Pow(2, $attempt)
                Write-Warning "Transient error ($statusCode). Retrying in $backoff s... (attempt $attempt/$MaxRetries) [$Uri]"
                Start-Sleep -Seconds $backoff
                continue
            }
            else {
                throw "Okta request failed ($statusCode) on $Uri : $($_.Exception.Message)"
            }
        }
    }
}
 
# ---------------------------------------------------------------------------
# Resolve a person's Okta profile by an identifier that may be a login, an
# email, or a managerLoginID value. Tries an exact match first; if that
# 404s, falls back to Okta's user search on the "pid" portion (whatever
# precedes the first "@"), since source-system addresses don't always
# match Okta's real login domain.
# ---------------------------------------------------------------------------
function Resolve-OktaUserProfile {
    param(
        [string]$Identifier,
        [string]$OktaOrgUrl,
        [hashtable]$Cache,
        [int]$ThrottleMs,
        [int]$MaxRetries
    )
 
    if ($Cache.ContainsKey($Identifier)) {
        return $Cache[$Identifier]
    }
 
    $entry = $null
 
    # 1. Exact match on the identifier as given
    $encoded = [uri]::EscapeDataString($Identifier)
    $uri = "$OktaOrgUrl/api/v1/users/$encoded"
    $result = Invoke-OktaRequest -Uri $uri -MaxRetries $MaxRetries
    Start-Sleep -Milliseconds $ThrottleMs
 
    if ($result.StatusCode -eq 200) {
        $entry = @{
            Found          = $true
            ManagerEmail   = $result.Content.profile.managerEmail
            ManagerLoginID = $result.Content.profile.managerLoginID
            OktaStatus     = $result.Content.status
            Ambiguous      = $false
        }
    }
    else {
        # 2. Fallback: search on the "pid" (text before "@"), since the
        #    domain portion of source-system addresses isn't reliably
        #    Okta's actual login domain.
        $pidPart = $Identifier.Split('@')[0]
        if (-not [string]::IsNullOrWhiteSpace($pidPart)) {
            $searchExpr = 'profile.login sw "' + $pidPart + '@"'
            $searchUri = "$OktaOrgUrl/api/v1/users?search=$([uri]::EscapeDataString($searchExpr))"
            $searchResult = Invoke-OktaRequest -Uri $searchUri -MaxRetries $MaxRetries
            Start-Sleep -Milliseconds $ThrottleMs
 
            $found = @()
            if ($searchResult.StatusCode -eq 200 -and $searchResult.Content) {
                $found = @($searchResult.Content)
            }
 
            if ($found.Count -eq 1) {
                $entry = @{
                    Found          = $true
                    ManagerEmail   = $found[0].profile.managerEmail
                    ManagerLoginID = $found[0].profile.managerLoginID
                    OktaStatus     = $found[0].status
                    Ambiguous      = $false
                }
            }
            elseif ($found.Count -gt 1) {
                $entry = @{ Found = $false; ManagerEmail = $null; ManagerLoginID = $null; OktaStatus = $null; Ambiguous = $true }
            }
            else {
                $entry = @{ Found = $false; ManagerEmail = $null; ManagerLoginID = $null; OktaStatus = $null; Ambiguous = $false }
            }
        }
        else {
            $entry = @{ Found = $false; ManagerEmail = $null; ManagerLoginID = $null; OktaStatus = $null; Ambiguous = $false }
        }
    }
 
    $Cache[$Identifier] = $entry
    return $entry
}
 
function Save-Cache {
    param([hashtable]$Cache, [string]$Path)
    $arr = foreach ($key in $Cache.Keys) {
        [PSCustomObject]@{
            Identifier     = $key
            Found          = $Cache[$key].Found
            ManagerEmail   = $Cache[$key].ManagerEmail
            ManagerLoginID = $Cache[$key].ManagerLoginID
            OktaStatus     = $Cache[$key].OktaStatus
            Ambiguous      = $Cache[$key].Ambiguous
        }
    }
    $arr | ConvertTo-Json -Depth 3 | Set-Content -Path $Path -Encoding UTF8
}
 
function Load-Cache {
    param([string]$Path)
    $cache = @{}
    if (Test-Path $Path) {
        $data = @(Get-Content $Path -Raw | ConvertFrom-Json)
        foreach ($item in $data) {
            if ([string]::IsNullOrWhiteSpace($item.Identifier)) { continue }
            $cache[$item.Identifier] = @{
                Found = $item.Found; ManagerEmail = $item.ManagerEmail
                ManagerLoginID = $item.ManagerLoginID; OktaStatus = $item.OktaStatus
                Ambiguous = $item.Ambiguous
            }
        }
    }
    return $cache
}
 
# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not (Test-Path $InputCsvPath)) {
    throw "Input CSV not found: $InputCsvPath"
}
 
if ($PSCmdlet.ParameterSetName -eq 'OAuth') {
    if (-not (Test-Path $PrivateKeyJwkPath)) {
        throw "Private key JWK file not found: $PrivateKeyJwkPath"
    }
    $jwk = Get-Content $PrivateKeyJwkPath -Raw | ConvertFrom-Json
    Initialize-OAuthAuth -OktaOrgUrl $OktaOrgUrl -ClientId $OktaClientId -Jwk $jwk -Scope $Scope
    Write-Host "OAuth access token acquired (scope: $Scope)." -ForegroundColor Cyan
}
else {
    Initialize-SswsAuth -Token $OktaApiToken
    Write-Host "Using SSWS token auth." -ForegroundColor Yellow
}
 
$inputRows = Import-Csv -Path $InputCsvPath -Delimiter $Delimiter
if (-not ($inputRows | Get-Member -Name $LoginColumnName -MemberType NoteProperty)) {
    throw "Column '$LoginColumnName' not found in $InputCsvPath. Columns present: $(($inputRows[0].PSObject.Properties.Name) -join ', ')"
}
 
$processedLogins = @{}
if (Test-Path $OutputCsvPath) {
    $existing = Import-Csv -Path $OutputCsvPath -Delimiter $Delimiter
    foreach ($row in $existing) { $processedLogins[$row.Login] = $true }
    Write-Host "Resuming: $($processedLogins.Count) users already in output, will skip them." -ForegroundColor Cyan
}
 
$cache = Load-Cache -Path $CachePath
if ($cache.Count -gt 0) {
    Write-Host "Loaded $($cache.Count) cached profile lookups from $CachePath" -ForegroundColor Cyan
}
 
$total      = $inputRows.Count
$i          = 0
$fullyOk    = 0
$withErrors = 0
 
foreach ($row in $inputRows) {
    $i++
    $login = $row.$LoginColumnName
 
    if ([string]::IsNullOrWhiteSpace($login)) { continue }
    if ($processedLogins.ContainsKey($login)) { continue }
 
    Write-Progress -Activity "Resolving Okta manager chain" `
        -Status "$i / $total : $login" `
        -PercentComplete ([Math]::Min(100, ($i / $total) * 100))
 
    $outRow = [ordered]@{
        Login                              = $login
        EmployeeOktaStatus                 = ""
        ManagerEmail                       = ""
        ManagerStatus                      = ""
        ManagerOktaAccountStatus           = ""
        SkipLevelManagerEmail              = ""
        SkipLevelManagerStatus             = ""
        SkipLevelManagerOktaAccountStatus  = ""
    }
 
    try {
        $employee = Resolve-OktaUserProfile -Identifier $login -OktaOrgUrl $OktaOrgUrl `
            -Cache $cache -ThrottleMs $ThrottleMs -MaxRetries $MaxRetries
 
        if (-not $employee.Found) {
            $status = if ($employee.Ambiguous) { "ERROR: multiple ambiguous matches in Okta search" } else { "ERROR: user not found in Okta" }
            $outRow.ManagerStatus          = $status
            $outRow.SkipLevelManagerStatus = $status
            $withErrors++
        }
        else {
            $outRow.EmployeeOktaStatus = $employee.OktaStatus
            $managerEmail   = $employee.ManagerEmail
            $managerLoginID = $employee.ManagerLoginID
 
            if ([string]::IsNullOrWhiteSpace($managerEmail) -and [string]::IsNullOrWhiteSpace($managerLoginID)) {
                $outRow.ManagerStatus          = "ERROR: no manager assigned"
                $outRow.SkipLevelManagerStatus = "ERROR: no manager assigned"
                $withErrors++
            }
            else {
                $outRow.ManagerEmail = $managerEmail
 
                # Prefer managerLoginID for the actual lookup (more likely to already
                # be in Okta's real login format); fall back to managerEmail if blank.
                $hop1Identifier = if (-not [string]::IsNullOrWhiteSpace($managerLoginID)) { $managerLoginID } else { $managerEmail }
 
                $manager = Resolve-OktaUserProfile -Identifier $hop1Identifier -OktaOrgUrl $OktaOrgUrl `
                    -Cache $cache -ThrottleMs $ThrottleMs -MaxRetries $MaxRetries
 
                if (-not $manager.Found) {
                    # The manager listed on the employee's profile couldn't actually be
                    # resolved in Okta - that's a real problem with the ManagerEmail
                    # reference itself, not just with the skip-level lookup.
                    $status = if ($manager.Ambiguous) { "ERROR: multiple ambiguous matches for manager in Okta search" } else { "ERROR: manager not found in Okta" }
                    $outRow.ManagerStatus          = $status
                    $outRow.SkipLevelManagerStatus = $status
                    $withErrors++
                }
                else {
                    $outRow.ManagerStatus            = "OK"
                    $outRow.ManagerOktaAccountStatus = $manager.OktaStatus
 
                    $skipManagerEmail   = $manager.ManagerEmail
                    $skipManagerLoginID = $manager.ManagerLoginID
 
                    if ([string]::IsNullOrWhiteSpace($skipManagerEmail) -and [string]::IsNullOrWhiteSpace($skipManagerLoginID)) {
                        $outRow.SkipLevelManagerStatus = "ERROR: manager has no manager assigned"
                        $withErrors++
                    }
                    else {
                        $hop2Identifier = if (-not [string]::IsNullOrWhiteSpace($skipManagerLoginID)) { $skipManagerLoginID } else { $skipManagerEmail }
 
                        $skipManager = Resolve-OktaUserProfile -Identifier $hop2Identifier -OktaOrgUrl $OktaOrgUrl `
                            -Cache $cache -ThrottleMs $ThrottleMs -MaxRetries $MaxRetries
 
                        if (-not $skipManager.Found) {
                            $status = if ($skipManager.Ambiguous) { "ERROR: multiple ambiguous matches for skip-level manager in Okta search" } else { "ERROR: skip-level manager not found in Okta" }
                            $outRow.SkipLevelManagerStatus = $status
                            $withErrors++
                        }
                        else {
                            $outRow.SkipLevelManagerEmail             = $skipManagerEmail
                            $outRow.SkipLevelManagerStatus            = "OK"
                            $outRow.SkipLevelManagerOktaAccountStatus = $skipManager.OktaStatus
                            $fullyOk++
                        }
                    }
                }
            }
        }
    }
    catch {
        $outRow.ManagerStatus          = "ERROR: $($_.Exception.Message)"
        $outRow.SkipLevelManagerStatus = "ERROR: $($_.Exception.Message)"
        $withErrors++
    }
 
    [PSCustomObject]$outRow | Export-Csv -Path $OutputCsvPath -Delimiter $Delimiter -Append -NoTypeInformation
 
    if ($i % 100 -eq 0) {
        Save-Cache -Cache $cache -Path $CachePath
    }
}
 
Save-Cache -Cache $cache -Path $CachePath
Write-Progress -Activity "Resolving Okta manager chain" -Completed
 
Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  Fully resolved (manager + skip-level manager): $fullyOk"
Write-Host "  Rows with at least one error: $withErrors"
Write-Host "  Output: $OutputCsvPath"
Write-Host "  Cache:  $CachePath (safe to delete once you're done re-running)"
 
