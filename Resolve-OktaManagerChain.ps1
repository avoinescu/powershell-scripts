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

.PARAMETER InputCsvPath
    CSV with one column containing the user logins. See -LoginColumnName.

.PARAMETER OutputCsvPath
    Where results are written. If this file already exists, already-processed
    logins are skipped (resume behavior) and new rows are appended.

.PARAMETER OktaOrgUrl
    e.g. https://tenant.okta.com  (no trailing slash)

.PARAMETER OktaApiToken
    Plain-text SSWS API token. See usage notes for how to avoid hardcoding it.

.PARAMETER LoginColumnName
    Name of the column in the input CSV that holds the login. Default: "login"

.EXAMPLE
    .\Resolve-OktaManagerChain.ps1 `
        -InputCsvPath ".\users.csv" `
        -OutputCsvPath ".\users_with_managers.csv" `
        -OktaOrgUrl "https://tenant.okta.com" `
        -OktaApiToken $plainTextToken
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$InputCsvPath,

    [Parameter(Mandatory=$true)]
    [string]$OutputCsvPath,

    [Parameter(Mandatory=$true)]
    [string]$OktaOrgUrl,

    [Parameter(Mandatory=$true)]
    [string]$OktaApiToken,

    [string]$LoginColumnName = "login",

    [string]$CachePath = ".\okta_manager_cache.json",

    [int]$MaxRetries = 5,

    # Base delay between Okta calls, in milliseconds. Raise this if you hit
    # sustained 429s; lower it once you know your org's rate limit headroom.
    [int]$ThrottleMs = 150
)

$ErrorActionPreference = "Stop"
$OktaOrgUrl = $OktaOrgUrl.TrimEnd('/')

# ---------------------------------------------------------------------------
# Okta request wrapper with 429 / 5xx retry handling
# ---------------------------------------------------------------------------
function Invoke-OktaRequest {
    param(
        [string]$Uri,
        [hashtable]$Headers,
        [int]$MaxRetries
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $response = Invoke-WebRequest -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
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
                # 400/401/403/etc - not retryable, surface it
                throw "Okta request failed ($statusCode) on $Uri : $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Cached profile -> managerEmail lookup
# ---------------------------------------------------------------------------
function Get-CachedManagerEmail {
    param(
        [string]$Login,
        [hashtable]$Headers,
        [string]$OktaOrgUrl,
        [hashtable]$Cache,
        [int]$ThrottleMs
    )

    if ($Cache.ContainsKey($Login)) {
        return $Cache[$Login]
    }

    $encodedLogin = [uri]::EscapeDataString($Login)
    $uri = "$OktaOrgUrl/api/v1/users/$encodedLogin"
    $result = Invoke-OktaRequest -Uri $uri -Headers $Headers -MaxRetries $MaxRetries

    if ($result.StatusCode -eq 404) {
        $entry = @{ Found = $false; ManagerEmail = $null }
    }
    else {
        $managerEmail = $result.Content.profile.managerEmail
        if ([string]::IsNullOrWhiteSpace($managerEmail)) {
            $entry = @{ Found = $true; ManagerEmail = $null }
        }
        else {
            $entry = @{ Found = $true; ManagerEmail = $managerEmail }
        }
    }

    $Cache[$Login] = $entry
    Start-Sleep -Milliseconds $ThrottleMs
    return $entry
}

function Save-Cache {
    param([hashtable]$Cache, [string]$Path)
    $arr = foreach ($key in $Cache.Keys) {
        [PSCustomObject]@{
            Login        = $key
            Found        = $Cache[$key].Found
            ManagerEmail = $Cache[$key].ManagerEmail
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
            $cache[$item.Login] = @{ Found = $item.Found; ManagerEmail = $item.ManagerEmail }
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

$inputRows = Import-Csv -Path $InputCsvPath
if (-not ($inputRows | Get-Member -Name $LoginColumnName -MemberType NoteProperty)) {
    throw "Column '$LoginColumnName' not found in $InputCsvPath. Columns present: $(($inputRows[0].PSObject.Properties.Name) -join ', ')"
}

$processedLogins = @{}
if (Test-Path $OutputCsvPath) {
    $existing = Import-Csv -Path $OutputCsvPath
    foreach ($row in $existing) { $processedLogins[$row.Login] = $true }
    Write-Host "Resuming: $($processedLogins.Count) users already in output, will skip them." -ForegroundColor Cyan
}

$cache = Load-Cache -Path $CachePath
if ($cache.Count -gt 0) {
    Write-Host "Loaded $($cache.Count) cached profile lookups from $CachePath" -ForegroundColor Cyan
}

$headers = @{
    Authorization = "SSWS $OktaApiToken"
    Accept        = "application/json"
}

$total        = $inputRows.Count
$i            = 0
$fullyOk      = 0
$withErrors   = 0

foreach ($row in $inputRows) {
    $i++
    $login = $row.$LoginColumnName

    if ([string]::IsNullOrWhiteSpace($login)) { continue }
    if ($processedLogins.ContainsKey($login)) { continue }

    Write-Progress -Activity "Resolving Okta manager chain" `
        -Status "$i / $total : $login" `
        -PercentComplete ([Math]::Min(100, ($i / $total) * 100))

    $outRow = [ordered]@{
        Login                  = $login
        ManagerEmail           = ""
        ManagerStatus          = ""
        SkipLevelManagerEmail  = ""
        SkipLevelManagerStatus = ""
    }

    try {
        $userLookup = Get-CachedManagerEmail -Login $login -Headers $headers `
            -OktaOrgUrl $OktaOrgUrl -Cache $cache -ThrottleMs $ThrottleMs

        if (-not $userLookup.Found) {
            $outRow.ManagerStatus          = "ERROR: user not found in Okta"
            $outRow.SkipLevelManagerStatus = "ERROR: user not found in Okta"
            $withErrors++
        }
        elseif ([string]::IsNullOrWhiteSpace($userLookup.ManagerEmail)) {
            $outRow.ManagerStatus          = "ERROR: no manager assigned"
            $outRow.SkipLevelManagerStatus = "ERROR: no manager assigned"
            $withErrors++
        }
        else {
            $outRow.ManagerEmail  = $userLookup.ManagerEmail
            $outRow.ManagerStatus = "OK"

            $managerLookup = Get-CachedManagerEmail -Login $userLookup.ManagerEmail -Headers $headers `
                -OktaOrgUrl $OktaOrgUrl -Cache $cache -ThrottleMs $ThrottleMs

            if (-not $managerLookup.Found) {
                $outRow.SkipLevelManagerStatus = "ERROR: manager not found in Okta"
                $withErrors++
            }
            elseif ([string]::IsNullOrWhiteSpace($managerLookup.ManagerEmail)) {
                $outRow.SkipLevelManagerStatus = "ERROR: manager has no manager assigned"
                $withErrors++
            }
            else {
                $outRow.SkipLevelManagerEmail  = $managerLookup.ManagerEmail
                $outRow.SkipLevelManagerStatus = "OK"
                $fullyOk++
            }
        }
    }
    catch {
        $outRow.ManagerStatus          = "ERROR: $($_.Exception.Message)"
        $outRow.SkipLevelManagerStatus = "ERROR: $($_.Exception.Message)"
        $withErrors++
    }

    [PSCustomObject]$outRow | Export-Csv -Path $OutputCsvPath -Append -NoTypeInformation

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
