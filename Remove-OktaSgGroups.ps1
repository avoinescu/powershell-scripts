<#
.SYNOPSIS
    Bulk-removes group memberships matching a given filter for a list of Okta users.

.DESCRIPTION
    Reads a CSV of users (Okta ID, username, or email), looks each one up in a specified
    Okta tenant, retrieves their current group memberships, finds any groups whose name
    contains the text passed via -GroupFilter (matched case-insensitively, so "sg_okta_"
    also catches SG_Okta_, SG_OKTA_, etc.), and removes the user from those groups.

    -GroupFilter is required and passed at run time, e.g. "sg_okta_", "sg_okta-test", or
    "sg_okta_app1" — so you can scope a run to all sg_okta_ groups, or to one specific group,
    without editing the script.

    Every user is logged to the console as it's processed, and a full CSV report is written
    at the end covering: the user, which groups matched, which were removed, which failed,
    and any errors.

    Supports -WhatIf for a dry run — looks everything up and reports what WOULD be removed
    without actually removing anything.

.PARAMETER CsvPath
    Path to the input CSV. Must contain a column with the user identifier
    (Okta user ID, login/username, or email) — see -IdentifierColumn.

.PARAMETER OutputLogPath
    Path where the CSV report will be written.

.PARAMETER OktaOrgUrl
    Base URL of the Okta tenant, e.g. https://yourorg.okta.com

.PARAMETER ApiToken
    Okta API token as a SecureString. If omitted, the script falls back to
    $env:OKTA_API_TOKEN, and if that's not set either, prompts for it securely.

    The token needs read access to Users and Groups, plus permission to manage
    group membership (e.g. an admin role of Group Membership Administrator or higher).

.PARAMETER IdentifierColumn
    Name of the CSV column containing the Okta ID / username / email.
    Default: "Identifier". Change this to match your CSV's actual header.

.PARAMETER GroupFilter
    Required. Text to match against group names — any group whose name CONTAINS this
    text is a candidate for removal. Matched case-insensitively, so "sg_okta_" also
    catches SG_Okta_, Sg_Okta_, SG_OKTA_, etc.

    Examples: "sg_okta_" (every sg_okta_ group), "sg_okta-test" (just that one),
    "sg_okta_app1" (just that one).

.PARAMETER MaxRetries
    How many times to retry a request after hitting Okta's rate limit (HTTP 429)
    before giving up on that call. Default: 5.

.EXAMPLE
    # Dry run - see what would be removed, nothing actually changes
    .\Remove-OktaSgGroups.ps1 -CsvPath .\users.csv -OutputLogPath .\removal-log.csv `
        -OktaOrgUrl "https://yourorg.okta.com" -GroupFilter "sg_okta_" -WhatIf

.EXAMPLE
    # Live run - only the one specific group
    .\Remove-OktaSgGroups.ps1 -CsvPath .\users.csv -OutputLogPath .\removal-log.csv `
        -OktaOrgUrl "https://yourorg.okta.com" -GroupFilter "sg_okta-test"

.NOTES
    Tested against PowerShell 7. Should also run on Windows PowerShell 5.1
    (uses Invoke-WebRequest throughout rather than PS7-only parameters).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputLogPath,

    [Parameter(Mandatory = $true)]
    [string]$OktaOrgUrl,

    [Parameter(Mandatory = $false)]
    [SecureString]$ApiToken,

    [Parameter(Mandatory = $false)]
    [string]$IdentifierColumn = "Identifier",

    [Parameter(Mandatory = $true)]
    [string]$GroupFilter,

    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 5
)

#region Setup

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$isDryRun = $PSBoundParameters.ContainsKey('WhatIf')

# --- Resolve API token ---
if (-not $ApiToken) {
    if ($env:OKTA_API_TOKEN) {
        $ApiToken = ConvertTo-SecureString $env:OKTA_API_TOKEN -AsPlainText -Force
    }
    else {
        $ApiToken = Read-Host -Prompt "Enter Okta API token" -AsSecureString
    }
}

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiToken)
$plainToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$OktaOrgUrl = $OktaOrgUrl.TrimEnd('/')

$script:headers = @{
    "Authorization" = "SSWS $plainToken"
    "Accept"        = "application/json"
    "Content-Type"  = "application/json"
}

Remove-Variable plainToken, bstr -ErrorAction SilentlyContinue

#endregion

#region Helper functions

function Invoke-OktaApi {
    <#
        Thin wrapper around Invoke-WebRequest that retries on 429 (rate limit)
        using Okta's X-Rate-Limit-Reset header, and normalizes 404s to a
        StatusCode instead of throwing. Returns StatusCode / Headers / Body.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $false)][string]$Method = "GET"
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $resp = Invoke-WebRequest -Uri $Uri -Headers $script:headers -Method $Method -ErrorAction Stop
            $body = $null
            if ($resp.Content) { $body = $resp.Content | ConvertFrom-Json }
            return [PSCustomObject]@{
                StatusCode = [int]$resp.StatusCode
                Headers    = $resp.Headers
                Body       = $body
            }
        }
        catch {
            $webResp = $_.Exception.Response
            $statusCode = $null
            if ($webResp) { $statusCode = [int]$webResp.StatusCode }

            if ($statusCode -eq 429 -and $attempt -le $MaxRetries) {
                $waitSeconds = 5
                try {
                    $resetHeader = $webResp.Headers["X-Rate-Limit-Reset"]
                    if ($resetHeader) {
                        $resetEpoch = [int]@($resetHeader)[0]
                        $resetTime  = [DateTimeOffset]::FromUnixTimeSeconds($resetEpoch).UtcDateTime
                        $delta      = ($resetTime - [DateTime]::UtcNow).TotalSeconds
                        if ($delta -gt 0) { $waitSeconds = [Math]::Ceiling($delta) + 1 }
                    }
                } catch { }
                Write-Warning "Rate limited (429) on $Uri. Waiting $waitSeconds sec (retry $attempt/$MaxRetries)..."
                Start-Sleep -Seconds $waitSeconds
                continue
            }
            elseif ($statusCode -eq 404) {
                return [PSCustomObject]@{ StatusCode = 404; Headers = $null; Body = $null }
            }
            else {
                throw
            }
        }
    }
}

function Get-OktaUserByAnyId {
    <#
        Handles Okta ID, login/username, or email:
          1. Try the direct GET /users/{id} endpoint - covers Okta ID and login.
          2. Fall back to a search filter on profile.email / profile.login,
             which covers tenants where login isn't the email address.
    #>
    param([string]$Identifier)

    $encoded = [Uri]::EscapeDataString($Identifier)
    $direct = Invoke-OktaApi -Uri "$OktaOrgUrl/api/v1/users/$encoded"
    if ($direct.StatusCode -eq 200 -and $direct.Body) {
        return $direct.Body
    }

    $filter = "profile.email eq `"$Identifier`" or profile.login eq `"$Identifier`""
    $encodedFilter = [Uri]::EscapeDataString($filter)
    $search = Invoke-OktaApi -Uri "$OktaOrgUrl/api/v1/users?search=$encodedFilter"

    if ($search.Body -and $search.Body.Count -gt 0) {
        return $search.Body[0]
    }

    return $null
}

function Get-OktaUserGroups {
    param([string]$UserId)

    $groups = @()
    $nextUri = "$OktaOrgUrl/api/v1/users/$UserId/groups"

    while ($nextUri) {
        $result = Invoke-OktaApi -Uri $nextUri
        if ($result.Body) { $groups += $result.Body }

        $nextUri = $null
        if ($result.Headers -and $result.Headers["Link"]) {
            foreach ($link in @($result.Headers["Link"])) {
                if ($link -match '<([^>]+)>;\s*rel="next"') {
                    $nextUri = $Matches[1]
                }
            }
        }
    }

    return $groups
}

function Remove-OktaGroupMembership {
    param([string]$GroupId, [string]$UserId)
    Invoke-OktaApi -Uri "$OktaOrgUrl/api/v1/groups/$GroupId/users/$UserId" -Method DELETE | Out-Null
}

#endregion

#region Main

if (-not (Test-Path $CsvPath)) {
    throw "Input CSV not found: $CsvPath"
}

$inputRows = Import-Csv -Path $CsvPath

if (-not $inputRows -or $inputRows.Count -eq 0) {
    throw "Input CSV is empty: $CsvPath"
}

if ($inputRows[0].PSObject.Properties.Name -notcontains $IdentifierColumn) {
    throw "Column '$IdentifierColumn' not found in CSV. Available columns: $($inputRows[0].PSObject.Properties.Name -join ', ')"
}

$results = New-Object System.Collections.Generic.List[Object]
$total = $inputRows.Count
$counter = 0

foreach ($row in $inputRows) {

    $counter++
    $identifier = $row.$IdentifierColumn
    Write-Host "[$counter/$total] Processing '$identifier'..." -ForegroundColor Cyan

    if ([string]::IsNullOrWhiteSpace($identifier)) {
        Write-Host "  Skipped: empty identifier" -ForegroundColor Yellow
        $results.Add([PSCustomObject]@{
            Timestamp     = (Get-Date -Format "o")
            Identifier    = $identifier
            OktaUserId    = ""
            Login         = ""
            Status        = "SKIPPED"
            MatchedGroups = ""
            RemovedGroups = ""
            FailedGroups  = ""
            ErrorMessage  = "Empty identifier"
        })
        continue
    }

    try {
        $user = Get-OktaUserByAnyId -Identifier $identifier

        if (-not $user) {
            Write-Host "  Not found in Okta" -ForegroundColor Red
            $results.Add([PSCustomObject]@{
                Timestamp     = (Get-Date -Format "o")
                Identifier    = $identifier
                OktaUserId    = ""
                Login         = ""
                Status        = "USER_NOT_FOUND"
                MatchedGroups = ""
                RemovedGroups = ""
                FailedGroups  = ""
                ErrorMessage  = "No matching Okta user"
            })
            continue
        }

        $userId = $user.id
        $login  = $user.profile.login

        $allGroups = Get-OktaUserGroups -UserId $userId
        $matchedGroups = @($allGroups | Where-Object { $_.profile.name -like "*$GroupFilter*" })

        if ($matchedGroups.Count -eq 0) {
            Write-Host "  $login - no groups matching '$GroupFilter'" -ForegroundColor DarkGray
            $results.Add([PSCustomObject]@{
                Timestamp     = (Get-Date -Format "o")
                Identifier    = $identifier
                OktaUserId    = $userId
                Login         = $login
                Status        = "NO_MATCHING_GROUPS"
                MatchedGroups = ""
                RemovedGroups = ""
                FailedGroups  = ""
                ErrorMessage  = ""
            })
            continue
        }

        $matchedNames = ($matchedGroups | ForEach-Object { $_.profile.name }) -join "; "
        Write-Host "  $login - matched: $matchedNames" -ForegroundColor White

        $removed = New-Object System.Collections.Generic.List[string]
        $failed  = New-Object System.Collections.Generic.List[string]

        foreach ($group in $matchedGroups) {
            $groupName = $group.profile.name

            if ($PSCmdlet.ShouldProcess($login, "Remove from group '$groupName'")) {
                try {
                    Remove-OktaGroupMembership -GroupId $group.id -UserId $userId
                    Write-Host "    Removed from '$groupName'" -ForegroundColor Green
                    $removed.Add($groupName)
                }
                catch {
                    Write-Host "    FAILED to remove from '$groupName': $($_.Exception.Message)" -ForegroundColor Red
                    $failed.Add($groupName)
                }
            }
        }

        $status = if ($isDryRun) { "DRYRUN" }
                  elseif ($failed.Count -gt 0) { "PARTIAL_FAILURE" }
                  else { "SUCCESS" }

        $results.Add([PSCustomObject]@{
            Timestamp     = (Get-Date -Format "o")
            Identifier    = $identifier
            OktaUserId    = $userId
            Login         = $login
            Status        = $status
            MatchedGroups = $matchedNames
            RemovedGroups = ($removed -join "; ")
            FailedGroups  = ($failed -join "; ")
            ErrorMessage  = ""
        })
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $results.Add([PSCustomObject]@{
            Timestamp     = (Get-Date -Format "o")
            Identifier    = $identifier
            OktaUserId    = ""
            Login         = ""
            Status        = "ERROR"
            MatchedGroups = ""
            RemovedGroups = ""
            FailedGroups  = ""
            ErrorMessage  = $_.Exception.Message
        })
    }
}

$results | Export-Csv -Path $OutputLogPath -NoTypeInformation -Encoding UTF8

#endregion

#region Summary

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Group-Object Status | ForEach-Object {
    Write-Host ("  {0,-20} {1}" -f $_.Name, $_.Count)
}
Write-Host "Log written to: $OutputLogPath" -ForegroundColor Cyan

#endregion
