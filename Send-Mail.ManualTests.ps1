<#
    Manual test harness for Send-Mail.psm1 - no Pester required.

    How it works: PowerShell resolves an unqualified command name (like
    Invoke-RestMethod) by walking the scope chain, which falls through to
    the session's global scope. Functions win over cmdlets at the same
    scope. So defining `function global:Invoke-RestMethod {...}` here
    intercepts the call your module makes internally - no real HTTP
    request ever happens, and no real waiting occurs.

    Run with:
        .\Send-Mail.ManualTests.ps1

    IMPORTANT: run the SMOKE TEST section first and confirm it prints
    "[PASS] shadowing intercepted the call" before trusting anything else
    below - it's a 2-second sanity check that the technique actually works
    on your PowerShell version before you rely on the full suite.
#>

$ModulePath = "$PSScriptRoot\Send-Mail.psm1"
Import-Module $ModulePath -Force

$script:TestFailures = 0

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Host "  [PASS] $Message" -ForegroundColor Green
    }
    else {
        Write-Host "  [FAIL] $Message" -ForegroundColor Red
        $script:TestFailures++
    }
}

# Builds an exception shaped the way your catch block expects:
# .Response.StatusCode and .Response.Headers.GetValues('Retry-After')
function New-FakeHttpError {
    param(
        [Parameter(Mandatory)][System.Net.HttpStatusCode]$StatusCode,
        [int]$RetryAfterSeconds,
        [string]$Message = "Simulated HTTP error"
    )
    $headers = New-Object System.Net.WebHeaderCollection
    if ($PSBoundParameters.ContainsKey('RetryAfterSeconds')) {
        $headers.Add('Retry-After', $RetryAfterSeconds.ToString())
    }
    $fakeResponse = [PSCustomObject]@{ StatusCode = $StatusCode; Headers = $headers }
    $ex = New-Object System.Exception($Message)
    $ex | Add-Member -NotePropertyName Response -NotePropertyValue $fakeResponse -Force
    return $ex
}

$script:BaseArgs = @{
    AccessToken     = 'fake-token'
    From            = 'sender@contoso.com'
    Subject         = 'Test'
    GreetingName    = 'Alex'
    Recipient       = 'recipient@contoso.com'
    Body            = 'Test body'
    Facts           = @()
    HeadlineTitle    = 'Title'
    HeadlineSubtitle = 'Subtitle'
}

try {

    # ---------------------------------------------------------------
    # SMOKE TEST - confirm shadowing actually intercepts the call
    # ---------------------------------------------------------------
    Write-Host "`n=== Smoke test: does shadowing work at all? ===" -ForegroundColor Cyan

    $global:SmokeTestHit = $false
    function global:Invoke-RestMethod { $global:SmokeTestHit = $true; return @{ ok = $true } }
    function global:Start-Sleep { param($Seconds) }

    $null = Send-Mail @script:BaseArgs
    Assert-True $global:SmokeTestHit "shadowing intercepted the call (fake Invoke-RestMethod ran, not the real one)"

    if (-not $global:SmokeTestHit) {
        Write-Host "`nShadowing did not intercept the call - stopping here." -ForegroundColor Red
        Write-Host "Fallback: point Send-Mail at a local HttpListener instead (ask me for that version)." -ForegroundColor Yellow
        return
    }

    # ---------------------------------------------------------------
    # Test 1: happy path - no retries needed
    # ---------------------------------------------------------------
    Write-Host "`n=== Test 1: succeeds on first try ===" -ForegroundColor Cyan
    $global:CallCount = 0
    $global:SleepCalls = @()
    function global:Invoke-RestMethod { $global:CallCount++; return @{} }
    function global:Start-Sleep { param($Seconds) $global:SleepCalls += $Seconds }

    $threw = $false
    try { Send-Mail @script:BaseArgs } catch { $threw = $true }

    Assert-True (-not $threw) "did not throw"
    Assert-True ($global:CallCount -eq 1) "called Invoke-RestMethod exactly once (was $($global:CallCount))"
    Assert-True ($global:SleepCalls.Count -eq 0) "never slept"

    # ---------------------------------------------------------------
    # Test 2: 429 with Retry-After header - waits exact duration
    # ---------------------------------------------------------------
    Write-Host "`n=== Test 2: 429 with Retry-After header ===" -ForegroundColor Cyan
    $global:CallCount = 0
    $global:SleepCalls = @()
    function global:Invoke-RestMethod {
        $global:CallCount++
        if ($global:CallCount -eq 1) { throw (New-FakeHttpError -StatusCode TooManyRequests -RetryAfterSeconds 5) }
        return @{}
    }
    function global:Start-Sleep { param($Seconds) $global:SleepCalls += $Seconds }

    $threw = $false
    try { Send-Mail @script:BaseArgs } catch { $threw = $true }

    Assert-True (-not $threw) "did not throw (recovered after one retry)"
    Assert-True ($global:CallCount -eq 2) "called Invoke-RestMethod twice (was $($global:CallCount))"
    Assert-True ($global:SleepCalls.Count -eq 1 -and $global:SleepCalls[0] -eq 5) "slept exactly 5s as specified by Retry-After (was $($global:SleepCalls -join ','))"

    # ---------------------------------------------------------------
    # Test 3: every retryable status code recovers on retry
    # ---------------------------------------------------------------
    Write-Host "`n=== Test 3: all 5 retryable status codes recover on retry ===" -ForegroundColor Cyan

    $retryableCodes = @(
        [System.Net.HttpStatusCode]::TooManyRequests,     # 429
        [System.Net.HttpStatusCode]::InternalServerError, # 500
        [System.Net.HttpStatusCode]::BadGateway,           # 502
        [System.Net.HttpStatusCode]::ServiceUnavailable,   # 503
        [System.Net.HttpStatusCode]::GatewayTimeout        # 504
    )

    foreach ($code in $retryableCodes) {
        $global:CallCount = 0
        $global:SleepCalls = @()
        $codeForClosure = $code
        # Closure captures $codeForClosure's current value so each loop iteration
        # simulates a different status code without them bleeding into each other
        $mockBody = {
            $global:CallCount++
            if ($global:CallCount -eq 1) { throw (New-FakeHttpError -StatusCode $codeForClosure) }
            return @{}
        }.GetNewClosure()
        Set-Item Function:\global:Invoke-RestMethod $mockBody
        function global:Start-Sleep { param($Seconds) $global:SleepCalls += $Seconds }

        $threw = $false
        try { Send-Mail @script:BaseArgs } catch { $threw = $true }

        Assert-True (-not $threw) "[$([int]$code) $code] recovered and sent on retry (no exception thrown)"
        Assert-True ($global:CallCount -eq 2) "[$([int]$code) $code] retried exactly once before succeeding (was $($global:CallCount) calls)"
        Assert-True ($global:SleepCalls.Count -eq 1) "[$([int]$code) $code] waited before the retry (slept $($global:SleepCalls -join ','))"
    }

    # ---------------------------------------------------------------
    # Test 4: non-retryable errors bubble up immediately, no retry
    # ---------------------------------------------------------------
    Write-Host "`n=== Test 4: non-retryable status codes fail immediately ===" -ForegroundColor Cyan

    $nonRetryableCodes = @(
        [System.Net.HttpStatusCode]::BadRequest,   # 400
        [System.Net.HttpStatusCode]::Unauthorized, # 401
        [System.Net.HttpStatusCode]::Forbidden,    # 403
        [System.Net.HttpStatusCode]::NotFound      # 404
    )

    foreach ($code in $nonRetryableCodes) {
        $global:CallCount = 0
        $global:SleepCalls = @()
        $codeForClosure = $code
        $mockBody = {
            $global:CallCount++
            throw (New-FakeHttpError -StatusCode $codeForClosure -Message "Simulated $codeForClosure")
        }.GetNewClosure()
        Set-Item Function:\global:Invoke-RestMethod $mockBody
        function global:Start-Sleep { param($Seconds) $global:SleepCalls += $Seconds }

        $threw = $false
        try { Send-Mail @script:BaseArgs } catch { $threw = $true }

        Assert-True $threw "[$([int]$code) $code] threw as expected, error returned to caller"
        Assert-True ($global:CallCount -eq 1) "[$([int]$code) $code] no retry attempted (was $($global:CallCount) calls)"
        Assert-True ($global:SleepCalls.Count -eq 0) "[$([int]$code) $code] never slept"
    }

    # ---------------------------------------------------------------
    # Test 5: persistent 429 beyond MaxRetries - eventually throws
    # ---------------------------------------------------------------
    Write-Host "`n=== Test 5: persistent 429 exhausts MaxRetries ===" -ForegroundColor Cyan
    $global:CallCount = 0
    $global:SleepCalls = @()
    function global:Invoke-RestMethod {
        $global:CallCount++
        throw (New-FakeHttpError -StatusCode TooManyRequests -RetryAfterSeconds 1)
    }
    function global:Start-Sleep { param($Seconds) $global:SleepCalls += $Seconds }

    $threw = $false
    try { Send-Mail @script:BaseArgs -MaxRetries 2 } catch { $threw = $true }

    Assert-True $threw "threw after exhausting retries"
    Assert-True ($global:CallCount -eq 3) "called Invoke-RestMethod 3 times: initial + 2 retries (was $($global:CallCount))"

    # ---------------------------------------------------------------
    # Test 6: bare connection failure (no response object at all)
    # ---------------------------------------------------------------
    Write-Host "`n=== Test 6: transient network failure with no HTTP response ===" -ForegroundColor Cyan
    $global:CallCount = 0
    $global:SleepCalls = @()
    function global:Invoke-RestMethod {
        $global:CallCount++
        if ($global:CallCount -eq 1) { throw (New-Object System.Net.Http.HttpRequestException "Simulated connection reset") }
        return @{}
    }
    function global:Start-Sleep { param($Seconds) $global:SleepCalls += $Seconds }

    $threw = $false
    try { Send-Mail @script:BaseArgs } catch { $threw = $true }

    Assert-True (-not $threw) "did not throw (connection failure was treated as retryable)"
    Assert-True ($global:CallCount -eq 2) "called Invoke-RestMethod twice (was $($global:CallCount))"

}
catch {
    $script:TestFailures++
    Write-Host "`n[FATAL] Test run aborted before completing - this is NOT a pass:" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "  Check that Send-Mail.psm1 actually exists next to this test script." -ForegroundColor Yellow
}
finally {
    # Always clean up the shadow functions so they don't leak into the
    # rest of your session and silently break other scripts.
    Remove-Item Function:\Invoke-RestMethod -ErrorAction SilentlyContinue
    Remove-Item Function:\Start-Sleep -ErrorAction SilentlyContinue
    Remove-Variable -Name CallCount, SleepCalls, SmokeTestHit -Scope Global -ErrorAction SilentlyContinue
    Remove-Module Send-Mail -Force -ErrorAction SilentlyContinue

    Write-Host "`n=========================================" -ForegroundColor Cyan
    if ($script:TestFailures -eq 0) {
        Write-Host "All tests passed." -ForegroundColor Green
    }
    else {
        Write-Host "$($script:TestFailures) test(s) FAILED." -ForegroundColor Red
    }
}
