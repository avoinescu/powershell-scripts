<#
.SYNOPSIS
    Diagnostic only. Tries several ways of locating a user in Okta by "pid"
    (the numeric part before the @ in your source file) so we can see which
    one actually resolves against your org, before baking a fix into the
    main script.

.EXAMPLE
    .\Test-OktaLookupStrategies.ps1 `
        -OktaOrgUrl "https://tenant.okta.com" `
        -OktaClientId "0oaXXXXXXXXXXXXXXXXX" `
        -PrivateKeyJwkPath "C:\secure\svc-manager-chain-lookup.jwk.json" `
        -TestPid "086174"
#>

param(
    [Parameter(Mandatory=$true)] [string]$OktaOrgUrl,
    [Parameter(Mandatory=$true)] [string]$OktaClientId,
    [Parameter(Mandatory=$true)] [string]$PrivateKeyJwkPath,
    [Parameter(Mandatory=$true)] [string]$TestPid,
    [string]$Scope = "okta.users.read"
)

$ErrorActionPreference = "Stop"
$OktaOrgUrl = $OktaOrgUrl.TrimEnd('/')

function ConvertTo-Base64Url {
    param([byte[]]$Bytes)
    $b64 = [Convert]::ToBase64String($Bytes)
    return $b64.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url {
    param([string]$Base64Url)
    $s = $Base64Url.Replace('-', '+').Replace('_', '/')
    switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }
    return [Convert]::FromBase64String($s)
}

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
    param([string]$OktaOrgUrl, [string]$ClientId, [PSCustomObject]$Jwk, [string]$Scope)
    $tokenEndpoint = "$OktaOrgUrl/oauth2/v1/token"
    $now = [DateTimeOffset]::UtcNow
    $exp = $now.AddMinutes(5)
    $header = @{ alg = "RS256"; typ = "JWT" }
    if ($Jwk.kid) { $header.kid = $Jwk.kid }
    $payload = @{
        iss = $ClientId; sub = $ClientId; aud = $tokenEndpoint
        iat = [long]$now.ToUnixTimeSeconds(); exp = [long]$exp.ToUnixTimeSeconds()
        jti = [guid]::NewGuid().ToString()
    }
    $headerB64  = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes(($header  | ConvertTo-Json -Compress)))
    $payloadB64 = ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress)))
    $signingInput = "$headerB64.$payloadB64"
    $rsa = ConvertTo-RsaFromJwk -Jwk $Jwk
    $sig = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($signingInput),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $clientAssertion = "$signingInput.$(ConvertTo-Base64Url $sig)"
    $body = @{
        grant_type = "client_credentials"; scope = $Scope
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion = $clientAssertion
    }
    $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    return $response.access_token
}

$jwk = Get-Content $PrivateKeyJwkPath -Raw | ConvertFrom-Json
$accessToken = Get-OktaAccessToken -OktaOrgUrl $OktaOrgUrl -ClientId $OktaClientId -Jwk $jwk -Scope $Scope
$headers = @{ Authorization = "Bearer $accessToken"; Accept = "application/json" }
Write-Host "Token acquired.`n" -ForegroundColor Green

function Try-Call {
    param([string]$Label, [string]$Uri)
    Write-Host "=== $Label ===" -ForegroundColor Cyan
    Write-Host $Uri -ForegroundColor DarkGray
    try {
        $result = Invoke-RestMethod -Uri $Uri -Headers $headers -Method Get -ErrorAction Stop
        $result | ConvertTo-Json -Depth 5 | Write-Host
    }
    catch {
        $body = $null
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $body = $_.ErrorDetails.Message }
        Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
        if ($body) { Write-Host $body -ForegroundColor Red }
    }
    Write-Host ""
}

# A: guess the real domain has no subdomain (nttdata.com instead of na.nttdata.com)
Try-Call "A: truncated-domain direct lookup" `
    "$OktaOrgUrl/api/v1/users/$([uri]::EscapeDataString("$TestPid@nttdata.com"))"

# B: q= startsWith match (documented to match firstName/lastName/email)
Try-Call "B: q= startsWith search" `
    "$OktaOrgUrl/api/v1/users?q=$([uri]::EscapeDataString($TestPid))"

# C: search= with sw operator on profile.login (may be deprecated - testing anyway)
$searchExprC = 'profile.login sw "' + $TestPid + '@"'
Try-Call "C: search= profile.login sw" `
    "$OktaOrgUrl/api/v1/users?search=$([uri]::EscapeDataString($searchExprC))"

# D: search= with sw operator on profile.email
$searchExprD = 'profile.email sw "' + $TestPid + '@"'
Try-Call "D: search= profile.email sw" `
    "$OktaOrgUrl/api/v1/users?search=$([uri]::EscapeDataString($searchExprD))"

Write-Host "sDone. Tell me which section(s) returned the correct user (Harish Jade / 086174)." -ForegroundColor Green
