$ErrorActionPreference = "Stop"

if (Test-Path -LiteralPath ".env") {
    throw ".env already exists; refusing to overwrite it."
}

function New-RandomBase64([int]$Length, [bool]$UrlSafe = $false) {
    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $value = [Convert]::ToBase64String($bytes)
    if ($UrlSafe) { $value = $value.Replace("+", "-").Replace("/", "_") }
    return $value
}

function New-RandomHex([int]$Length) {
    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToHexString($bytes).ToLowerInvariant()
}

$djangoKey = New-RandomBase64 48
$vaultKey = New-RandomBase64 32 $true
$postgresPassword = New-RandomBase64 48 $true
$auditKey = New-RandomBase64 48 $true
$gatewayKey = New-RandomBase64 48 $true
$recordingKey = New-RandomBase64 48 $true
$operationsToken = New-RandomBase64 48 $true
$guacamoleJsonKey = New-RandomHex 16
$content = Get-Content -LiteralPath ".env.example" -Raw
$content = $content.Replace("change-me-with-at-least-50-random-characters", $djangoKey)
$content = $content.Replace("generate-a-long-random-database-password", $postgresPassword)
$content = $content.Replace("CBPAM_VAULT_KEY=", "CBPAM_VAULT_KEY=$vaultKey")
$placeholder = "generate-a-distinct-random-value-of-at-least-32-characters"
$content = $content.Replace("CBPAM_AUDIT_SIGNING_KEY=$placeholder", "CBPAM_AUDIT_SIGNING_KEY=$auditKey")
$content = $content.Replace("CBPAM_GATEWAY_SHARED_KEY=$placeholder", "CBPAM_GATEWAY_SHARED_KEY=$gatewayKey")
$content = $content.Replace("CBPAM_RECORDING_KEY=$placeholder", "CBPAM_RECORDING_KEY=$recordingKey")
$content = $content.Replace("CBPAM_OPERATIONS_TOKEN=$placeholder", "CBPAM_OPERATIONS_TOKEN=$operationsToken")
$content = $content.Replace(
    "CBPAM_GUACAMOLE_JSON_KEY=generate-a-distinct-32-character-hex-value",
    "CBPAM_GUACAMOLE_JSON_KEY=$guacamoleJsonKey"
)
[System.IO.File]::WriteAllText((Join-Path $PWD ".env"), $content)

if ($env:CBPAM_BOOTSTRAP_PREPARE_ONLY -eq "true") {
    Write-Host "PAM-olive environment prepared without starting Docker."
    exit 0
}

docker compose up --build -d
Write-Host "PAM-olive is starting at http://localhost:8000"
Write-Host "PAM-olive RDP is starting at http://localhost:8081"
