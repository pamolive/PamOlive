$ErrorActionPreference = "Stop"

if (Test-Path -LiteralPath ".env") {
    Write-Host "PAM-olive is already initialized: .env exists and was left unchanged."
    Write-Host "To regenerate intentionally, stop the stack, back up .env, move it aside, then rerun install.ps1."
    exit 0
}
if (-not (Select-String -LiteralPath ".gitignore" -Pattern "^\.env$" -Quiet)) {
    throw ".env must be ignored by Git before secrets can be generated."
}

function New-RandomHex([int]$Length) {
    $bytes = [byte[]]::new($Length)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToHexString($bytes).ToLowerInvariant()
}

$djangoKey = New-RandomHex 64
$postgresPassword = New-RandomHex 32
$redisPassword = New-RandomHex 32
$keyringToken = New-RandomHex 48
$gatewayKey = New-RandomHex 48
$recordingKey = New-RandomHex 48
$operationsToken = New-RandomHex 48
$guacamoleJsonKey = New-RandomHex 16

$content = @"
DJANGO_SETTINGS_MODULE=config.settings.base
DJANGO_SECRET_KEY=$djangoKey
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=http://localhost:8000

POSTGRES_DB=pamolive
POSTGRES_USER=pamolive
POSTGRES_PASSWORD=$postgresPassword
DATABASE_URL=postgresql://pamolive:$postgresPassword@postgres:5432/pamolive

REDIS_PASSWORD=$redisPassword
REDIS_URL=redis://:$redisPassword@redis:6379/0

PAMOLIVE_KEYRING_URL=http://keyring:8000
PAMOLIVE_KEYRING_TIMEOUT_SECONDS=3
PAMOLIVE_KEYRING_TOKEN=$keyringToken
PAMOLIVE_GATEWAY_SHARED_KEY=$gatewayKey
PAMOLIVE_RECORDING_KEY=$recordingKey
PAMOLIVE_OPERATIONS_TOKEN=$operationsToken
PAMOLIVE_GUACAMOLE_JSON_KEY=$guacamoleJsonKey

PAMOLIVE_HTTP_BIND=127.0.0.1
PAMOLIVE_HTTP_PORT=8000
PAMOLIVE_RDP_ENABLED=true
PAMOLIVE_RDP_PUBLIC_ORIGIN=http://localhost:8081
PAMOLIVE_RDP_HTTP_BIND=127.0.0.1
PAMOLIVE_RDP_HTTP_PORT=8081
PAMOLIVE_FRONTEND_SUBNET=10.253.0.0/24
PAMOLIVE_INTERNAL_SUBNET=10.254.0.0/24
PAMOLIVE_TARGETS_SUBNET=10.255.0.0/24
PAMOLIVE_ROTATION_BACKENDS={}
"@

[System.IO.File]::WriteAllText((Join-Path $PWD ".env"), $content)
Write-Host "PAM-olive secrets generated in .env."
Write-Host "Start the stack with: docker compose up --build -d"
