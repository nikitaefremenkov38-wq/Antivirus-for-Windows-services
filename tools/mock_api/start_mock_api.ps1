$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$certPath = Join-Path $scriptDir "localhost-cert.pem"
$keyPath = Join-Path $scriptDir "localhost-key.pem"
$openssl = "C:\msys64\mingw64\bin\openssl.exe"

if (!(Test-Path $certPath) -or !(Test-Path $keyPath)) {
    & $openssl req -x509 -nodes -newkey rsa:2048 -keyout $keyPath -out $certPath -days 365 -subj "/CN=localhost"
}

python (Join-Path $scriptDir "mock_api_server.py")
