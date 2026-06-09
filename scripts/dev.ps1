#!/usr/bin/env pwsh
# Start API + worker together for local development.
# Worker writes data/dev_worker_payment_pubkey.hex; API picks it up automatically.
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

function Ensure-Wasm {
    if (-not (Test-Path "frontend\wasm\tor_marketplace_wasm.js")) {
        Write-Host "[*] Building WASM client..."
        if (-not (Get-Command wasm-pack -ErrorAction SilentlyContinue)) {
            Write-Host "[!] wasm-pack not found. Install: cargo install wasm-pack"
            exit 1
        }
        wasm-pack build wasm --target web --out-dir pkg
        New-Item -ItemType Directory -Force -Path "frontend\wasm" | Out-Null
        Copy-Item "wasm\pkg\*" "frontend\wasm\" -Force
        Write-Host "[+] WASM built"
    }
}

Ensure-Wasm
New-Item -ItemType Directory -Force -Path "data" | Out-Null

if (-not $env:SERVER_SECRET) {
    $env:SERVER_SECRET = "dev_secret_32_bytes_minimum_length!!"
}
$env:EPHEMERAL_KEK = "1"
$env:EPHEMERAL_WORKER_KEY = "1"

$PubkeyFile = Join-Path $Root "data\dev_worker_payment_pubkey.hex"
if (Test-Path $PubkeyFile) { Remove-Item $PubkeyFile -Force }

Write-Host "[*] Starting worker (background)..."
$logFile = Join-Path $Root "data\worker.log"
$workerCmd = @"
Set-Location '$Root'
`$env:EPHEMERAL_KEK = '1'
`$env:EPHEMERAL_WORKER_KEY = '1'
`$env:SERVER_SECRET = '$($env:SERVER_SECRET)'
cargo run --features worker --bin tor-marketplace-worker *>&1 | Out-File -FilePath '$logFile' -Encoding utf8
"@
$workerProc = Start-Process -FilePath "powershell" `
    -ArgumentList "-NoProfile", "-WindowStyle", "Hidden", "-Command", $workerCmd `
    -PassThru

$deadline = (Get-Date).AddSeconds(120)
while (-not (Test-Path $PubkeyFile)) {
    if ((Get-Date) -gt $deadline) {
        Stop-Process -Id $workerProc.Id -Force -ErrorAction SilentlyContinue
        Get-Content (Join-Path $Root "data\worker.log") -Tail 30 -ErrorAction SilentlyContinue
        throw "Timed out waiting for worker pubkey file"
    }
    if ($workerProc.HasExited) {
        Get-Content (Join-Path $Root "data\worker.log") -Tail 40 -ErrorAction SilentlyContinue
        throw "Worker exited before writing pubkey (exit $($workerProc.ExitCode))"
    }
    Start-Sleep -Milliseconds 400
}

$env:WORKER_PAYMENT_PUBKEY_HEX = (Get-Content $PubkeyFile -Raw).Trim()
Write-Host "[+] Worker pubkey synced"
Write-Host "[*] Open http://127.0.0.1:9080 after API starts"
Write-Host "[*] Worker log: data\worker.log"
Write-Host "[*] Starting API (Ctrl+C stops both)..."

try {
    cargo run
} finally {
    Write-Host "[*] Stopping worker..."
    if (-not $workerProc.HasExited) {
        Stop-Process -Id $workerProc.Id -Force -ErrorAction SilentlyContinue
    }
}
