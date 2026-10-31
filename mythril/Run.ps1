param([int]$Target = 20, [int]$TimeoutSeconds = 90)
$ErrorActionPreference = 'Stop'
$docker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
if (-not (Test-Path $docker)) { throw 'Install Docker Desktop first.' }
$env:PATH = (Split-Path $docker) + [IO.Path]::PathSeparator + $env:PATH
& $docker info --format '{{.ServerVersion}}' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Start Docker Desktop and wait for the engine.' }
& $docker pull 'mythril/myth@sha256:49e11758e359d0b410f648df5bbcba28a52e091a78e4772b5c02b9043666b4ff'
if ($LASTEXITCODE -ne 0) { throw 'Mythril image download failed.' }
& python (Join-Path $PSScriptRoot 'scanner\run_pipeline.py') --target $Target --audit-timeout $TimeoutSeconds
exit $LASTEXITCODE

