$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dest = Join-Path $env:LOCALAPPDATA "Lexis"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
foreach ($name in @("lexis-agent.mjs", "lexis-frame.mjs", "zstd.wasm", "lexis-tls.crt", "lexis-tls.key", "lexis.config.json")) {
  Copy-Item (Join-Path $here $name) $dest -Force
}
$node = (Get-Command node -ErrorAction SilentlyContinue).Source
if (-not $node) { throw "需要 Node.js 22。安装后再运行本脚本。" }
$arg = "`"$dest\lexis-agent.mjs`""
$action = New-ScheduledTaskAction -Execute $node -Argument $arg -WorkingDirectory $dest
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "LexisAgent" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "LexisAgent"
Write-Output "词隙已在登录时后台常驻。状态页 http://127.0.0.1:17890/"
