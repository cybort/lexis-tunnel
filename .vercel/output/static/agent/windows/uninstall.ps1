$ErrorActionPreference = "SilentlyContinue"
Stop-ScheduledTask -TaskName "LexisAgent"
Unregister-ScheduledTask -TaskName "LexisAgent" -Confirm:$false
Write-Output "已取消词隙的登录任务。配置还在 $env:LOCALAPPDATA\Lexis"
