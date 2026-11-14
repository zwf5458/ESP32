# 把 firmware/muse-sdk 里的覆盖文件同步到 Meta Muse Gadget SDK 克隆。
# 用法: powershell -ExecutionPolicy Bypass -File sync-to-sdk.ps1 [-SdkPath <esp32 目录>]
param(
  [string]$SdkPath = "E:\code\muse-gadget-sdk\esp32"
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path (Join-Path $SdkPath "sdkconfig.defaults"))) {
  throw "找不到 SDK: $SdkPath (应指向 muse-gadget-sdk\esp32)"
}

Copy-Item (Join-Path $here "partitions_c5_16mb_triple.csv") (Join-Path $SdkPath "partitions_c5_16mb_triple.csv") -Force
Copy-Item (Join-Path $here "sdkconfig.c5-16mb-triple") (Join-Path $SdkPath "devices\sdkconfig.c5-16mb-triple") -Force

Write-Host "已同步到 $SdkPath :" -ForegroundColor Green
Write-Host "  partitions_c5_16mb_triple.csv"
Write-Host "  devices\sdkconfig.c5-16mb-triple"
