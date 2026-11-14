<#
.SYNOPSIS
  ESP32-C5N16R8 一键复位 (经 CH340 UART 口拉 DTR/EN), 可选打印启动横幅。
.DESCRIPTION
  射频反复重启 (邪恶双子 / 双频跳频) 后, 原生 USB CDC (COM3) 可能不再重新枚举,
  但板载 CH340 的 UART 口 (本板 COM5) 始终可用。本脚本只用 Windows 自带的
  .NET SerialPort 打一个复位脉冲, 收完启动日志立刻关闭串口 —— 不会像串口监视器
  那样长期占用 COM 打断纯 HTTP 验证 (板子 RTS 接复位脚, 动 RTS/开关串口都会复位)。

  正常启动的复位时序 (真机验证): DTR=1 (拉低 EN) -> 200ms -> DTR=0。
  若你的板子复位线接在 RTS 上, 用 -RtsPulse 切到 grab-boot-log.py 那套时序。

  复位后若日志出现 `invalid header`, 说明 bootloader 被写到 0x0 (应在 0x2000),
  见 docs/firmware-flashing.md §5.7。

.PARAMETER Port      CH340 UART 串口号, 默认 COM5 (原生 USB CDC 是 COM3, 别填错)。
.PARAMETER Baud      波特率, 默认 115200。
.PARAMETER WaitSec   复位后抓启动日志的秒数, 默认 4; -NoLog 等价于 0。
.PARAMETER RtsPulse  改用 RTS 脉冲复位 (RTS=True -> 100ms -> RTS=False, DTR 保持 False)。
.PARAMETER NoLog     只发复位脉冲、不读启动日志, 发完立即释放串口。

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\reset_c5.ps1
  powershell -ExecutionPolicy Bypass -File tools\reset_c5.ps1 -Port COM7 -WaitSec 8
  powershell -ExecutionPolicy Bypass -File tools\reset_c5.ps1 -NoLog
#>
param(
  [string]$Port = 'COM5',
  [int]$Baud = 115200,
  [ValidateRange(0, 60)][int]$WaitSec = 4,
  [switch]$RtsPulse,
  [switch]$NoLog
)

$ErrorActionPreference = 'Stop'
if ($NoLog) { $WaitSec = 0 }

$ser = $null
try {
  $ser = New-Object System.IO.Ports.SerialPort($Port, $Baud, 'None', 8, 'One')
  $ser.Encoding = [System.Text.Encoding]::UTF8
  $ser.Open()
} catch {
  Write-Host "[reset_c5] 打不开 $Port : $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "[reset_c5] 用 CH340 的 UART 口 (本机 COM5); 原生 USB CDC (COM3) 在射频重启后可能消失。" -ForegroundColor Yellow
  Write-Host "[reset_c5] 当前可用串口:" -ForegroundColor Yellow
  [System.IO.Ports.SerialPort]::GetPortNames() | ForEach-Object { Write-Host "  $_" }
  exit 1
}

try {
  # 先把两条控制线放到确定状态 (RTS 接复位脚, 之后不再动它, 避免额外复位)。
  $ser.RtsEnable = $false
  $ser.DtrEnable = $false
  Start-Sleep -Milliseconds 100
  $ser.DiscardInBuffer()

  if ($RtsPulse) {
    $ser.RtsEnable = $true
    Start-Sleep -Milliseconds 100
    $ser.RtsEnable = $false
    Write-Host "[reset_c5] 已向 $Port 发送 RTS 复位脉冲 (100ms)。" -ForegroundColor Green
  } else {
    $ser.DtrEnable = $true       # DTR=1 -> 拉低 EN -> 复位
    Start-Sleep -Milliseconds 200
    $ser.DtrEnable = $false      # DTR=0 -> 释放 EN -> 正常启动
    Write-Host "[reset_c5] 已向 $Port 发送 DTR 复位脉冲 (200ms), 设备正在重启…" -ForegroundColor Green
  }

  if ($WaitSec -le 0) {
    Write-Host "[reset_c5] -NoLog: 不读启动日志, 即将关闭串口 (纯 HTTP 验证请保持 COM 空闲)。" -ForegroundColor Gray
  } else {
    $buf = New-Object System.Text.StringBuilder
    $deadline = (Get-Date).AddSeconds($WaitSec)
    while ((Get-Date) -lt $deadline) {
      try {
        $chunk = $ser.ReadExisting()
        if ($chunk) { [void]$buf.Append($chunk) }
      } catch { }
      Start-Sleep -Milliseconds 200
    }
    $text = $buf.ToString()
    $lines = @($text -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
    if ($lines.Count) {
      Write-Host "[reset_c5] 启动日志 ($($lines.Count) 行, 最多显示 40 行):" -ForegroundColor Cyan
      $lines | Select-Object -First 40 | ForEach-Object { Write-Host "  $_" }
    } else {
      Write-Host "[reset_c5] 未读到启动日志 (波特率不符 / 日志在串口打开前已输出 / 该口不是日志口)。" -ForegroundColor Yellow
    }
    if ($text -match 'invalid header|ets_flash_boot|assertion .* failed') {
      Write-Host "[reset_c5] ⚠ 检测到 bootloader 无效头: 可能被写到 0x0 (应在 0x2000), 见 docs/firmware-flashing.md §5.7。" -ForegroundColor Red
    } elseif ($text -match 'v1\.1\.0|ESP-ROM|WiFi-') {
      Write-Host "[reset_c5] ✓ 已看到正常启动横幅, 复位成功。" -ForegroundColor Green
    }
  }
} finally {
  # 必须释放: 板子 RTS 接复位脚, 长连 COM 会反复打断设备。
  if ($ser -and $ser.IsOpen) { $ser.Close() }
  if ($ser) { $ser.Dispose() }
  Write-Host "[reset_c5] 串口已释放。" -ForegroundColor Gray
}
