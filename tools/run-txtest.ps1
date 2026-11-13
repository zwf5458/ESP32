# txtest 运行器: 等设备启动 → 连热点 → 串口发 txtest → 打印结果
$ser = New-Object System.IO.Ports.SerialPort('COM3',115200,'None',8,'One')
$ser.Open()
Start-Sleep -Seconds 16
$ser.ReadExisting() | Out-Null
netsh wlan connect name="WiFi-12F9" | Out-Null
Start-Sleep -Seconds 12
$ser.ReadExisting() | Out-Null
$ser.Write("txtest`r`n")
Start-Sleep -Seconds 6
$out = $ser.ReadExisting()
$ser.Close()
$out -split "`n" | Select-String "txtest" | ForEach-Object { $_.Line.Trim() }
