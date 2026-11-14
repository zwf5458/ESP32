Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | ? { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' }
[Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher,Windows.Devices.Bluetooth.Advertisement,ContentType=WindowsRuntime] | Out-Null
$watcher = New-Object Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher
$watcher.ScanningMode = [Windows.Devices.Bluetooth.Advertisement.BluetoothLEScanningMode]::Active

$action = {
    param($sender, $eventArgs)
    $name = $eventArgs.Advertisement.LocalName
    $addr = $eventArgs.BluetoothAddress.ToString('X12')
    $rssi = $eventArgs.RawSignalStrengthInDBm
    Write-Host "[BLE] Addr=$addr RSSI=$rssi Name='$name'"
}

Register-ObjectEvent -InputObject $watcher -EventName Received -Action $action | Out-Null
$watcher.Start()
Start-Sleep -Seconds 5
$watcher.Stop()
