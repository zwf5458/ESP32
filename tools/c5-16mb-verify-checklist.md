# ESP32-C5 16MB 三系统真机验收清单

> 适用硬件：ESP32-C5N16R8 (16MB Flash) 开发板
> 前置条件：`npm test` 56/56 全绿；`pio run -e esp32c5_16mb` 编译通过

---

## 一、分区表烧录验证

### 1.1 整片擦除 + 分区表写入

```powershell
cd E:\code\ESP32\firmware
# 擦除整片 Flash
esptool --chip esp32c5 erase_flash

# 仅写入分区表 (验证分区解析)
esptool --chip esp32c5 write_flash 0x8000 .pio\build\esp32c5_16mb\partitions.bin
```

**验收**：
- [ ] `esptool flash_id` 返回 Flash 大小 = 16MB
- [ ] 串口监控显示分区表加载成功

### 1.2 完整镜像烧录

```powershell
# 烧录合并后的完整镜像 (bootloader + 分区表 + 固件)
esptool --chip esp32c5 write_flash 0x0 .pio\build\esp32c5_16mb\merged.bin
```

**验收**：
- [ ] 设备重启后出热点 `WiFi-XXXX`
- [ ] 连接热点，访问 `http://192.168.4.1/admin.html`
- [ ] 后台首页显示版本号，串口控制台有启动日志

---

## 二、多系统引导 API 验证

### 2.1 GET /api/system/boot

```powershell
# 连接设备热点后
curl http://192.168.4.1/api/system/boot -H "Authorization: Bearer <token>"
```

**期望响应**：
```json
{
  "ok": true,
  "current": "audit",
  "runningPartition": "ota_0",
  "multiBootSupported": true,
  "systems": [
    { "id": "audit",   "partition": "ota_0", "active": true,  "installed": true,  "address": "0x10000", "size": "4032KB" },
    { "id": "espsoup", "partition": "ota_1", "active": false, "installed": false, "address": "0x400000", "size": "4032KB" },
    { "id": "muse",    "partition": "ota_2", "active": false, "installed": false, "address": "0x7F0000", "size": "4032KB" }
  ]
}
```

**验收**：
- [ ] `current` = `"audit"`
- [ ] `multiBootSupported` = `true`
- [ ] `systems` 数组长度 = 3
- [ ] 各分区地址 = `0x10000` / `0x400000` / `0x7F0000`
- [ ] `ota_0.installed` = `true`（当前固件）
- [ ] `ota_1.installed` / `ota_2.installed` = `false`（未刷入外部固件）

### 2.2 Web 后台多系统卡片

**验收**：
- [ ] `admin.html` 底部显示「多系统引导管理 (Triple-Boot)」卡片
- [ ] 三个系统槽位正确显示名称、描述、分区信息
- [ ] 当前系统 (audit) 显示「● 当前运行中」灰色按钮
- [ ] 未安装系统 (espsoup/muse) 显示「[点击切换至] ... (需刷入)」

---

## 三、串口 CLI 验证

### 3.1 boot 命令（查看槽位）

```
# 串口连接 115200，输入:
boot
```

**期望输出**：
```
=== 多系统引导槽位 (Triple-Boot) ===
当前运行: [audit]
 - audit    : Wi-Fi 安全审计平台 | 分区:ota_0 (0x010000) | 状态:[活跃运行中] ◀
 - espsoup  : ESPsoup 口袋 SDR 模式 | 分区:ota_1 (0x400000) | 状态:[未安装/未刷入]
 - muse     : Meta Muse AI 伴侣模式 | 分区:ota_2 (0x7F0000) | 状态:[未安装/未刷入]
===================================
```

**验收**：
- [ ] 三个槽位全部列出
- [ ] 当前系统标记 `[活跃运行中] ◀`
- [ ] 未安装系统标记 `[未安装/未刷入]`

### 3.2 boot <target> 命令（切换引导）

```
# 尝试切换到未安装的系统
boot espsoup
```

**期望输出**：
```
[boot] 切换失败: [ESPsoup 口袋 SDR 模式] 分区尚未烧录有效固件 (需在烧录台刷入 ota_1)
```

**验收**：
- [ ] 切换被拒绝（因为目标分区无有效固件）
- [ ] 错误信息明确指出需先刷入固件

### 3.3 help 命令

```
help
```

**验收**：
- [ ] 列出 `boot` / `boot audit` / `boot espsoup` / `boot muse` / `reboot` / `info`

---

## 四、烧录台多系统刷写验证

### 4.1 准备外部固件

需要准备 ESPsoup 或 Muse 的 `.bin` 固件文件（或任意 ESP32-C5 兼容固件用于测试）。

**测试用固件要求**：
- 芯片目标：ESP32-C5
- 大小：< 3.9MB (4,063,232 字节)
- 格式：裸二进制 (raw binary)

### 4.2 刷入 ota_1 (ESPsoup)

1. 打开烧录台 `http://localhost:8787`
2. 选择串口 → 连接
3. 滚动到「🧩 多系统 / 外部固件刷写」区域
4. 写入目标选择 `ota_1 (0x400000) — ESPsoup 口袋 SDR 模式`
5. 选择本地 `.bin` 文件
6. 点击「⚡ 刷入指定系统分区」

**验收**：
- [ ] 文件大小检查通过（< 3.9375MB）
- [ ] 确认对话框显示目标分区、文件大小、剩余空间
- [ ] 写入进度条正常推进
- [ ] 写入成功后控制台显示 `[custom] 固件写入成功! 目标地址: 0x400000`

### 4.3 刷入 ota_2 (Meta Muse)

同上步骤，目标选择 `ota_2 (0x7F0000)`。

### 4.4 超限保护验证

**测试**：准备一个 > 3.9375MB 的 `.bin` 文件，尝试刷入 ota_0/1/2。

**验收**：
- [ ] 弹窗阻止刷写：`固件文件过大！... 写入将超出目标分区边界并破坏相邻分区数据`
- [ ] 控制台记录 `[custom][ERROR] 固件大小 ... 超过目标分区上限 ... 操作已阻止`

### 4.5 整片写入验证

**测试**：目标选择 `0x000000 — 整片写入`，刷入完整合并镜像。

**验收**：
- [ ] 大小上限 = 16MB (16,777,216 字节)
- [ ] 写入成功后设备重启，恢复出厂状态

---

## 五、引导切换验证

### 5.1 切换到已安装系统

**前置**：ota_1 已刷入有效固件。

**Web 后台**：
1. 访问 `admin.html` → 多系统引导管理卡片
2. 点击 espsoup 槽位的「[点击切换至] ESPsoup 口袋 SDR 模式」
3. 确认对话框 → 确定

**验收**：
- [ ] 弹窗提示切换成功，设备正在重启
- [ ] 设备重启后**不再**出 `WiFi-XXXX` 热点（因为 ESPsoup 固件行为不同）
- [ ] 串口控制台显示 ESPsoup 固件的启动日志

### 5.2 切换回 audit

**串口 CLI**：
```
boot audit
```

**验收**：
- [ ] 串口输出 `[boot] 切换成功: 引导目标设为 [audit], 正在重启 …`
- [ ] 设备重启后恢复 `WiFi-XXXX` 热点
- [ ] `GET /api/system/boot` 返回 `current: "audit"`

### 5.3 切换至不存在的系统

**测试**：ota_2 未刷入固件时，尝试切换。

**验收**：
- [ ] Web 后台按钮显示「(需刷入)」灰色
- [ ] 点击后确认对话框警告「目标分区尚未检测到有效固件」
- [ ] 强制切换后设备重启，串口显示 `Guru Meditation Error` 或反复重启（因镜像缺失）
- [ ] **恢复方法**：按住 BOOT 键 → 上电 → 烧录台重新刷入 audit 固件

---

## 六、分区边界完整性

### 6.1 备份整片 Flash

1. 烧录台 → 「💾 备份固件」
2. 等待 3-5 分钟（16MB 读取）

**验收**：
- [ ] 备份文件下载成功，文件名含 `esp32c5_16mb_16mb_YYYYMMDD-HHMM.bin`
- [ ] 文件大小 = 16,777,216 字节
- [ ] 控制台显示 MD5 校验和

### 6.2 恢复备份

```powershell
esptool --chip esp32c5 write_flash 0x0 backup.bin
```

**验收**：
- [ ] 设备重启后恢复正常工作状态
- [ ] 所有三个系统槽位状态与备份前一致

---

## 七、边界情况

### 7.1 4MB 板子误刷 16MB 分区表

**测试**：在 4MB ESP32-C5 上烧录 `esp32c5_16mb` 镜像。

**期望**：
- [ ] 设备启动后 `GET /api/system/boot` 返回 `multiBootSupported: false`
- [ ] ota_1/ota_2 分区不存在，`installed: false`
- [ ] 引导切换被拒绝（分区未找到）

### 7.2 断电恢复

**测试**：在引导切换重启过程中拔掉电源。

**验收**：
- [ ] 重新上电后设备仍能启动（otadata 分区保证原子性）
- [ ] 引导目标回退到切换前的系统

---

## 八、验收通过标准

- [ ] 第一至七节所有勾选框全部通过
- [ ] 无 Guru Meditation Error / 异常重启
- [ ] 串口日志无 `esp_partition_read` / `esp_ota_set_boot_partition` 错误
- [ ] 三系统切换 10 次无失败

---

## 附录：快速诊断命令

```powershell
# 读取 Flash ID (确认容量)
esptool --chip esp32c5 flash_id

# 读取分区表
esptool --chip esp32c5 read_flash 0x8000 0xC00 partitions.bin
python -c "import sys; data=open('partitions.bin','rb').read(); [print(f'{i:02x}: {data[i:i+24]}') for i in range(0, len(data), 24) if any(data[i:i+24])]"

# 读取 otadata (当前引导槽位)
esptool --chip esp32c5 read_flash 0xD000 0x2000 otadata.bin

# 擦除 otadata (恢复出厂引导)
esptool --chip esp32c5 erase_region 0xD000 0x2000
```
