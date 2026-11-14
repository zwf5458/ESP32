# ESP32-C5 16MB 三系统验证报告

> 生成时间：2026-11-12  
> 验证范围：16MB Triple-Boot 实现的代码一致性（无需硬件）

---

## 一、实现完整性核对

### 1.1 分区表 (`firmware/partitions-16mb-triple.csv`)

| 分区 | 类型 | 偏移 | 大小 | 用途 |
|------|------|------|------|------|
| nvs | data | 0x009000 | 16KB | 非易失存储 |
| otadata | data | 0x00d000 | 8KB | OTA 引导数据 |
| phy_init | data | 0x00f000 | 4KB | PHY 初始化 |
| **ota_0** | app | **0x010000** | **3.9375MB** | Wi-Fi 安全审计固件 |
| **ota_1** | app | **0x400000** | **3.9375MB** | ESPsoup 口袋 SDR |
| **ota_2** | app | **0x7F0000** | **3.9375MB** | Meta Muse AI 伴侣 |
| spiffs | data | 0xBE0000 | 4.0625MB | 文件系统 |

**总计**：16MB（16,777,216 字节），无重叠，纯 ASCII 兼容 Windows PlatformIO。

### 1.2 PlatformIO 配置 (`firmware/platformio.ini`)

```ini
[env:esp32c5_16mb]
extends = env:esp32c5
board_build.partitions = partitions-16mb-triple.csv
board_upload.flash_size = 16MB
board_upload.maximum_size = 16777216
```

- ✅ 继承 `env:esp32c5`（复用 C5 工具链与编译选项）
- ✅ 指定 16MB 分区表
- ✅ 声明 Flash 容量与体积上限
- ✅ 16MB 分区表仅被此 env 引用（不污染 4MB 版）

### 1.3 固件实现 (`firmware/src/main.cpp`)

**核心组件**：
- `SYSTEM_SLOTS[]`：定义 3 个槽位（audit/espsoup/muse）
- `findSystemPartition()`：按 subtype/label 查找分区
- `isSlotInstalled()`：检查分区首字节是否为 0xE9（ESP 镜像魔数）
- `getRunningSystemId()`：返回当前运行系统 ID
- `switchBootSystem()`：调用 `esp_ota_set_boot_partition()` 切换引导
- `handleBootGet()`：GET `/api/system/boot` 返回槽位信息
- `handleBootPost()`：POST `/api/system/boot` 切换系统
- `handleSerialCli()`：串口 CLI 支持 `boot` / `boot <target>` / `reboot` / `info`

**关键特性**：
- ✅ 引导切换前验证目标分区已安装有效固件
- ✅ 切换失败返回明确错误信息
- ✅ 切换成功后延迟 1 秒重启（保证 HTTP 响应送达）

### 1.4 烧录台 (`flasher/app.js` + `flasher/index.html`)

**多系统刷写区域**（步骤 ③ 卡片下方）：
- 目标分区选择器：ota_0 / ota_1 / ota_2 / 整片写入
- `SLOT_PARTITION_LIMITS`：各分区容量上限（0x3F0000 = 3.9375MB）
- 文件大小校验：超限阻止并弹窗警告
- 确认对话框：显示目标分区、文件大小、剩余空间
- 进度条 + 控制台日志

**芯片识别保护**：
- `chipDisplayName('esp32c5_16mb')` → `'ESP32-C5 (16MB 三系统)'`
- 自动识别不覆盖手动选择的同芯片变体（`startsWith(detected + '_')`）

### 1.5 服务端 (`server/src/logic.js` + `server/src/index.js`)

- `CHIP_ALIASES` 包含 `'esp32c5_16mb'`
- `BOOTLOADER_OFFSET` 映射 `esp32c5_16mb: 0x2000`
- 镜像注册/下载/MD5 校验支持 16MB 变体

### 1.6 构建脚本 (`tools/build-firmware.sh`)

```bash
CHIPS=(esp32 esp32s2 esp32s3 esp32c3 esp32c5 esp32c5_16mb esp32c6)

case "$CHIP" in
  esp32c5_16mb) BL_OFFSET="0x2000"; ESPTOOL_CHIP="esp32c5" ;;
esac
```

- ✅ 编译 16MB 镜像
- ✅ bootloader 偏移 0x2000（C5 系列统一）
- ✅ esptool chip 类型仍为 `esp32c5`（同一物理芯片）

### 1.7 Web 后台 (`firmware/data/admin.html`)

- `bootCard` 卡片：显示三系统槽位
- `loadBootSlots()`：调用 `/api/system/boot` 获取槽位信息
- `doSwitchBoot()`：确认对话框 → POST 切换 → 重启
- 当前系统显示「● 当前运行中」
- 未安装系统显示「(需刷入)」灰色按钮

---

## 二、离线自检结果

**脚本**：`tools/verify-c5-16mb.mjs`  
**检查项**：51 项  
**结果**：✅ **51/51 通过**

### 检查覆盖范围

| 类别 | 检查数 | 状态 |
|------|--------|------|
| 1. 分区表基础校验 | 10 | ✅ |
| 2. 烧录台 SLOT_PARTITION_LIMITS 一致性 | 5 | ✅ |
| 3. 烧录台 HTML select 选项一致性 | 4 | ✅ |
| 4. 固件 SYSTEM_SLOTS 一致性 | 6 | ✅ |
| 5. PlatformIO env 配置 | 6 | ✅ |
| 6. 构建脚本集成 | 3 | ✅ |
| 7. 服务端芯片注册 | 2 | ✅ |
| 8. 烧录台芯片显示 | 2 | ✅ |
| 9. Web 后台多系统卡片 | 4 | ✅ |
| 10. 串口 CLI 命令 | 5 | ✅ |
| 11. 契约测试覆盖 | 4 | ✅ |

**关键验证点**：
- 分区表偏移与烧录台容量上限一致
- 固件槽位标签与分区表标签一致
- 构建脚本 bootloader 偏移与服务端一致
- 契约测试覆盖所有关键约束

---

## 三、契约测试覆盖

**文件**：`server/test/index.test.js`  
**测试数**：56/56 通过（含 2 条多系统引导契约测试）

### 多系统引导契约测试

1. **`多系统引导(契约): 支持三系统槽位定义与引导切换接口`**
   - 验证 `SYSTEM_SLOTS` 定义
   - 验证 `esp_ota_set_boot_partition` 调用
   - 验证串口 CLI 实现
   - 验证 admin.html `bootCard` 存在
   - 验证分区表偏移（ota_1 = 0x400000, ota_2 = 0x7F0000）
   - 验证分区表纯 ASCII

2. **`多系统引导(契约): 16MB 三系统镜像已接入构建与烧录台`**
   - 验证 `[env:esp32c5_16mb]` 存在
   - 验证使用 16MB 分区表
   - 验证 Flash 容量声明
   - 验证分区表仅被 esp32c5_16mb 引用
   - 验证 `CHIP_ALIASES` 包含 esp32c5_16mb
   - 验证构建脚本编译 16MB 镜像
   - 验证 bootloader 偏移与 esptool chip
   - 验证烧录台芯片显示名
   - 验证自动识别不覆盖手动变体

---

## 四、真机验收结果（2026-11-12 · ESP32-C5N16R8 · COM3 · MAC 14:c1:9f:8a:12:f8）

**环境**：esptool v5.4.0，esp32c5_16mb 镜像（含 P4），合并镜像 16MB 烧录 @0x0

| # | 验收项 | 结果 |
|---|--------|------|
| 1 | Flash 容量识别 | ✅ 16MB（Manufacturer 0x68, Device 0x4018） |
| 2 | 分区表 7 项偏移/大小 | ✅ 与 CSV 逐项一致（nvs/otadata/phy/ota_0/ota_1/ota_2/spiffs） |
| 3 | 固件启动 + AP | ✅ `WiFi-12F9`（2.4G 信道 6），ping 平均 4ms |
| 4 | GET /api/system/boot | ✅ current=audit, runningPartition=ota_0, multiBootSupported=true |
| 5 | 切换未安装系统 (espsoup) | ✅ 400「分区尚未烧录有效固件 (需在烧录台刷入 ota_1)」 |
| 6 | 非法目标 ("hacker") | ✅ 400「未知系统目标」 |
| 7 | ota_1 刷入后 installed 检测 | ✅ isSlotInstalled 的 0xE9 魔数检测生效 |
| 8 | 切换 espsoup → 重启 | ✅ current=espsoup, **runningPartition=ota_1** |
| 9 | 切回 audit → 重启 | ✅ current=audit, runningPartition=ota_0 |
| 10 | NVS 跨切换持久 | ✅ 后台口令在切换重启后保持有效 |
| 11 | 切换到当前系统 | ⚠️ 发现 Bug → **已修复并真机复测通过** |

**发现并修复的 Bug**（真机复测通过）：
- 原行为：POST 切换到当前运行系统 → `switchBootSystem` 对"已在运行"分支 `return true`
  → `handleBootPost` 走成功路径返回 200「切换成功」并执行 `ESP.restart()`（无谓重启）
- 修复：`firmware/src/main.cpp` 该分支改为 `return false` → 400 +「当前正在运行 [...], 无需切换」，不再重启
- 复测：HTTP 400 + 正确提示 + 设备保持在线 ✓

**遗留发现（已修复，`2aa34cf`）**：
- C5 自定义 board JSON 未定义 `ARDUINO_USB_CDC_ON_BOOT` → 固件 `Serial` 走 UART0 引脚。
  已在 `[env:esp32c5]` 加 `-DARDUINO_USB_MODE=1 -DARDUINO_USB_CDC_ON_BOOT=1`
  （`esp32c5_16mb` 经 extends 继承）。真机复测通过：启动日志 + NDJSON 遥测出现在原生 USB COM3；
  串口 CLI `boot` 输出三槽位正确状态（audit 活跃 ◀ / espsoup 已就绪 / muse 未安装）。
  体积：esp32c5 97.9%（余 41,781B，CDC 开销 +13,844B）。契约测试 56→57。

**真机测试注意事项**：
- esptool v5 写入会跳过镜像中的全 FF 区域（如 NVS/otadata），旧数据会遗留——
  需要彻底干净的状态时先 `erase_flash` 再烧录
- 设备重启后 AP 需 15~30s 才接受新连接，验收脚本要留足重试时间
- 网卡连着家用路由时 netsh 扫描窗口受限，可能漏扫设备热点（断开后再扫）

---

## 五、剩余真机验证项（低优先级）

以下代码路径与已验证项走同一实现，风险低，待拿到 ESPsoup / Muse 真固件后一并验证：

- [ ] ota_2 (muse) 刷入后 installed 检测 / 切换运行（与 ota_1 同路径）
- [ ] ESPsoup / Muse 真实固件启动行为（不出 audit 热点、SDR 瀑布图、BLE 配对）
- [ ] 烧录台 Web Serial 自定义刷写（浏览器 writeFlash 路径，与 esptool CLI 同机制）
- [ ] 串口 CLI `boot` / `boot <target>`（依赖 CDC 修复后才能在原生 USB 上观察）
- [ ] 整片备份恢复（16MB 全片读回 + esptool write_flash 0x0）
- [ ] 切换过程中断电：otadata 原子性回退

> ⚠️ 2026-11-14 纠偏（Muse 槽位）：Meta 官方预编译 `muse-gadget.bin` 按官方布局编译
> （分区表 `0x10000` / app `0x20000` / 4M 槽位），与本表不兼容，写进 `ota_0` 或 `ota_2`
> 都不启动（前者崩溃在 `esp_ota_get_running_partition()`，后者同样读不到自己的分区）。
> 因此上面两条 Muse 项**不能**用官方原始镜像验证，须先按 `firmware/muse-sdk/README.md`
> 重编，再验 installed 检测 / 切换 / 配对。细节见 `docs/firmware-flashing.md` §6.6、§6.9。

---

## 六、快速诊断命令

```powershell
# 读取 Flash ID (确认容量)
esptool --chip esp32c5 flash_id

# 读取分区表
esptool --chip esp32c5 read_flash 0x8000 0xC00 partitions.bin

# 读取 otadata (当前引导槽位)
esptool --chip esp32c5 read_flash 0xD000 0x2000 otadata.bin

# 擦除 otadata (恢复出厂引导)
esptool --chip esp32c5 erase_region 0xD000 0x2000
```

---

## 七、结论

✅ **16MB 三系统实现完整：离线一致性 51/51 + 真机验收全项通过（2 项真机发现当场修复并复测）**

- 分区表 / 烧录台 / 固件 / 构建脚本 / 服务端之间偏移与约束完全一致（离线自检 51/51）
- 真机完成：分区表烧录、API 三槽位、负向切换拒绝、0xE9 安装检测、
  **audit ↔ espsoup 双向引导切换**（runningPartition 随之变化）、NVS 跨切换持久、
  串口 CLI `boot` 三槽位状态
- 真机发现并修复 2 个问题：
  1. Bug：切换到当前系统无谓重启 → 400 提示（`18dd6f3`）
  2. 配置：C5 原生 USB 无串口输出 → 开启 CDC（`2aa34cf`，esp32c5 余 41,781B）
- 契约测试 **57/57** 全绿

**提交记录**（`18dd6f3` / `8476894` / `2aa34cf` / `5d05eef` 后续均已推送到 `origin/main`）：
- `18dd6f3` fix(firmware): 切换到当前运行系统时返回提示而非重启
- `8476894` test(tools): C5 16MB 三系统离线自检脚本 + 真机验收清单/报告
- `2aa34cf` build(c5): 开启原生 USB CDC
- `5d05eef` docs(tools): 验证报告收尾 - CDC 修复真机复测结果

### 后续（2026-11-13）开发态 `pio upload` 烧录偏移修复

`tools/build-firmware.sh` 的合并镜像从 0x0 整片写入不踩坑；但直接
`pio run -e esp32c5_16mb -t upload` 会把 bootloader 写到 0x0（C5 应在 0x2000），
上电 `invalid header: 0xa8030007` 无限复位。已由 `ff62eda` 用 post 脚本
`firmware/tools/fix_c5_bootloader_offset.py` 修正 esptool 命令行偏移，并在
`[env:esp32c5_16mb]` 重写 `extra_scripts`（含 `pre:tools/embed_admin_page.py` +
`post:tools/fix_c5_bootloader_offset.py`）。真机实烧验证：esptool 命令行出现
`0x2000 …bootloader.bin`，启动 `invalid header`=0、正常打印 v1.1.0 横幅。
详见 `docs/firmware-flashing.md` §5.7。

**下一步**：
1. 拿到 ESPsoup / Muse 真固件后完成剩余验证项（ota_2 切换、真实固件行为、烧录台 Web Serial 刷写路径）
2. 邪恶双子 / 5G 取消认证 / 双频跳频已在同板真机验证，见 `tools/c5-feature-acceptance-report.md` §5
