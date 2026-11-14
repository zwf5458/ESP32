# 刷固件说明（网页烧录台 / 命令行）

适用于固件 **v1.1.0**，芯片 `esp32 / esp32s2 / esp32s3 / esp32c3 / esp32c5 / esp32c6`。
镜像为 **4MB 整片合并镜像**，从 `0x0` 一次写入；16MB 板的三系统 (Triple-Boot)
部署需用专用镜像 `esp32c5_16mb`（见 §6）。

> ⚠️ 仅用于自有设备或取得书面授权的受测设备。刷入后设备会真实发射 WiFi 信号，
> 教学模块的使用边界见 [README「功能范围与合规边界」](../README.md#功能范围与合规边界)。

---

## 0. 前置条件

| 项目 | 要求 |
|---|---|
| 后端 | 已启动：`npm start`（或 `node server/src/index.js`），烧录台地址 `http://localhost:8787` |
| 镜像 | 已注册到 manifest：浏览器打开 `http://localhost:8787/api/firmware/manifest` 能看到对应芯片 |
| 浏览器 | Chrome / Edge **89+**（Web Serial）。Firefox、Safari 不支持 |
| 数据线 | 能传输数据的 USB 线（很多附赠线只能充电） |
| 开发板 | **4MB Flash**；ESP32 / S2 / S3 / C3 / C5 / C6 |
| 串口驱动 | 按板载 USB 转串口芯片安装：CP210x、CH340/CH9102 等；Windows 设备管理器应出现 `COMx` |

> 烧录台依赖已随仓库内置在 `flasher/vendor/`（esptool-js 0.7.1 + crypto-js 4.2.0），
> 页面加载**不需要**访问公网 CDN，离线 / 内网环境可直接使用。

> 原生 USB 开发板（S3 / C3 / C6 / C5 常见两个 USB 口）：C5 的两个 env
> （`esp32c5` / `esp32c5_16mb`）已开启 `ARDUINO_USB_CDC_ON_BOOT=1`，原生 USB 口即
> `Serial`（日志 / CLI / 首次口令）所在口；其余芯片的固件仍走 UART，请连接标注
> **UART** 的口。C5 实测：射频反复重启后原生 USB CDC 可能不再重新枚举，此时改用板载
> CH340 的 UART 口抓日志 / 复位（见 §5.7）。

---

## 1. 方式一：网页烧录台（推荐）

### 1.1 获取烧录码

烧录码是一次性凭据，**校验后 15 分钟内有效**，烧录成功后核销；烧录失败不扣码。

本地开发可直接生成：

```bash
npm run gen-code -- 3        # 生成 3 个码；也支持 npm run codes / npm run stats
```

生产/教学场景由管理员通过 `POST /api/admin/codes` 发码，或按页面「获取烧录码」提示获取。

### 1.2 打开烧录台并连接开发板

1. 打开 `http://localhost:8787`。
2. 在「① 串口连接」点「连接」，在浏览器弹窗中选择开发板对应的 `COMx` / `/dev/cu.*` / `/dev/ttyUSB*`。
3. 能自动复位进入下载模式时，控制台会显示芯片型号并自动匹配镜像。
4. 若提示连接失败或自动复位不生效：
   - **按住 BOOT 键** → 点「连接」（或点一下 RESET/EN 再松开）→ 松开 BOOT；
   - 或勾选「跳过自动复位」后重试。

### 1.3 校验烧录码

1. 粘贴烧录码到「② 烧录码」，点「✓ 校验烧录码」。
2. 校验通过后前端会拿到一次性 nonce；此后才能开始烧录。
3. 校验接口限流 **10 次/分钟/IP**，触发 `429` 时等一分钟再试。

### 1.4 选择型号并烧录

1. 「③ 开发板与烧录」中，芯片识别成功会**自动匹配**镜像；也可手动预选，
   但识别到实际芯片后会以实际芯片为准（防止选错芯片烧错镜像）。
2. 阅读并勾选《使用条款》。
3. 点「开始烧录」，流程为：
   - 从后端下载对应芯片镜像；
   - 本地比对 manifest 的 **MD5 与文件大小**，不一致直接阻止烧录；
   - 以 `921600` 波特率、单镜像 `offset 0x0` 写入；
   - 进度条与串口控制台实时显示。
4. 成功后页面提示「烧录码已核销」，设备自动复位，控制台切回 `115200` 读启动日志。

> 烧录失败（断线、供电不足、写超时）时**烧录码不会核销**：重新点「校验烧录码」拿新 nonce 再烧即可。
> 若网页端反复失败，可改用第 2 节命令行方式（更易降速排查）。

### 1.5 首次启动、连接热点与登录后台

1. 设备重启后发出热点：SSID `WiFi-xxxx`（MAC 尾 4 位），密码 `00000000`。
2. 手机/电脑连接该热点，通常会自动弹出后台（Captive Portal）；未弹窗就手动打开
   `http://192.168.4.1/admin.html`。
3. **首次上电会在串口打印一次随机后台口令**（12 位，区分大小写），
   形如：

   ```text
   [admin] ===== 首次上电: 后台初始口令 (仅显示这一次) =====
   [admin]   A7kQ2mZx9Ptc
   [admin] 请登录后立即在「配置」页修改并妥善保存; 恢复出厂会重新生成
   ```

   - 用烧录台的「串口控制台」查看（`115200`），或任意串口工具；
   - 该口令**不会**出现在网页、`/api/log`、NDJSON 遥测中；
   - 旧版的 `esp32admin` 只是历史默认值，升级时会被自动轮换，**不能用作登录口令**。
4. 打开后台 → 输入该口令登录。若仍在使用初始口令，页面顶部会提示，
   点进「配置」→「后台口令」设置自己的口令（**4–32 位，立即生效**）。
5. 之后所有 `/api/*` 请求都需携带 `X-Admin-Token`（面板会自动加）。

> **重刷整片镜像会覆盖 NVS**：热点配置与已修改的后台口令都会丢失，
> 首次启动会重新生成初始口令。请重新从串口读取。

### 1.6 一键备份整片 Flash（推荐首刷前做一次）

烧录台「③ 开发板与烧录」卡片底部有 **「💾 备份固件」**，用于在**写入前**把整片 Flash
读回成 `.bin` 文件，刷坏时可整片还原。

1. 先按 1.2 连接开发板（或直接点备份，页面会提示并自动进入下载模式）。
2. 点「💾 备份固件」。
3. 前端按 **Flash ID 自动识别容量**（4MB / 8MB / 16MB …），从 `0x0` 起分块读取
   （1MB/块），进度条实时显示已读字节与百分比。
4. 读完后自动生成并下载 `<chip>_backup_<容量>_<日期-时间>.bin`，
   控制台同时打印 **大小与 MD5**，建议记录到刷机记录里。
5. 备份结束设备会自动复位，控制台切回 `115200`。

注意：

- 备份是**只读**操作：不消耗烧录码、不改动设备现有固件；
- 容量跟随实测 Flash，而不是跟随镜像大小 —— C5N16R8 这类 16MB 板子会读满 16MB；
- 读取期间会短暂断开串口控制台，**不要拔线**；16MB 约需 3–5 分钟（921600 波特率）；
- 恢复备份：

  ```powershell
  # esptool v5；v4 用 write_flash
  esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x0 esp32c5_backup_16mb_20261111-1530.bin
  ```

- 浏览器内存需能容纳整片数据（16MB 备份约占用 32–48MB），桌面版 Chrome/Edge 无压力；
  读取失败时改用第 2 节命令行 `read-flash`（更易降速排查）。

---

## 2. 方式二：命令行 esptool（开发 / 批量）

### 2.1 找到镜像并核对 MD5

镜像在 `server/firmware/firmware-<chip>-<version>.bin`，MD5 以 manifest 为准：

```bash
curl http://localhost:8787/api/firmware/manifest
```

校验文件：

```powershell
# Windows PowerShell
certutil -hashfile server\firmware\firmware-esp32-1.1.0.bin MD5
```

```bash
# macOS
md5 server/firmware/firmware-esp32-1.1.0.bin
# Linux
md5sum server/firmware/firmware-esp32-1.1.0.bin
```

MD5 与 manifest 不一致时**不要烧录**：重新运行 `sh tools/build-firmware.sh <版本>` 构建并注册。

### 2.2 写入

```powershell
# Windows（脚本会自动探测的 esptool 也可直接用完整路径）
python -m esptool --chip esp32 -p COM3 -b 460800 write-flash 0x0 server\firmware\firmware-esp32-1.1.0.bin
```

```bash
# macOS
python3 -m esptool --chip esp32c3 -p /dev/cu.usbserial-0001 -b 460800 \
  write-flash 0x0 server/firmware/firmware-esp32c3-1.1.0.bin

# Linux
python3 -m esptool --chip esp32s3 -p /dev/ttyUSB0 -b 460800 \
  write-flash 0x0 server/firmware/firmware-esp32s3-1.1.0.bin
```

说明：

- 以上为 **esptool v5** 写法（子命令用连字符）；**v4 及更早版本**用下划线
  （`write_flash` / `read_flash` / `erase_flash`），且可加 `--verify` 让写入后回读校验。
  v5 默认会校验写入结果，但没有 `--verify` 选项。
- 只装了 PlatformIO、没有 Python esptool 时，可把 `python -m esptool` 换成
  `%USERPROFILE%\.platformio\packages\tool-esptool\esptool.exe`（macOS/Linux 为
  `~/.platformio/packages/tool-esptool/esptool`）。
- `--chip` 可填 `esp32` / `esp32s2` / `esp32s3` / `esp32c3` / `esp32c5` / `esp32c6`。
  `auto` 也可用，但显式指定更稳。
- **必须从 `0x0` 写整片镜像**，不要写 `0x10000`：bootloader / 分区表 / app 已在镜像内按芯片偏移排好
  （见 README「合并镜像布局与 Bootloader 偏移」）。
- 460800 失败时可降到 `115200`；成功后可加 `--after hard-reset` 自动复位。
- 需要清空 NVS / 重新生成口令时，可先执行
  `python -m esptool --chip <chip> -p <port> erase-flash`，再按上面命令写入。
- Linux 串口权限：`sudo usermod -aG dialout $USER`，重新登录后生效。

---

## 3. 常见问题

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 串口列表为空 | 充电线 / 驱动未装 / 浏览器不支持 / 串口被占用 / Linux 无权限 | 换数据线；装 CP210x 或 CH340 驱动；改用 Chrome/Edge；关闭其他串口工具；加 `dialout` 组 |
| 连接失败或识别不到芯片 | 未进入下载模式 / 自动复位失效 | 按住 BOOT → 点连接（或点 RESET）→ 松开 BOOT；或勾「跳过自动复位」；CLI 降到 115200 |
| 校验码返回 `429` | 触发限流（10 次/分钟/IP） | 等 1 分钟再试；不要连续点击 |
| 校验码提示已使用 | 一次性码已核销 | 重新发码；烧录失败不会核销，可重新校验 |
| 烧录中途失败 | USB 线/供电不稳、速率过高、串口被抢占 | 换线换口；关闭其他串口工具；用 CLI 以 460800/115200 重烧；重新校验烧录码 |
| 提示镜像 MD5 或大小不一致 | manifest 与磁盘文件不同步 | 重新构建并注册镜像；不要强行烧录 |
| 烧完没有热点 | 未重新上电 / 板子 Flash 不足 4MB / 镜像芯片不匹配 | 断电重上电；确认 4MB Flash；看 115200 启动日志；按实际芯片重烧 |
| 后台登录 401 | 口令错误、大小写/空格、已改过口令 | 使用串口首次打印的 12 位口令；确认无多余空格；改过则用新口令 |
| 输入 `esp32admin` 无效 | 该值是旧版遗留默认值，仅用于升级识别 | 使用串口输出的随机初始口令 |
| 网页备份读不出来 / 中途失败 | 高速率不稳、供电不足、串口被其他程序占用 | 关闭其他串口工具、换线换口后重试；或用命令行 `read-flash` 降到 460800/115200；备份只读，失败不影响设备 |
| 忘记后台口令 | 口令只存 NVS，无物理重置入口 | 重新烧录整片镜像（或 `erase-flash`）→ 首次启动重新生成口令 |
| C5 启动反复打印 `invalid header: 0xa8030007` | 用 `pio run -t upload` 直接烧时 bootloader 被写到 0x0（C5 应在 0x2000） | 见 §5.7；改用合并镜像从 0x0 整片写入，或 `pio run` 已由 post 脚本自动修正偏移后重烧 |
| C5 原生 USB 口（CDC）重启后消失 | 射频反复重启后 USB CDC 未重新枚举 | 用 CH340 的 UART 口（如 COM5）抓日志 / 复位，见 §5.7；不是板子变砖 |
| 起邪恶双子后管理热点 `WiFi-12F9` 消失 | 克隆阶段软 AP 已真实改名为目标 SSID（开放） | 属预期行为；攻击停止或复位后恢复 `WiFi-12F9`，见 §5.7 |

---

## 4. 附：镜像与安全说明

- 6 个芯片的镜像均为 **4MB 整片镜像**，下载与写入前都会校验 MD5/大小；
- 镜像内已包含后台 SPA（`admin.html` 经 zlib 压缩内嵌），无需额外上传文件系统；
- 后台初始口令由硬件 TRNG 生成、仅串口显示一次；修改后以 NVS 中的值为准；
- 烧录码与设备后台口令是两套独立凭据：前者保护发码/注册，后者保护设备 `/api/*`；
- 详细构建流程见 [README「快速开始」](../README.md#快速开始本地跑通)，
  API 清单见 [README「设备端 API」](../README.md#设备端-api19216841)。

---

## 5. 附：ESP32-C5N16R8 首刷检查清单

C5N16R8 = **16MB Flash + 8MB PSRAM**，而本工程的 C5 镜像是 **4MB 整片镜像**：
只使用前 4MB，剩余 12MB 空闲；固件未启用 PSRAM，不会因为 PSRAM 配置导致启动失败。
C5 目前为实验性支持，建议首刷用命令行，先只读、再备份、最后写入。

### 5.1 先只读，确认板子身份

```powershell
# esptool v5；v4 用 flash_id / read_mac
esptool --chip esp32c5 -p COM5 flash-id
esptool --chip esp32c5 -p COM5 read-mac
```

确认输出为 `Chip is ESP32-C5`、`Detected flash size: 16MB`。
若只识别到 4MB，先换线/换口复核，不要急着写。

> 若提示找不到 `esptool`，改用 `python -m esptool`，或使用 PlatformIO 自带的
> `%USERPROFILE%\.platformio\packages\tool-esptool\esptool.exe`（见 2.2 节）。

> C5 已开启 USB CDC：原生 USB 口（COM3）与 UART 口（CH340，如 COM5）都能看到启动日志；
> 射频反复重启后原生 USB CDC 可能不再重新枚举，此时改用 UART 口。
> 自动复位失败时：按住 **BOOT** → 点一下 **RST/EN** → 松开 BOOT，再执行命令。

### 5.2 备份整片 16MB Flash（首刷最重要的一步）

```powershell
# v4 用 read_flash
esptool --chip esp32c5 -p COM5 -b 460800 read-flash 0x0 0x1000000 c5n16r8-backup.bin
```

16MB 读取需要几分钟，中途不要拔线。保留这份备份，最坏情况可以整片恢复。
网页烧录台也支持一键备份（见 [1.6](#16-一键备份整片-flash推荐首刷前做一次)）：连上后点「💾 备份固件」即可，
容量自动识别；若网页端读取失败，再用上面这条命令行 `read-flash` 备份（可降速排查）。

### 5.3 命令行首刷（460800，先不追求高速）

```powershell
# v4 用 write_flash；v5 无 --verify 选项
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x0 server\firmware\firmware-esp32c5-1.1.0.bin
```

- 必须从 `0x0` 写整片，**不要**写 `0x2000` 或 `0x10000`；
- ESP32-C5 有两个镜像，别选错：`firmware-esp32c5-*.bin` 是 4MB/min_spiffs 版，
  `firmware-esp32c5_16mb-*.bin` 才是 16MB 三系统分区表版（见 §6，做 Triple-Boot 必须用后者）；
- 保持镜像原样写入，写到 16MB 板子的前 4MB 是安全的（不会动 `0x400000` 之后的 ota_1/ota_2）；
- esptool **v5 没有 `--verify` 选项**，需要回读校验时用
  `verify-flash 0x0 <镜像>`；v4 可在 `write_flash` 后加 `--verify`；
- 不要加 `--erase-all`，也不要用 `--override-vddsdio` 之类电压覆盖；
- 稳定后网页烧录台或 921600 都可以用（0.7.1 版 esptool-js 已内置 ESP32-C5 目标，
  网页端能自动识别 C5，无需手动指定）。

### 5.4 看启动日志

```powershell
# 运行应用；或直接用烧录台「串口控制台」(115200)
esptool --chip esp32c5 -p COM5 -b 115200 run
```

重点确认：

- `[wifi] AP 已启动: SSID=WiFi-xxxx ...`
- `[admin] ===== 首次上电: 后台初始口令 (仅显示这一次) =====`
- 没有反复出现 `rst:0x...` 重启

### 5.5 启动失败 / 反复重启的恢复

先抓一次完整串口日志，不要反复上电。进入下载模式后：

```powershell
# 1) 清空 Flash（会丢 NVS/口令）
esptool --chip esp32c5 -p COM5 erase-flash

# 2) 重刷 4MB 镜像
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x0 server\firmware\firmware-esp32c5-1.1.0.bin

# 或彻底恢复到出厂备份（16MB，耗时较长）
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x0 c5n16r8-backup.bin
```

> 软件刷写不会永久变砖：即使 bootloader 被写坏，ROM 下载模式仍可通过
> BOOT + RST 进入并重刷。真正不可逆的是 eFuse 安全启动/Flash 加密被启用，
> 或硬件损坏；本项目镜像不涉及这两项。

### 5.6 C5N16R8 首刷不要做的事

- 不要把网页烧录台的型号手动改成其他芯片（自动识别优先，防烧错镜像；
  只有做 16MB 三系统时才需要手动选同芯片的 `ESP32-C5 (16MB 三系统)` 变体）；
- 不要往 4MB 镜像上强行套 16MB 分区表 / 改 bootloader 头：要用满 16MB 请直接
  构建并烧录 `esp32c5_16mb` 专用镜像（见 §6），两个镜像在烧录台里分开注册；
- 不要因为个别 raw TX 报错就判断板子坏：C5 的帧类型白名单已解除（Deauth/Disassoc
  真机可发），广播 Deauth 被 Wi-Fi 6 终端丢弃时会转而学习客户端 MAC 做单播定向踢线；
  若某平台仍拒绝，后台会如实显示错误码；
- 不要用劣质 USB 线或供电不足的 Hub 刷写，写入中断虽可恢复，但会增加排查成本。

### 5.7 `pio run -t upload` 开发态烧录（C5 bootloader 偏移坑）

网页烧录台 / 命令行写的是 **合并镜像**，从 `0x0` 整片写入，bootloader 已在镜像内
按芯片排好（C5 在 `0x2000`），不会踩坑。但开发时常用的
`pio run -e esp32c5_16mb -t upload` 走的是 PlatformIO 的分段写入：

- `framework-arduinoespressif32/tools/platformio-build.py` 的 `FLASH_EXTRA_IMAGES`
  对 riscv 芯片统一用 `0x0000`（只有 esp32/esp32s2 用 `0x1000`），而 **ESP32-C5 的
  二阶段 bootloader 实际位于 `0x2000`**（arduino `boards.txt`：
  `esp32c5.build.bootloader_addr=0x2000`，PlatformIO 不读该文件）。
- 后果：`pio upload` 把 bootloader 写到 `0x0`，`0x2000` 处无合法镜像头，上电 ROM
  反复打印 `invalid header: 0xa8030007` +
  `assertion "result == ETS_OK" failed: ... ets_flash_boot`，无限复位。

**已修复（2026-11-13，提交 `ff62eda`）**：

- `firmware/platformio.ini` 的 `[env:esp32c5_16mb]` 加
  `board_build.bootloader_addr = 0x2000` 并**显式重写** `extra_scripts`（该选项不会
  自动继承 `[env]`，必须再带上 `pre:tools/embed_admin_page.py`）：
  ```ini
  extra_scripts =
      pre:tools/embed_admin_page.py
      post:tools/fix_c5_bootloader_offset.py
  ```
- `post` 脚本同时修正 `FLASH_EXTRA_IMAGES` 与**已经展开的** `UPLOADERFLAGS`（pre 阶段
  框架还没追加镜像，改不到），仅 `mcu == esp32c5` 生效。
- 自检：`pio run -e esp32c5_16mb -t upload -v --upload-port COM99` 的 esptool 命令行
  应出现 `write-flash ... 0x2000 ...bootloader.bin 0x8000 ...partitions.bin
  0xe000 ...boot_app0.bin 0x10000 ...firmware.bin`。真机实烧后串口 `invalid header`
  计数为 0、正常打印 `v1.1.0` 启动横幅。

**若仍用旧配置刷坏了**（无限复位）：用 esptool 按正确偏移手动重烧即可救回，
不需要再次整片擦除：

```powershell
esptool --chip esp32c5 -p COM5 -b 921600 write-flash -z `
  --flash-mode dio --flash-freq 80m --flash-size 16MB `
  0x2000 .pio\build\esp32c5_16mb\bootloader.bin `
  0x8000 .pio\build\esp32c5_16mb\partitions.bin `
  0xe000 "$env:USERPROFILE\.platformio\packages\framework-arduinoespressif32\tools\partitions\boot_app0.bin" `
  0x10000 .pio\build\esp32c5_16mb\firmware.bin
```

### 5.8 C5N16R8 射频重启后的串口 / 热点现象（排障）

- **原生 USB CDC（COM3）可能不再重新枚举**：邪恶双子 / 双频跳频会让射频反复
  stop/start，实测此后原生 USB 口在设备管理器里消失，但板载 CH340 的 UART 口
  （本板为 **COM5**）始终可用，`esptool --chip esp32c5 -p COM5 chip_id` 能读到 MAC。
  用 UART 口正常启动的复位时序：`DTR=1`（拉低 EN）→ 200ms → `DTR=0`；esptool /
  烧录台的 `--after hard-reset` 也会触发复位。这不是变砖。
- **起攻击后 `WiFi-12F9` 热点消失**：克隆阶段把软 AP **真实改名**为目标 SSID
  （本环境 `WiFi6`，开放无密码）并驻留到主目标信道；管理热点自然不可见。
  单射频双频覆盖时克隆热点会在 5G ch149 与双子 2.4G ch11 之间每 2s 跳一次，
  扫描结果时有时无属预期。停止攻击或复位后恢复 `WiFi-12F9` / `00000000` / 管理页。
- **板子 RTS 接复位脚**：开/关串口或动 RTS 都会触发复位，长时间挂串口会打断验证；
  纯 HTTP 验证时不要保持 COM 长连接。

---

## 6. 附：16MB Flash 三系统 (Triple-Boot) 部署说明

针对 ESP32-C5N16R8 等 16MB Flash 开发板，本工程支持在单块板子上同时部署并无缝切换三个系统：
1. **Wi-Fi 安全审计平台**（`ota_0`，本工程固件）
2. **ESPsoup 口袋 SDR 模式**（`ota_1`，全频段接收机与瀑布图）
3. **Meta Muse AI 伴侣模式**（`ota_2`，Wi-Fi 6 联网与智能家居网关）

### 6.1 镜像与构建 env 的对应关系

C5 有两个镜像，烧录台里分开注册，**别选错**：

| chip key / env | 分区表 | 适用板子 | 说明 |
|---|---|---|---|
| `esp32c5` | `min_spiffs.csv` | 4MB Flash C5 | 双 app 槽（`app0 @0x10000` / `app1 @0x1F0000`），无 `ota_2` |
| `esp32c5_16mb` | `partitions-16mb-triple.csv` | 16MB Flash C5（C5N16R8） | `ota_0/1/2` 各 3.9375MB + 共享 spiffs |

- `esp32c5_16mb` 通过 `extends = env:esp32c5` 复用 4MB 版配置，只覆盖分区表与
  Flash 容量（`board_upload.flash_size = 16MB`、`maximum_size = 16777216`）；
- esptool 的物理芯片型号仍是 **`esp32c5`**：`tools/build-firmware.sh` 内部用
  `ESPTOOL_CHIP` 做映射，bootloader 偏移同样是 `0x2000`；
- 合并镜像仍按 **4MB** pad（`merge-bin --pad-to-size 4MB`），只覆盖
  `0x10000–0x3FFFFF` 的 `ota_0` 范围，不会碰 `0x400000` 的 `ota_1` 与 `0x7F0000` 的
  `ota_2`，因此重复刷新审计固件不会抹掉另外两个系统。

### 6.2 分区规划（`firmware/partitions-16mb-triple.csv`）

```text
0x009000  nvs         (16KB)
0x00d000  otadata     (8KB, 引导状态)
0x00f000  phy_init    (4KB)
0x010000  ota_0       (3.9375MB) -> Wi-Fi 安全审计平台
0x400000  ota_1       (3.9375MB) -> ESPsoup 口袋 SDR 固件
0x7F0000  ota_2       (3.9375MB) -> Meta Muse AI 伴侣固件
0xBE0000  spiffs      (4.0625MB) -> 共享存储与数据区
```

> ⚠️ 该 CSV **必须保持纯 ASCII**（注释也只能用英文）：PlatformIO 在 Windows 下按
> 系统默认编码（GBK）解析 `board_build.partitions`，出现中文会直接
> `UnicodeDecodeError` 构建失败。契约测试会校验这一点。

### 6.3 部署步骤（网页烧录台直接刷写 或 命令行写入）

**前置：先把 16MB 三系统基础镜像刷进 `ota_0`**

三系统分区表只内建在 `esp32c5_16mb` 这个专用构建里（4MB 版 `esp32c5` 仍是
min_spiffs，`0x400000` / `0x7F0000` 在它下面不可引导）。先构建并注册该镜像：

```bash
tools/build-firmware.sh            # 产出 server/firmware/firmware-esp32c5_16mb-<版本>.bin
```

然后在网页烧录台里**手动**把型号选成 `ESP32-C5 (16MB 三系统)`（自动识别只会匹配到
4MB 版 `esp32c5`，手动选中的同芯片变体会被保留），再从 `0x0` 整片刷入；或命令行：

```powershell
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x0 server\firmware\firmware-esp32c5_16mb-1.1.0.bin
```

该镜像实际只占前 4MB（bootloader + 分区表 + `ota_0` app），不会覆盖
`0x400000` 之后的 `ota_1` / `ota_2`，所以重复刷新审计固件不会抹掉已写入的
ESPsoup / Muse。

**方式 A：直接在网页烧录台（Flasher）界面刷入（最推荐，免敲命令）**
1. 访问本地烧录台（如 `http://127.0.0.1:8787`）；
2. 连上开发板后，在步骤 ③ 卡片下方的 **「🧩 多系统 / 外部固件刷写」** 区域：
   - 目标系统分区选择：`ota_2 (0x7F0000) — Meta Muse AI 伴侣模式`；
   - 点击「📁 选择本地 .bin 固件」选中你的 `muse.bin`；
   - 点击 **「⚡ 刷入指定系统分区」**，进度条跑满即可完成烧录，不影响其他分区！
   - 同理，刷写 ESPsoup 固件只需选择 `ota_1 (0x400000)` 并上传对应镜像即可。

**方式 B：命令行写入独立分区**

```powershell
# 1. 刷入当前安全审计固件至 ota_0 (从 0x10000; 需先有 16MB 分区表)
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x10000 .pio\build\esp32c5_16mb\firmware.bin

# 2. 刷入 ESPsoup 固件至 ota_1 (从 0x400000)
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x400000 espsoup-c5.bin

# 3. 刷入 Meta Muse AI 固件至 ota_2 (从 0x7F0000)
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x7F0000 muse-c5.bin
```

### 6.4 切换方式

- **Web 后台一键切换**：进入后台「配置」页面的 **多系统引导管理 (Triple-Boot)** 卡片，点击目标系统的 `[点击切换至]` 按钮确认即可重启进入；
- **串口 CLI 命令切换**：在串口控制台输入 `boot` 查看槽位状态，输入 `boot espsoup` 或 `boot muse` 或 `boot audit` 即刻切换并重启。

### 6.5 构建产物自检（刷机前，不需要硬件）

```powershell
# 1) 16MB 环境能否构建（应 SUCCESS, Flash 上限 4128768 字节）
cd firmware
pio run -e esp32c5_16mb

# 2) 反解生成的分区表，确认三个 app 槽偏移/大小
python "$env:USERPROFILE\.platformio\packages\framework-arduinoespressif32\tools\gen_esp32part.py" `
  .pio\build\esp32c5_16mb\partitions.bin
# 期望: ota_0=0x10000 / ota_1=0x400000 / ota_2=0x7f0000, 各 4032K, spiffs=0xbe0000 4160K

# 3) 合并镜像自检: 必须正好 4MB, 0x2000 处为 0xE9 (bootloader), 0x8000 处为 0xAA50 (分区表)
esptool --chip esp32c5 merge-bin --pad-to-size 4MB -o merged-16mb.bin `
  0x2000 .pio\build\esp32c5_16mb\bootloader.bin `
  0x8000 .pio\build\esp32c5_16mb\partitions.bin `
  0x10000 .pio\build\esp32c5_16mb\firmware.bin

# 3b) 或直接读字节确认（size 应为 4194304）
$d = [IO.File]::ReadAllBytes('merged-16mb.bin')
"{0} bytes; magic @0x2000=0x{1:X2}, @0x8000=0x{2:X2}{3:X2}" -f $d.Length, $d[0x2000], $d[0x8000], $d[0x8001]

# 4) 契约测试（含 16MB env / 分区偏移 / 烧录台变体契约）
cd ..\server; npm test
```

### 6.6 真机验证清单（有 16MB 板时按序执行）

| # | 操作 | 期望结果 |
|---|---|---|
| 1 | `esptool --chip esp32c5 -p COM5 flash-id` | `Chip is ESP32-C5`、`Detected flash size: 16MB` |
| 2 | 烧录台手动选 `ESP32-C5 (16MB 三系统)`，从 `0x0` 刷合并镜像 | 进度跑满；串口能看到审计固件启动日志 |
| 3 | 串口输入 `boot` | 列出 audit / espsoup / muse 三个槽，audit 标记为当前运行 |
| 4 | 「外部固件刷写」向 `0x400000` 写 ESPsoup、`0x7F0000` 写 Muse | 两次写入均完成，MD5/大小校验通过 |
| 5 | `boot espsoup` 或后台点「切换至 ESPsoup」 | 重启进入 ESPsoup；反向 `boot audit` 能切回 |
| 6 | 再刷一次审计固件（`0x0` 整片 4MB 镜像） | 审计固件正常启动，且 `boot` 里 espsoup/muse 仍显示已安装 |
| 7 | 重复步骤 5 | 两个外部系统仍可正常切换启动 |

> 第 6 步是关键回归：验证 4MB pad 的合并镜像只覆盖 `ota_0`，不会清掉
> `0x400000` / `0x7F0000` 的外部系统。

### 6.7 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| 后台切换报「未找到分区 (需 16MB 多系统分区表)」 | 板子里跑的还是 4MB 版 `esp32c5` 镜像；改刷 `esp32c5_16mb` |
| 烧录台自动识别后又变回 4MB 镜像 | 已修复：手动选中的同芯片变体（`esp32c5_16mb`）会被保留；若仍被覆盖，检查是否选中了「自动识别」 |
| 构建报 `UnicodeDecodeError: 'gbk' codec ...` | `partitions-16mb-triple.csv` 混入了非 ASCII 字符（注释也算） |
| `merge-bin` 报镜像超过 4MB | `ota_0` 只有 3.9375MB；需裁剪固件或调整分区表 |
| 写入 `0x400000` 后无法引导 | 确认写入的是**应用镜像**（`firmware.bin` / 厂商 app bin），不是整片合并镜像 |

---

## 7. 便携脱机扩展套件指南（0.96寸 OLED 屏幕 + 蜂鸣器）

固件集成了针对 **ESP32-C5-DevKit V2.0 (HW-982)** 优化的脱机便携扩展模块，完全脱离电脑与手机后台，实现随身掌上渗透/审计设备。

### 7.1 硬件接线对照表 (30P 开发板)

开发板为标准 30 针（两排各 15 针，2.54mm 针距）。推荐使用 4 根母对母杜邦线直连：

| 外设模块 | 外设引脚 | 开发板引脚 (参考背面丝印) | 说明 |
|---|---|---|---|
| **0.96寸 OLED (I2C)** | **GND** | **G (GND)** | 地线 |
| | **VCC** | **3V3** | 3.3V 稳压电源 |
| | **SCL** | **IO 5** | I2C 硬件时钟线 |
| | **SDA** | **IO 4** | I2C 硬件数据线 |
| **蜂鸣器 (无源/有源)** | **正极 (+)** | **IO 13** | PWM 音频驱动引脚 |
| | **负极 (-)** | **G (GND)** | 地线 |

> 驱动说明：内置轻量 `firmware/src/ssd1306_tiny.h`，纯基于 `Wire.h` 硬件 I2C，零第三方库依赖，仅消耗 1024 字节显存缓冲与 475 字节内置 ASCII 5x7 字符模，编译快、内存开销极小。

### 7.2 屏幕双模式智能交互

屏幕无需任何按键，运行中全自动智能切换：
1. **常规状态仪表盘（未捕获密码时）**：
   - 第 1 行：本机软 AP 名称 `AP: WiFi-xxxx`
   - 第 2 行：当前核心模块运行状态 `[EvilTwin]` / `[Deauth]` / `[Idle]`
   - 第 3 行：当前锁定目标 `Tgt: <SSID>`
   - 第 4 行：已连接受害者客户端数与已捕获凭据数 `Cli: 1  Cred: 0`
   - 第 5 行：可用堆内存与开机运行时间 `Heap: 248K  Up: 120s`
2. **凭据捕获直显页（捕获到密码时自动切屏）**：
   - 只要有受害者在钓鱼门户提交密码，屏幕**瞬间切换**为凭据展示页；
   - 顶部标注验真状态（`[VERIFIED] PWD:` 或 `[CAPTURED] PWD:`）；
   - 中间区域以 **12×16 像素双倍大字体直接明文显示密码**；
   - 底部显示提交该密码的客户端 IP；
   - 配合蜂鸣器音效：通过本地 PBKDF2+MIC 验真的真密码触发“上扬胜利三音”，未校验密码触发“警报双音”。

### 7.3 开发板双 Type-C 接口注意事项

HW-982 板载两个 Type-C 接口：
- **上方接口（印有 UART）**：板载独立 USB 转串口芯片，连接稳定，开发板重启不会导致 Windows USB 端口重枚举，日常烧录最推荐。
- **下方接口（原生 USB）**：直连 C5 芯片内部 USB-CDC / JTAG 控制器。固件已启用 `ARDUINO_USB_CDC_ON_BOOT=1`，同样支持正常烧录与日志查看。
  - **避坑提示 1**：烧录前必须关闭 Arduino IDE 等软件的串口监视器，避免独占 COM 口报错。
  - **避坑提示 2**：若上位机串口工具未正确释放 DTR/RTS 导致板子卡在 `ESP-ROM` 引导行，拔插一次 USB 线（冷重启）即可正常加载应用程序。

