# 刷固件说明（网页烧录台 / 命令行）

适用于固件 **v1.1.0**，芯片 `esp32 / esp32s2 / esp32s3 / esp32c3 / esp32c5 / esp32c6`。
镜像为 **4MB 整片合并镜像**，从 `0x0` 一次写入。

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

> 原生 USB 开发板（S3 / C3 / C6 / C5 常见两个 USB 口）请连接标注 **UART** 的口；
> 本固件未启用 USB CDC，连接原生 USB 口可能无法识别串口。

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
| 忘记后台口令 | 口令只存 NVS，无物理重置入口 | 重新烧录整片镜像（或 `erase-flash`）→ 首次启动重新生成口令 |
| C5 部分功能报错 | C5 对 raw TX 的 SDK 支持受限（实验性） | 属预期行为，后台会显示错误码；刷写与后台本身不受影响 |

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

> 连接板子标注 **UART** 的 USB 口；固件未启用 USB CDC，只接原生 USB 口可能看不到启动日志。
> 自动复位失败时：按住 **BOOT** → 点一下 **RST/EN** → 松开 BOOT，再执行命令。

### 5.2 备份整片 16MB Flash（首刷最重要的一步）

```powershell
# v4 用 read_flash
esptool --chip esp32c5 -p COM5 -b 460800 read-flash 0x0 0x1000000 c5n16r8-backup.bin
```

16MB 读取需要几分钟，中途不要拔线。保留这份备份，最坏情况可以整片恢复。
网页烧录台目前**没有**读回/备份功能，备份必须走命令行。

### 5.3 命令行首刷（460800，先不追求高速）

```powershell
# v4 用 write_flash；v5 无 --verify 选项
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x0 server\firmware\firmware-esp32c5-1.1.0.bin
```

- 必须从 `0x0` 写整片，**不要**写 `0x2000` 或 `0x10000`；
- 保持 4MB 镜像原样，写到 16MB 板子的前 4MB 是安全的；
- esptool **v5 没有 `--verify` 选项**，需要回读校验时用
  `verify-flash 0x0 <镜像>`；v4 可在 `write_flash` 后加 `--verify`；
- 不要加 `--erase-all`，也不要用 `--override-vddsdio` 之类电压覆盖；
- 稳定后网页烧录台或 921600 都可以用。

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

- 不要把网页烧录台的型号手动改成其他芯片（自动识别优先，防烧错镜像）；
- 不要往 4MB 镜像上强行套 16MB 分区表 / 改 bootloader 头；要用满 16MB 需重新
  生成分区表并重建镜像，属于后续优化，不是首刷目标；
- 不要因为 Deauth / raw TX 报错就判断板子坏：C5 对 raw TX 的 SDK 支持受限，
  后台会如实显示错误码；
- 不要用劣质 USB 线或供电不足的 Hub 刷写，写入中断虽可恢复，但会增加排查成本。
