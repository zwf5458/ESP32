# ESP32 无线网络开发固件 · 烧录台 + 固件 整套（本地版）

参考 [ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder) 与
[esp32.ssaa.cc.cd 烧录台](https://esp32.ssaa.cc.cd/) 的完整链路复刻：

> 网页连串口 → 校验一次性烧录码 → esptool-js 整片烧录（0x0 起）
> → 成功后后端核销 → 板子出热点 `WiFi-xxxx`（密码 `00000000`）
> → 后台 `http://192.168.4.1/admin.html`

⚠️ 仅供网络安全学习研究，严禁用于非法用途。

## 快速开始（本地跑通）

```bash
# 1. 启动后端（静态资源用绝对路径, 任意 cwd 均可启动）
npm start   # 或 node server/src/index.js
# → 烧录台: http://localhost:8787

# 2. 生成测试烧录码 (全平台通用)
npm run gen-code -- 3   # 或 node tools/gen-code.mjs 3
# 也支持查看列表与统计: npm run codes / npm run stats

# 3. 运行自动化测试套件
npm test

# 4. 浏览器 (Chrome/Edge) 打开 http://localhost:8787
#    选串口 → 输烧录码校验 → 勾条款 → 开始烧录
#    首刷前可先用「💾 备份固件」只读整片 Flash（不消耗烧录码）
#    完整刷机步骤 / 命令行 esptool / 常见问题: docs/firmware-flashing.md

# 5. 编译固件镜像并注册（环境搭建见下节；需保持第 1 步的后端在运行）
sh tools/build-firmware.sh 1.1.0
```

`build-firmware.sh` 会先探测后端与 `esptool`（PlatformIO venv 脚本 → 工具链自带
`esptool.exe` → `PATH`），再逐个 env 编译、`merge-bin` 合并、注册到后端。版本号经
`PLATFORMIO_BUILD_FLAGS` 注入（`pio run` 并无 `--build-flag` 选项）；直接 `pio run`
时由 `main.cpp` 的 `#ifndef FW_VERSION` 兜底。可用环境变量 `BASE` / `ADMIN_TOKEN` /
`ESPTOOL` / `BUILD_DIR` 覆盖默认值。发布构建默认落在独立的 `firmware/.pio/build-release`
（与开发态 `pio run` 的 `.pio/build` 隔离，后续重跑为增量构建）；`BUILD_DIR` 另指向一个
全新目录可做不覆写旧对象文件的干净全量构建。

烧录成功后：手机/电脑连接热点 `WiFi-xxxx`（密码 `00000000`），
会自动弹出固件后台（Captive Portal 强制门户）；若未弹窗，手动访问
`http://192.168.4.1/admin.html`
（11 页：状态总览 / 扫描与嗅探 / 邪恶双子 / Karma / 取消认证 / 数据包分析器 / Airodump /
BLE 扫描 / 802.15.4 扫描 / 捕获凭据 / 配置）。**首次上电时设备会用硬件 TRNG 生成一台一密的随机后台
初始口令**，仅在 115200 串口启动日志中打印一次（可用烧录台「串口控制台」查看），不出现在
网页、NDJSON 遥测或 `/api/log` 里；首次登录会直接落到「配置」页引导修改口令。
之后所有 `/api/*` 管理接口均需携带 `X-Admin-Token` 请求头。

## 功能范围与合规边界

本项目固件是面向**自有网络 / 书面授权受测环境**的无线教学验证工具：
所有模块均需在后台显式启停、状态与计数如实回显，不做隐蔽驻留或规模化攻击形态
（与 ESP32 Marauder / WatchDogsGo 一类成品攻击固件划清界限）。
能力矩阵（6 颗芯片行为一致）：

| 模块 | 状态 | 说明 |
|---|---|---|
| AP 热点 | ✅ 实现 | SSID `WiFi-xxxx`（MAC 尾 4 位）/ 密码 `00000000` / `192.168.4.1` |
| Web 后台 11 页 | ✅ 实现 | 状态总览 / 扫描与嗅探 / 邪恶双子 / Karma / 取消认证 / 数据包分析器 / Airodump / BLE 扫描 / 802.15.4 扫描 / 捕获凭据 / 配置（内嵌 SPA） |
| 后台口令鉴权 | ✅ 实现 | 每台设备随机初始口令（仅串口打印一次）；`/api/*` 需 `X-Admin-Token`（或 `?token=`），401 不执行业务逻辑 |
| Captive Portal | ✅ 实现 | UDP 53 通配解析 + iOS/Android/Windows 探测路径 302 → 连热点自动弹后台 |
| 周边 AP 扫描 | ✅ 实现 | `WiFi.scanNetworks()` 被动列出 SSID/RSSI/信道/加密方式 |
| 已连客户端计数 | ✅ 实现 | `softAPgetStationNum()` 只读计数 |
| 事件日志 | ✅ 实现 | 64 条环形缓冲，`GET /api/log?since=` 增量拉取 |
| 内存/运行诊断 | ✅ 实现 | 堆、PSRAM、信道、uptime |
| Evil Twin（邪恶双子） | ✅ 真实实现 | 攻击时把本机热点**真实改名**为与主目标一模一样的 SSID（开放无密码、信道对齐主目标）→ 目标设备免密直连；同时自动对主目标持续注入 Deauth，并对双子目标（通常同路由 5G BSSID）每 2s 跳频连发注入 → 目标两个频段都无法联网；Captive Portal 自动弹钓鱼页，捕获第一条凭据后自动停止干扰，手动停止恢复原热点名/密码/信道 |
| Deauther（WiFi 杀手） | ✅ 真实实现 | 经 `esp_wifi_80211_tx` 向空口注入真实 Deauthentication 管理帧（0x00c0，广播踢出目标 AP 下全部客户端），带 Reason Code 与帧率/计数遥测。启动时自动把热点切到目标信道（已连受测设备短暂掉线后自动重连），停止时恢复配置信道；C5 raw TX 受限时返回错误码并如实显示 |
| Handshake / 握手包与跑包 | ✅ 真实实现 | `esp_wifi_set_promiscuous` 真实空口捕获 4-Way Handshake（M1~M4，含 PMKID KDE）；板载用内置 7,153 条弱口令逐条跑包（PMK=PBKDF2-HMAC-SHA1 4096 轮 → PTK → 重算 M2 的 MIC 比对，支持 keyver 1/2）。keyver 3（802.11w PMF）导出后交服务端 `/api/wpa/crack`（SHA256-KDF + AES-CMAC） |
| 数据包分析器 (Sniffer) | ✅ 真实实现 | 共用 promiscuous 回调抓真实 802.11 管理/控制/数据帧，解析帧类型、源/目的 MAC、SSID、Deauth Reason；支持单信道停驻与 1-13 自动跳频，实时帧率统计 |
| Airodump 侦察 | ✅ 真实实现 | 从真实空口帧按 MAC 聚合对端（RSSI / 帧数 / 探测过的 SSID），支持 1-13 跳频；与 Evil Twin / Deauth / 握手捕获并行时停驻当前信道，避免破坏射频状态 |
| Karma 探针诱捕 | ✅ 真实实现 | 监听真实 Probe Request，记录客户端 MAC / 目标 SSID / RSSI；SSID 命中当前克隆热点时标记为「已诱捕」，并复用握手捕获链路同步收集 4-Way Handshake |
| BLE 广播嗅探 | ✅ 真实实现 | 纯被动监听周边 BLE 广播（ADV_IND / SCAN_RSP 等），解析 MAC / 名称 / RSSI / 广播类型 / 厂商数据摘要 / 广播计数；不发 SCAN_REQ、不连接设备。C3/C5/C6/S3 开放（NimBLE 后端），经典 ESP32 因 Bluedroid 体积与双 app 槽冲突而裁剪，S2 无蓝牙硬件 |
| 802.15.4 嗅探 | ✅ 真实实现 | 纯被动接收 IEEE 802.15.4 帧（Zigbee / Thread / 智能家居），解析帧类型 / PAN ID / 源地址 / RSSI / LQI，并对 11-26 信道做能量检测（dBm）；promiscuous 模式只收不发、不自动 ACK、不注入。仅 ESP32-C5 / C6 具备该射频，其余芯片整页隐藏且 API 返回 501；与 WiFi 2.4G 共用射频，AP 保持在线、抓包为分时采样 |

**Evil Twin 自 2026-11-10 起为真实实现**（热点真实改名 + 联动 Deauth 双频段压制），
Deauther 自 2026-11-10 起为真实帧注入，
Handshake 自 2026-11-10 起为真实抓包 + 真实跑包（见变更记录），
三者对周边网络会产生真实影响，须遵守以下边界：

1. **使用边界**：仅在自有网络或取得书面授权的受测环境启用；
   不得对第三方网络/设备伪造 AP、解除认证或收集凭据。
2. **法律提醒**：干扰他人通信 / 伪造他人网络可触及《网络安全法》第 27 条、
   《治安管理处罚法》、《刑法》第 285/286 条；销售形态风险更高。
   凭据捕获页记录的口令仅限演示，实验后应清空。
3. **实现性质**：Deauther 为**真实空口帧注入**（`esp_wifi_80211_tx`，26 字节
   Deauth 管理帧，仅 TX 成功后计数）；Handshake 为**真实空口抓包 + 真实离线跑包**
   （promiscuous 回调解析 EAPOL-Key 帧，MIC 校验与 aircrack-ng 官方向量一致）；
   Evil Twin 为**真实实现**：热点真实改名为目标 SSID（开放认证）+ 联动 Deauth
   压制主目标，并对双子目标（通常 5G）周期跳频注入 Deauth，使目标双频段都无法联网；
   凭据页与记录均为真实捕获。
   C5 对 raw TX 的 SDK 支持受限时会返回错误码并在后台如实标注。

详细边界与使用约束见设计文档 §3.1。

## 设备端 API（`192.168.4.1`）

除强制门户使用的 `POST /api/portal/submit` 外，所有 `/api/*` 均需鉴权：
请求头 `X-Admin-Token: <后台口令>`（兼容 `?token=<口令>`，方便 curl 调试），
缺失或错误返回 `401` 且不执行业务逻辑。

| 分组 | 接口 |
|---|---|
| 信息 / 配置 | `GET /api/info`、`GET /api/config`、`POST /api/config`、`GET /api/system/boot`、`POST /api/system/boot`、`POST /api/reset`、`POST /api/factory-reset` |
| 扫描 / 目标 | `GET /api/scan`、`POST /api/target`（`role=primary` 或 `twin`）、`POST /api/twin`、`DELETE /api/twin` |
| 日志 | `GET /api/log?since=`（64 条环形缓冲增量拉取） |
| 邪恶双子 | `POST /api/eviltwin/start`、`POST /api/eviltwin/stop`、`GET /api/eviltwin/creds`、`DELETE /api/eviltwin/creds` |
| 取消认证 | `POST /api/deauth/start`、`POST /api/deauth/stop`、`GET /api/deauth/status` |
| 握手包 | `POST /api/handshake/start`、`POST /api/handshake/stop`、`POST /api/handshake/crack`、`GET /api/handshake/dump` |
| 数据包分析器 | `POST /api/sniffer/start`、`POST /api/sniffer/stop`、`GET /api/sniffer/status` |
| Airodump | `POST /api/airodump/start`、`POST /api/airodump/stop`、`GET /api/airodump/status` |
| Karma | `POST /api/karma/start`、`POST /api/karma/stop`、`GET /api/karma/status` |
| BLE 扫描 | `POST /api/ble/start`、`POST /api/ble/stop`、`GET /api/ble/status`、`GET /api/ble/devices`、`POST /api/ble/clear` |
| 802.15.4 扫描 | `POST /api/ieee802154/start`、`POST /api/ieee802154/stop`、`GET /api/ieee802154/status`、`GET /api/ieee802154/frames`、`POST /api/ieee802154/clear` |

> `/api/info` 已包含 `evilTwin` / `deauth` / `handshake` / `sniffer` / `airodump` / `karma` / `ble` / `ieee802154`
> 等模块状态，不再单独提供 `/api/handshake/status`；`/api/karma/crack` 别名已删除，
> 统一走 `/api/handshake/crack`。

## PlatformIO 编译环境搭建

espressif32 v8 平台要求的工具链/框架包从 PIO registry CDN 下载时
极易断流（504 风暴），仓库提供断点续传 + 官方源注入两种手段：

```bash
# 0) PlatformIO 本体（独立 venv，避免污染系统 Python）
python3.11 -m venv ~/.venvs/platformio
~/.venvs/platformio/bin/pip install -U pip platformio esptool
ln -sf ~/.venvs/platformio/bin/pio ~/bin/pio        # PATH 需含 ~/bin

# 1) 工具链注入（espressif 官方 crosstool-NG esp-14.2.0_20260121，
#    与 espressif32 v8 要求的 14.2.0+20260121 精确对应）
sh tools/install-toolchain.sh           # 下载 ~/pio-dl/*.tar.xz 并注入 packages
sh tools/install-c5-libs.sh             # ESP32-C5 支持 (v8 registry 无 c5-libs, 本地注入)

# 2) 框架/芯片库（后台断点续传下载 → 安装；仓库提供
#    /tmp/fw-manifest.txt 式 sha256 清单用于下载后校验）
nohup zsh tools/dl-resume.sh framework-arduinoespressif32-4.30312.261024.tar.gz \
  framework-arduinoespressif32-esp32-libs-3.3.12.tar.gz \
  framework-arduinoespressif32-esp32s2-libs-3.3.12.tar.gz \
  framework-arduinoespressif32-esp32s3-libs-3.3.12.tar.gz \
  framework-arduinoespressif32-esp32c3-libs-3.3.12.tar.gz \
  framework-arduinoespressif32-esp32c6-libs-3.3.12.tar.gz \
  tool-esptool-darwin_arm64-2.50400.0.tar.gz \
  tool-esp-rom-elfs-0.0.1+20241011.tar.gz > /tmp/dl.log 2>&1 &
sh tools/install-registry-pkg.sh ~/pio-dl/framework-*.tar.gz ~/pio-dl/tool-*.tar.gz

# 3) 编译 + 合并镜像 + 注册后端
sh tools/build-firmware.sh 1.1.0
```

已验证 7 个 env 全部 SUCCESS：
`esp32 / esp32s2 / esp32s3 / esp32c3 / esp32c5 / esp32c5_16mb / esp32c6`；
其中 `esp32c5` 由 `tools/install-c5-libs.sh` 注入本地 libs 包实现（实验性支持），
`esp32c5_16mb` 是同一芯片的 16MB 三系统 (Triple-Boot) 镜像（见
[docs/firmware-flashing.md §6](docs/firmware-flashing.md)）。

> **Windows（Git Bash）**：venv 的可执行文件在 `~/.venvs/platformio/Scripts/`，
> 需把该目录加入 `PATH`（或安装全局 PlatformIO）让 `pio` 可被找到；`tools/build-firmware.sh`
> 会自动探测 `esptool.exe` 并用 `cygpath -m` 转换路径，无需手工改脚本。

## 目录结构

```
firmware/           PlatformIO 工程（Arduino 框架, espressif32 v8）
├── platformio.ini  可编 env: esp32/s2/s3/c3/c5/c5_16mb/c6（c5 需本地注入 libs）
├── src/main.cpp    共享固件逻辑（AP + 鉴权 API + 抓包/教学模块 + 日志/扫描/目标）
├── src/admin_page.h       自动生成（勿手改）
├── src/wifi_weak_dict.h   内置 7,153 条弱口令（由 build-wordlist.mjs 生成）
├── data/admin.html        固件后台 SPA（内嵌源文件；zlib deflate 压缩进固件）
├── tools/embed_admin_page.py   预构建脚本: admin.html → admin_page.h
└── tools/patch-platformio-c5.py  espressif32 平台的 C5 补丁（幂等可重跑）

flasher/            烧录台纯静态前端（Web Serial + esptool-js 0.7.1）
├── index.html      Neo-brutalism 布局（步骤卡 ①~④ + 控制台 + 条款/说明卡）
├── app.js          Web Serial + esptool-js 流程（镜像 MD5/大小校验、整片 Flash 备份）
├── style.css       视觉规范见 docs/plans 设计文档 §3.2
└── vendor/         本地固定依赖（esptool-js 0.7.1 / crypto-js 4.2.0，含许可证）

server/             Hono + better-sqlite3 后端（发码/校验/核销/固件分发）
├── src/index.js    入口（serveStatic 提供 /flasher/*，必须根目录启动）
├── src/logic.js    纯逻辑（nonce / 限流 / 口令常量时间比较 / 路径边界）
├── src/wpa.js      WPA 跑包（PBKDF2 / PRF / KDF / AES-CMAC / MIC / 帧解析）
├── data/weak-passwords.txt  服务端字典（与固件同序同量）
├── test/index.test.js       契约测试（38 项）
└── firmware/       合并镜像 bin（每个芯片一个, manifest 注册处）

tools/              构建与运维脚本
├── gen-code.mjs            生成本地测试烧录码（跨平台, npm run gen-code）
├── gen-code.sh             旧版 shell 发码脚本（保留）
├── build-firmware.sh       全 env 编译 → merge-bin → 注册
├── pack-admin.mjs          admin.html → admin_page.h（zlib level 9）
├── build-wordlist.mjs      生成 7,153 条字典（txt + C 头文件）
├── fetch-wpa-vectors.mjs   固化 aircrack-ng 官方向量到测试夹具
├── install-toolchain.sh    工具链注入（espressif 官方源）
├── install-registry-pkg.sh registry 包安装（含 .piopm 生成）
├── dl-resume.sh            registry CDN 断点续传下载
├── install-c5-libs.sh      ESP32-C5 libs 本地注入
├── patch-platformio-c5.py  espressif32 C5 平台补丁
├── esp32-c5-devkitc-1.json C5 板级定义副本
└── serial-telemetry.py     Serial JSON 遥测 PC 命令行消费端

docs/plans/         设计文档（含固件 API、合规边界、视觉规范）
docs/firmware-flashing.md  刷固件说明（网页烧录台 + 命令行 esptool + 常见问题）
```

## 合并镜像布局与 Bootloader 偏移（重要）

`tools/build-firmware.sh` 用 `esptool merge-bin` 把三段合成单镜像，
整片从 `0x0` 写入 flash。Bootloader 的偏移由芯片 ROM 规定，三方一致
（arduino `boards.txt` / IDF `CONFIG_BOOTLOADER_OFFSET_IN_FLASH` /
esptool `BOOTLOADER_FLASH_OFFSET`）：

| 芯片 | bootloader 偏移 | 说明 |
|---|---|---|
| `esp32` / `esp32s2` | `0x1000` | 经典 ESP32 与 S2 的 ROM 约定 |
| `esp32c5` | `0x2000` | WiFi 6 双频芯片, 前 2 扇区保留 |
| `esp32c5_16mb` | `0x2000` | 同一芯片的 16MB 三系统镜像, esptool 型号仍是 `esp32c5` |
| `esp32s3` / `esp32c3` / `esp32c6` | `0x0` | 新版 RISC-V/S3 从 0 起 |

分区表固定 `0x8000`、app 固定 `0x10000`（PlatformIO 默认，全系列一致）。
后端注册时的魔数校验会在**对应芯片的 bootloader 偏移**处检查 `0xE9`
（并兼容直接从 `0x0` 开始的 app-only 调试镜像）。

> ⚠️ espressif32 v8 的 `platformio-build.py` 把 `esp32c5` 也按 `0x0` 处理
> （平台对 C5 的适配缺陷，与 C5 的 ROM/sdkconfig/esptool 均矛盾）。
> 因此 `build-firmware.sh` 显式按芯片指定偏移，不沿用 `pio upload` 默认值。

## Serial JSON 遥测（外部设备即插即用）

固件在 115200 串口上**同时**输出两类行，保留原有 WebServer 与文本日志不变：

- 普通文本日志（如 `[wifi] AP 已启动 ...`）——烧录台串口控制台原样显示
- **NDJSON 遥测**：每行一个以 `{` 开头的 JSON 对象，供 PC 命令行 / 便携硬件按行解析

协议：`{"v":1,"ts":<毫秒>,"event":"<type>", ...}`，事件均为**只读数据镜像**：

| event | 触发 | 字段（全部只读） |
|---|---|---|
| `boot` | 上电 | chip / fw / ssid / mac / channel |
| `log` | 每次日志 | id / line（与环形缓冲同源） |
| `heartbeat` | 每 30s | clients / heap / minFree / uptime / ssid |
| `scan_result` | 扫描时每个周边 AP | ssid / rssi / ch / bssid / auth |
| `client_join` / `client_leave` | softAP 客户端数变化 | clients |
| `lab_state` | 教学模块启停（`eviltwin` / `deauth` / `handshake` / `ble` / `ieee802154`） | module / running |
| `eviltwin` | Evil Twin 首次捕获到门户提交 | caught / client（客户端 IP，不含口令） |

> 遥测只镜像**已有只读状态**：不含 Probe Request/Response、802.11 管理帧、
> EAPOL / 握手材料（M1~M4、PMKID、nonce、MIC）、凭据或任何密码字段。
> 捕获到的凭据在文本日志中只记录密码长度，明文仅保留在受后台口令保护的凭据表 API 中。
> 后台初始口令只经 `Serial` 直出一次，不经过 `log()`，因此不会被镜像成 `log` 事件。
> 文本日志与 JSON 事件并存，以 `{` 开头即视为 JSON，消费者按行判断即可。

消费端示例（PC 命令行，即插即用）：

```bash
pip install pyserial
python3 tools/serial-telemetry.py                          # 自动探测串口
python3 tools/serial-telemetry.py /dev/cu.usbserial-0001   # 指定端口
python3 tools/serial-telemetry.py --event heartbeat --event client_join
python3 tools/serial-telemetry.py --raw                    # 原样输出每行
python3 tools/serial-telemetry.py --save run.ndjson        # 导出 NDJSON 文件
```

## 烧录码生命周期

```
unused ──verify──▶ verified(15min) ──烧录成功/pair nonce──▶ redeemed(终态)
   ▲                    │烧录失败
   └────── 允许重试 ◀───┘ (不扣码)
```

- 校验 (`POST /api/codes/verify`) 发一次性 nonce；核销/失败上报 (`POST /api/codes/redeem`)
  必须携带匹配 nonce，同码无法多机复用。
- 失败不扣码：报 success=false 会把码放回可重试状态。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | 8787 | 后端监听端口 |
| `ADMIN_TOKEN` | local-admin-token-change-me | 服务端管理接口口令（生成码 / 注册镜像）；未显式配置时服务端只绑定 `127.0.0.1` |
| `TRUST_PROXY` | 0（忽略转发头） | 仅在服务部署于可信反向代理之后才置 `1`，此时 `verify` 限流采信 `X-Forwarded-For` 链尾地址；默认只取 TCP 对端 IP，杜绝伪造 XFF 绕过限流 |

> 服务端 `ADMIN_TOKEN` 与设备端后台口令是**两套独立凭据**：前者保护发码/注册等管理接口，
> 后者由固件首次上电随机生成并存入设备 NVS。另有构建脚本可识别的 `BASE` / `ESPTOOL` /
> `BUILD_DIR`，见「快速开始」。

## 已验证（验收清单对照）

- ✅ 无板子：verify 通过 → 烧录无串口失败 → 码未核销（可重试）
- ✅ 已核销的码再次 verify 被拒
- ✅ 镜像注册 0xE9 魔数校验 / 下载 md5 与 manifest 一致
- ✅ 烧录台 UI：校验通过、错误提示、进度条、控制台渲染正常
- ✅ 全 6 芯片镜像产出并注册（esp32/s2/s3/c3/c5/c6，C5 经本地 libs 注入支持）
- ✅ 固件后台 SPA 已内嵌（/api/scan、/api/target、/api/log、扩展 /api/info 编译通过）
- ✅ 2026-11-11 全量重建 6 芯片 v1.1.0 镜像并注册（4MB / 逐芯片），DB `md5`/`size`
  与磁盘逐字节一致；镜像内嵌 `admin.html` 解压后与源文件逐字节相同
- ✅ 后台鉴权回归：未带口令的 `/api/*` 返回 401，随机初始口令仅串口输出一次，
  旧版 `esp32admin` 升级后自动轮换
- ✅ 抓包模块回归：Sniffer / Airodump / Karma 共用 promiscuous 回调抓真实帧，
  握手状态并入 `/api/info`，冗余路由不再注册
- ⬜ 真机烧录 + 热点后台端到端（需要接一块 ESP32/S2/S3/C3/C6 板）

## 变更记录

### 2026-11-11（三）安全加固与工程闭环

- **后台口令**：移除全局静态 `esp32admin` 及其串口明文日志；改为每台设备首次上电用
  `esp_random()` 生成 12 位随机口令并存入 NVS，仅物理串口打印一次（不进遥测 / `/api/log`），
  旧版静态口令在升级时自动轮换。`/api/info` 增加 `mustChangeToken`，面板首次登录直达
  「配置」页引导改密；口令比较改为常量时间实现。
- **后台 SPA**：`go()` 与 `hashchange` 去重，一次导航只渲染一次。
- **烧录台**：下载镜像后本地比对 `manifest.md5` 与镜像大小，不一致直接阻止烧录；
  latin1 串只转换一次，MD5 校验与 `writeFlash` 共用。
- **服务端**：`verify` 限流默认只采信 TCP 对端 IP（只有 `TRUST_PROXY=1` 才认可信代理的
  XFF 链尾），杜绝伪造 XFF 绕过限流；`checkAdminToken` 改用定长 SHA-256 摘要 +
  `timingSafeEqual`；修正注册接口「支持二进制直传」的注释漂移。
- **三块抓包模块真实化**：Sniffer / Airodump / Karma 共用同一个 promiscuous 回调抓真实
  802.11 帧（替换此前的 `rand()` 模拟计数）；Karma 监听真实 Probe Request 并复用握手
  捕获链路；修复 Karma 启停双响应。
- **后台收尾**：邪恶双子页新增「克隆 SSID」输入框（留空跟随目标 SSID，攻击中禁用，草稿
  跨页面重建保留）；首次登录若仍是初始口令，面板顶部提示并直达改密；`/api/info` 的
  `handshake` 字段统一承载握手状态。
- **接口清理**：删除 `/api/handshake/status` 与 `/api/karma/crack`，握手/模块状态并入
  `/api/info`，跑包统一走 `/api/handshake/crack`；契约测试补「不得回退」断言。
- **构建链路**：`build-firmware.sh` 改为经 `PLATFORMIO_BUILD_FLAGS` 注入版本宏（PlatformIO
  6.2 无 `--build-flag`）、自动探测 esptool、Git Bash 路径经 `cygpath -m` 转换、增加
  `/api/health` 预检与独立 `firmware/.pio/build-release` 目录；本次据此全量重建 6 芯片
  v1.1.0 镜像并重新注册。
- **测试**：`npm test` 38/38 通过（覆盖鉴权、限流、路径边界、WPA 官方向量、字典契约、
  三模块真实抓包与冗余路由回归）。

### 2026-11-10（四）Evil Twin 真实化：同名克隆热点 + 主/双子目标 + 双频段压制

将「邪恶双子」从演示级（只记录一个克隆名字符串）升级为**真实攻击链**：

- **热点真实改名**：发起时 `WiFi.softAP(<主目标 SSID>, nullptr, <主目标信道>)` —— 与目标
  **一模一样**的 SSID、开放无密码（受害设备无需密码即可接入）、信道对齐主目标，停止时
  恢复原热点名/密码/信道。后台仍可用「克隆 SSID」输入框显式覆盖。
- **主目标 / 双子目标双目标模型**：扫描列表每行提供「设为主目标」「设为双子」两个按钮；
  `POST /api/target` 增加 `role=primary|twin`，主目标须为 2.4G（信道 1-14）或 5G 非 DFS
  （36-48/149-165，仅 C5 —— 克隆热点需能驻留该信道）；5G DFS 信道（52-144）拒绝作为
  主目标并提示改设为双子（双子只跳频注入、不起热点，因此 DFS 可用）。
- **双频段压制**：发起攻击自动对主目标持续注入 Deauth；若设了双子目标（通常同一路由器的
  5G BSSID），每 2s 跳频到双子信道连发 3 帧 Deauth 再跳回主信道 —— 单射频 C5 无法同时
  广播双频，跳频是让目标两个频段都无法联网的可行方案（跳频失效时自动停用并如实记日志）。
- **收束与恢复**：捕获第一条凭据后自动停止 Deauth/跳频（同名开放热点保留供其浏览），
  后台点「停止并恢复热点」恢复原热点；手动停 Deauth 时不会误切信道破坏克隆对齐。
- **后台**：目标卡改为「目标信息 (主 / 双子)」，双子页显示实时状态条（克隆热点是否上线 /
  主目标 Deauth 帧数 / 双子跳频次数与帧数 / 已接入设备数），发起失败回显固件中文原因。
- **工程**：`tools/patch-platformio-c5.py` 固化 espressif32 平台的 C5 补丁（注入
  c5-libs 包定义、把 Xtensa 工具链与两个 gdb 标 optional 免下 435MB 无关包、补 board 与
  builder 映射），幂等可重跑；`embed_admin_page.py` 改为显式 UTF-8 写盘，修掉生成
  `admin_page.h` 中文注释乱码。

### 2026-11-10（三）Handshake 真实空口抓包 + 板载跑包 + 服务端 /api/wpa/crack

将「握手包与破解」从定时器模拟升级为**真实抓包 + 真实离线跑包**（算法与 aircrack-ng
官方向量逐字节对齐）：

- **固件捕获**：`esp_wifi_set_promiscuous(true)` + 数据帧过滤，回调里按 LLC/SNAP
  `AA:AA:03:00:00:00:88:8E` 定位 EAPOL-Key 帧，依 Key Info 的 ACK/MIC/Secure 位区分
  M1（ANonce）/M2（SNonce+MIC）/M3（GTK）/M4，并解析 M1 的 PMKID KDE。启动前把空口
  对齐到目标信道（不写 NVS），停止/跑包前恢复；只接收选中目标 BSSID 的帧。
- **板载跑包**：内置 7,153 条弱口令（`firmware/src/wifi_weak_dict.h`，与
  `server/data/weak-passwords.txt` 同序同量），逐条
  `PMK=PBKDF2-HMAC-SHA1(口令, SSID, 4096, 32)` → `PTK=PRF-512` → 重算 M2 的 MIC
  （keyver 1 HMAC-MD5 / keyver 2 HMAC-SHA1）比对；主循环每轮只试一条，跑包期间
  HTTP 仍可查进度。
- **keyver 3（802.11w PMF）** 板载不实现（SHA256-KDF + AES-CMAC），标记
  `unsupported`，`GET /api/handshake/dump` 导出 essid/bssid/stmac/anonce/snonce/
  eapol/keyver，交服务端跑。
- **服务端**：新增 `server/src/wpa.js`（PBKDF2 / PRF / 802.11 KDF / AES-CMAC / MIC /
  PMKID / 帧解析）与 `POST /api/wpa/crack`（requireAdmin，支持内置字典、自定义
  dictionary、maxCandidates 截断，返回命中下标/口令/尝试数/耗时）。
- **算法验证**：aircrack-ng 官方单元测试向量（Harkonen keyver 1/2、Neheb keyver 3）
  与 RFC 4493 四个 CMAC 向量全部通过；`tools/fetch-wpa-vectors.mjs` 抓取并固化为
  `server/test/fixtures/wpa-vectors.json`，测试离线可复现。
- **字典**：`tools/build-wordlist.mjs` 确定性生成恰好 7,153 条（演示口令
  `00000000`/`88888888`/`12345678` 置顶），同时输出 txt 与 C 头文件，测试断言两者同序。
- 后台握手页改为真实状态：显示 keyver / 已收 EAPOL-Key 帧数 / 捕获是否完整，
  未捕获时禁用跑包，PMF 网络提示导出；新增「导出握手材料」按钮。
- `npm test` 23/23（新增 WPA 官方向量、RFC CMAC、字典契约、端到端跑包 9 项）。

### 2026-11-10（二）Deauther 真实 802.11 帧注入

将「WiFi 杀手」从纯计数模拟升级为**真实空口帧注入**：

- 固件 Deauth 引擎经 `esp_wifi_80211_tx(WIFI_IF_AP, …)` 发送预构的 26 字节
  Deauthentication 管理帧（Type=管理/Subtype=12，`0x00c0`），接收端为广播地址、
  发送端/BSSID 为目标 AP，客户端会真实收到并断线重试。序列号由系统填充（`en_sys_seq=true`）。
- 新增 `parseBssid()` 校验目标 MAC、`buildDeauthFrame()` 构帧；`/api/deauth/start`
  返回 `injected`/`txChannel`/`channelMismatch`，`/api/deauth/status` 返回 `txOk`/`txErr`，
  后台与首页据此显示真实发送状态。仅当 `esp_wifi_80211_tx` 返回 `ESP_OK` 才累加帧计数。
- **自动信道对齐**：单射频只能在本机信道发帧，故启动时经 `esp_wifi_set_channel` 把热点临时切到
  目标信道（不修改 NVS 配置；已连受测设备短暂掉线后自动重连），停止时恢复配置信道；对齐失败时
  后台明确提示「目标收不到」。C5 等 raw TX 受限芯片会返回错误码并在后台如实标注。
- 后台文案由「协议机制验证」改为「真实帧注入」，新增帧注入状态行与信道对齐/对齐失败提示。
- 测试新增契约用例 `Deauther 为真实帧注入而非纯计数`（断言源码含 `esp_wifi_80211_tx(WIFI_IF_AP`、
  `f[0] = 0xC0` 且计数不再无条件自增）与 `Deauther 启动前自动对齐目标信道且停止时恢复`
  （断言 `esp_wifi_set_channel` 调用与停止恢复、临时切换不写 NVS）。`npm test` 14/14。

### 2026-11-10 代码审查修复 (P0/P1) 与全栈工程级优化 (v1.1.0)

**Fixed (P0 / P1 安全与稳定性修复)**
- **P0 固件 extractJson 键值解析错误**：修复 key 偏移算错导致的冒号前缀与数字解析为 0 的严重缺陷，所有 10 处 API 参数提取恢复正常。
- **P0 服务端 Nonce 竞争与重放核销漏洞**：`registerNonce` 强制单一活跃映射；`redeem` 立即消费 Nonce 并通过 SQLite 事务与 `status != 'redeemed'` 条件原子核销，杜绝并发竞争。
- **P0 本地管理口令回环兼容**：未指定 `ADMIN_TOKEN` 时严格绑定回环 `127.0.0.1` 并放行默认管理口令，避免本地 CLI 工具（`gen-code` / `build-firmware`）报 503 阻断开箱体验。
- **P1 固件 XSS 漏洞**：钓鱼门户 `sendPortalPage()` 对克隆/目标 SSID 进行 `htmlEscape()` 转义，杜绝 XSS 注入。
- **P1 Captive Portal 强制跳转**：`captiveRedirect()` 统一采用绝对 URI（`http://192.168.4.1/admin.html` 与 `/portal.html`），严格满足 iOS/macOS CNA 和 Android 的强制门户标准。
- **P1 镜像注册路径越界防护**：`/api/admin/firmware/:chip` 增加版本号正则白名单与工作区绝对路径边界校验（`isWithinRoot`），防止任意文件读取与路径穿越。
- **P1 握手包页面 DOM 刷新断连**：解耦后台 SPA 轮询与页面挂载，采用节点内联更新机制，彻底解决每秒重建 DOM 导致按钮无法点击的交互缺陷。
- **P1 固件 Deauth 与时钟溢出计算**：添加帧率零除防崩溃保护，修复未捕获时跑包耗时算作系统总运行时间的计时漂移。

**Added & Optimized (系统与工程优化)**
- **跨平台烧录码命令行**：新增纯 Node.js 实现的 `tools/gen-code.mjs`，并在 `package.json` 集成 `npm run gen-code`、`npm run codes`、`npm run stats`，Windows/macOS/Linux 零配置即开即用。
- **后台页面打包器**：新增 `tools/pack-admin.mjs`，将 `firmware/data/admin.html` 自动压缩（zlib level 9）输出为 `firmware/src/admin_page.h`，集成 `npm run pack-admin`。
- **NVS 热点配置持久化**：固件与后台管理页面联动，支持在 Web 界面修改热点 SSID 与工作信道（1-13），自动存入 ESP32 NVS（Preferences），恢复出厂设置自动擦除。
- **服务端健康与统计探针**：增强 `GET /api/health`（提供活跃 Nonce 与可用码指标），新增 `GET /api/admin/stats` 汇总烧录码与刷机历史。
- **固件下载 ETag 缓存与限流响应**：`/api/firmware/bin/:chip` 支持 304 缓存降低网络开销；验证限流返回标准 `Retry-After` 秒数响应头。
- **串口遥测动态重连**：`tools/serial-telemetry.py` 的 `--reconnect` 支持动态设备端口重探测，即使断开重插到不同 COM 端口也能自动无缝恢复。
- **自动化测试套件**：新增 `server/test/index.test.js`，包含 10 项核心安全与逻辑单元测试（`npm test` 自动化验证）。

### 2026-11-09（四）Serial JSON 遥测（外部设备即插即用）

**Added**
- 固件串口在文本日志之外**新增 NDJSON 只读遥测**（`{"v":1,"ts":...,"event":...}`）：
  `boot` / `log` / `heartbeat` / `scan_result` / `client_join` / `client_leave` / `lab_state`。
  保留现有 WebServer 与文本日志不变，两类行并存（`{` 开头即 JSON）
- `tools/serial-telemetry.py`：PC 命令行消费端，自动探测串口、按行解析、
  `--event` 订阅过滤、`--raw` 原样输出、`--save` 导出 NDJSON
- 烧录台控制台提示标注「文本日志 + NDJSON 遥测」及解析方式

**边界**：遥测只镜像已有只读状态，不含 Probe Request/Response、管理帧、
EAPOL/握手材料（M1~M4、PMKID、nonce、MIC）、凭据或密码字段。

### 2026-11-09（三）新增 3 大网络安全教学验证板块 (v1.1.0)

**Added**
- **Evil Twin（邪恶双子 & 凭据捕获）**：支持克隆主目标 SSID，联动 Captive Portal 强制门户展示路由器升级认证页，记录受测端提交的凭据并在后台实时展示与管理。
- **Deauther（取消认证器）**：实现 IEEE 802.11 Deauth 管理帧机制测试，支持 10/20/50 fps 与 Reason Code (1/2/6/7) 调节，提供实时帧率与累计注入遥测。
- **Handshake & Crack（4次握手与字典跑包）**：实现 EAPOL 4-Way Handshake 状态机 (M1~M4) 与 PMKID 状态监听展示，内置 7,153 条弱密码离线跑包演示。
- **后台 SPA 全面联动**：抽屉菜单启用 3 大板块独立交互页，首页仪表板新增教学实验引擎状态指示，情报与捕获区数据动态实时绑定。

### 2026-11-09（二）代码审查修复 + Captive Portal

**Added**
- **Captive Portal 强制门户**：固件引入 `DNSServer`（UDP 53 通配解析 → AP IP），
  `notFound()` 对 iOS/Android/Windows 探测路径及任意未知路径返回 302 → `/admin.html`，
  手机连热点自动弹后台；`/api/*` 保持 404 不破坏后台 SPA

**Fixed (P0 / 安全 / 稳定性)**
- **Bootloader 偏移错误**（审查核心项，且审查自身论断有误）：按芯片动态指定
  `esp32/s2=0x1000`、`esp32c5=0x2000`、其余 `=0x0`，修复 3 颗芯片镜像放错位置
  导致无法开机的问题。审查稿仅识别经典 ESP32，并错误地让 S2/C5 保持 0x0
  （三方证据：arduino boards.txt / IDF sdkconfig / esptool 均已核对）；
  同时绕开 espressif32 v8 平台把 C5 也当 0x0 的适配缺陷
- **后端魔数校验误杀**：改为按芯片预期 bootloader 偏移检查 `0xE9`（对齐上表），
  并兼容 app-only 调试镜像（0x0）
- **烧录台 `consoleHint` 空指针**：HTML 补 `#consoleHint` 元素 + JS 判空保护 + 样式
- **nonce 内存无限膨胀**：5 分钟定期 sweep + `redeem` 真正校验 `expiresAt`
  （原实现过期 nonce 仍可核销）
- **verify 无限流**：单 IP 滑动窗口 10 次/分（`429`）
- **ADMIN_TOKEN 明文打印**：启动日志改为「已启用」提示，不输出值
- **静态托管依赖 cwd**：`serveStatic` 改用 `join(ROOT,'flasher')` 绝对路径

未采纳（经评估暂缓，见 §9）：CDN 本地化、异步扫描、串口探针免码升级
（后者与一次性烧录码核销闭环冲突）。

### 2026-11-09（一）初始版本

**Added**
- **ESP32-C5 固件支持**：`tools/install-c5-libs.sh` 注入本地 c5-libs（lib-builder
  idf-release_v5.5-b774170f）+ PlatformIO 平台三处补丁；6 env 全部出镜像并注册
- 固件后台 Neo-brutalism SPA（状态总览 / 扫描与嗅探 / 配置 + 合规未启用占位），
  build 时经 `firmware/tools/embed_admin_page.py` zlib 压缩内嵌
- 设备端 API：`GET /api/scan`（APSTA 扫描）、`POST /api/target`、
  `GET /api/log?since=`（环形 64 条）、`GET /api/info` 扩展内存诊断与恢复目标
- 烧录台「开发板型号」下拉支持手动预选（自动识别仍优先，防选错芯片烧错镜像）
- **功能范围与合规边界章节**（README + 设计文档 §3.1）：能力矩阵表 +
  不做主动攻击模块的三点依据（法律/产品定位/技术），与外部攻击固件形态划清界限
  （注：2026-11-09 初版定位；v1.1.0 起改为「授权教学验证」模块，见后续变更记录）
- 编译工具链三件套：`tools/install-toolchain.sh`、`tools/dl-resume.sh`、
  `tools/install-registry-pkg.sh`

**Changed**
- 烧录台 UI 重构为 Neo-brutalism（步骤卡 ①~④、黑底绿字控制台带时间戳、
  明暗主题切换）；④ 版本说明芯片列表动态生成
- `espressif32` 统一 v8.0.0（C6 不再用 6.9 旧平台；C5 env 收回统一平台）
- 静态托管加 `Cache-Control: no-store`（烧录台属迭代频繁的开发工具）

**Fixed**
- `tools/dl-resume.sh` 文件名含无 `darwin_arm64` 的 registry 包时版本解析错误
- `tools/build-firmware.sh` zsh 下 `CHIPS` 未加引号导致只编一个 env

## 下一步（未实现，见 docs/plans 设计文档 §9）

- 云部署（HTTPS + CDN；Web Serial 要求安全上下文）
- 图文教程页（tw.html / az.html 占位）
- C5 真机验证（镜像已出，等一块 ESP32-C5 板）
- C5 5GHz / BLE 5 / 802.15.4 能力扩展：P0（5G 抓包）与 P1（5G AP 非 DFS、5G 取消认证 /
  双子含 DFS 跳频）已实现，均待真机验证；P2（BLE 广播嗅探，C3/C5/C6/S3 走 NimBLE，
  经典 ESP32 因 Bluedroid 体积与双 app 槽冲突而裁剪）已实现待真机验证；P3（802.15.4
  纯被动嗅探 + 信道能量扫描，C5/C6 开放）已实现待真机验证。差距与改造清单见
  [docs/plans/2026-11-11-c5-5ghz-ble-802154-roadmap.md](docs/plans/2026-11-11-c5-5ghz-ble-802154-roadmap.md)
