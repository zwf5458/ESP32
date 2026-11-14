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
| Captive Portal | ✅ 深度实现（全平台 CNA 适配） | UDP 53 通配解析 + 深度适配 iOS / Android (MIUI/HyperOS/鸿蒙/ColorOS) / Windows 11 CNA 探活协议，解决现代手机防弹窗拦截与无网自动断开痛点；未知路径 302 全量保活 |
| 周边 AP 扫描 | ✅ 实现 | `WiFi.scanNetworks()` 被动列出 SSID/RSSI/信道/加密方式 |
| 已连客户端计数 | ✅ 实现 | `softAPgetStationNum()` 只读计数 |
| 事件日志 | ✅ 实现 | 64 条环形缓冲，`GET /api/log?since=` 增量拉取 |
| 内存/运行诊断 | ✅ 实现 | 堆、PSRAM、信道、uptime |
| 脱机便携扩展 (OLED + 蜂鸣器) | ✅ 深度实现 (`esp32c5_16mb_portable`) | 自研纯 Wire.h 极简驱动 `ssd1306_tiny.h`（零外部依赖，仅占 1KB 显存），支持 0.96/1.3 寸 I2C OLED (SDA=IO4, SCL=IO5)。双模式智能切屏：常规仪表盘 + 捕获密码时大字明文直显；配合蜂鸣器 (IO13) 声学提醒（成功三音/未校验双音） |
| Evil Twin（邪恶双子） | ✅ 真实实现（C5 真机已验证） | 攻击时把本机热点**真实改名**为与主目标一模一样的 SSID（开放无密码、信道对齐主目标）→ 目标设备免密直连；主目标可为 2.4G 或 5G 非 DFS（5G 克隆先切 `WIFI_BAND_MODE_5G_ONLY` 再起 AP，并以 `esp_wifi_get_channel` 校验真实驻留信道，避免「`softAP(ch149)` 返回 true 却停在 2.4G」）。同时自动对主目标持续注入**定向单播 Deauth**，并对双子目标（同一路由器另一频段 BSSID）每 2s 跳频连发注入 → 单射频也能让目标两个频段都无法联网（2026-11-13 真机：主 5G ch149 + 双子 2.4G ch11，两个频段在线设备均被打掉）；Captive Portal 自动弹钓鱼页，捕获第一条凭据后自动停止干扰，手动停止恢复原热点名/密码/信道 |
| Deauther（WiFi 杀手） | ✅ 真实实现（C5 真机已验证） | 经 `esp_wifi_80211_tx` 注入真实 Deauthentication 管理帧（0x00c0）。C5 的帧类型白名单由覆盖 `ieee80211_raw_frame_sanity_check`（链接加 `-Wl,--allow-multiple-definition`）解除，Deauth/Disassoc 真机可发。为应对 Wi-Fi 6 终端静默丢弃广播 Deauth，运行期开 promiscuous 从空口数据帧学习目标 AP 下客户端 MAC（最多 12 个），改为**单播定向踢线**（DA=客户端、TA/BSSID=目标 AP，原因码 1/3/7/15 轮换，每 4 帧留 1 帧广播兜底）。带 Reason Code / `unicast` / `knownStas` / `prom` / `rxFrames·rxData·rxMatch` 诊断计数遥测。启动时自动把热点切到目标信道，停止时恢复；探测前先开 promiscuous |
| Handshake / 握手包与跑包 | ✅ 真实实现 | `esp_wifi_set_promiscuous` 真实空口捕获 4-Way Handshake（M1~M4，含 PMKID KDE）；板载用内置 7,153 条弱口令逐条跑包（PMK=PBKDF2-HMAC-SHA1 4096 轮 → PTK → 重算 M2 的 MIC 比对，支持 keyver 1/2）。keyver 3（802.11w PMF）导出后交服务端 `/api/wpa/crack`（SHA256-KDF + AES-CMAC） |
| 数据包分析器 (Sniffer) | ✅ 真实实现 | 共用 promiscuous 回调抓真实 802.11 管理/控制/数据帧，解析帧类型、源/目的 MAC、SSID、Deauth Reason；支持单信道停驻与 1-13 自动跳频，实时帧率统计；源/目的 MAC 悬停显示 OUI 厂商名。同一回调顺带解析 Beacon / Probe Response 中的 ASTM F3411 Remote ID 厂商 IE |
| Remote ID 解析 | ✅ 真实实现 | 纯被动解析两路载体：BLE Service Data（UUID 0xFFFA + App Code 0x0D）与 WiFi Beacon / ProbeResp 厂商 IE（OUI `FA-0B-BC` / Type 0x0D）。解析 Basic ID（UAS ID / 机型 / ID 类型）、Location（无人机经纬度 / 高度）、System（操作员位置）；同一 MAC 的 BLE 与 WiFi 数据自动归并，2 分钟未更新自动隐藏，最多 8 条。坐标仅文本展示并可点击复制，不加载在线地图（AP 模式无外网） |
| Airodump 侦察 | ✅ 真实实现 | 从真实空口帧按 MAC 聚合对端（RSSI / 帧数 / 探测过的 SSID），支持 1-13 跳频；与 Evil Twin / Deauth / 握手捕获并行时停驻当前信道，避免破坏射频状态 |
| Karma 探针诱捕 | ✅ 真实实现 | 监听真实 Probe Request，记录客户端 MAC / 目标 SSID / RSSI；SSID 命中当前克隆热点时标记为「已诱捕」，并复用握手捕获链路同步收集 4-Way Handshake |
| BLE 广播嗅探 + 设备画像 | ✅ 真实实现 | 纯被动监听周边 BLE 广播（ADV_IND / SCAN_RSP 等），解析 MAC / 名称 / RSSI / 广播类型 / 厂商数据摘要 / 广播计数，并按 Company ID / Service UUID 识别 AirTag/Find My、iBeacon、Eddystone、BTHome、小米、Govee、Ruuvi、Fast Pair、Remote ID 等类别，展示厂商名与「随机 MAC」标记；不发 SCAN_REQ、不连接设备。C3/C5/C6/S3 开放（NimBLE 后端），经典 ESP32 因 Bluedroid 体积与双 app 槽冲突而裁剪，S2 无蓝牙硬件 |
| 802.15.4 嗅探 | ✅ 真实实现 | 纯被动接收 IEEE 802.15.4 帧（Zigbee / Thread / 智能家居），解析帧类型 / PAN ID / 源地址 / RSSI / LQI，并对 11-26 信道做能量检测（dBm）；promiscuous 模式只收不发、不自动 ACK、不注入。仅 ESP32-C5 / C6 具备该射频，其余芯片整页隐藏且 API 返回 501；与 WiFi 2.4G 共用射频，AP 保持在线、抓包为分时采样 |
| 16MB 三系统引导 | ✅ 实现（`esp32c5_16mb`） | 16MB C5 板（C5N16R8）上划分 `ota_0/ota_1/ota_2` 三个 app 槽（各 3.9375MB）+ 共享 spiffs，可部署审计固件 / ESPsoup / Meta Muse 并通过 `GET·POST /api/system/boot`、串口 `boot` 命令或烧录台「外部固件刷写」切换；4MB 版 `esp32c5` 不受影响 |

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
   Deauth 管理帧，仅 TX 成功后计数）；C5 的帧类型白名单已通过覆盖
   `ieee80211_raw_frame_sanity_check` 解除（2026-11-13 真机验证可发，见验收报告）。
   为避免 Wi-Fi 6 终端丢弃广播 Deauth，改为从空口学习客户端 MAC 后**单播定向踢线**。
   Handshake 为**真实空口抓包 + 真实离线跑包**
   （promiscuous 回调解析 EAPOL-Key 帧，MIC 校验与 aircrack-ng 官方向量一致）；
   Evil Twin 为**真实实现**：热点真实改名为目标 SSID（开放认证）+ 联动 Deauth
   压制主目标（可为 5G），并对双子目标（另一频段 BSSID）周期跳频注入 Deauth，
   单射频即可让目标双频段都无法联网；凭据页与记录均为真实捕获。
   若个别平台仍拒绝 raw TX，后台会返回错误码并如实标注。

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
| Remote ID | `GET /api/rid`（BLE + WiFi Beacon 汇总，只读，最多 8 条，2 分钟 TTL） |
| 厂商表资源 | `GET /vendor-db.js`（公开只读，deflate 压缩；后台按需加载，不含密钥） |
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
├── tools/embed_admin_page.py          预构建脚本: admin.html → admin_page.h
├── tools/fix_c5_bootloader_offset.py  后置脚本: 把 esp32c5 的 bootloader 烧录偏移修正到 0x2000
└── tools/patch-platformio-c5.py      espressif32 平台的 C5 补丁（幂等可重跑）

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

## 16MB 三系统 (Triple-Boot)

16MB Flash 的 C5（如 ESP32-C5N16R8）用专用 env `esp32c5_16mb` 构建，可在同一块板上
部署并无缝切换三套系统：

| 槽位 | 偏移 | 系统 |
|---|---|---|
| `ota_0` | `0x10000` | Wi-Fi 安全审计平台（本工程固件） |
| `ota_1` | `0x400000` | ESPsoup 口袋 SDR |
| `ota_2` | `0x7F0000` | Meta Muse AI 伴侣 |

- 分区表 `firmware/partitions-16mb-triple.csv`（纯 ASCII，Windows 下 PlatformIO 按系统编码解析）；
- 4MB 版 `esp32c5` 仍用 `min_spiffs.csv`，两个镜像在烧录台里分开注册（key 分别为
  `esp32c5` / `esp32c5_16mb`，后者显示为「ESP32-C5 (16MB 三系统)」）；
- 合并镜像仍按 4MB pad，只覆盖 `ota_0`，重刷审计固件不会抹掉 `ota_1`/`ota_2`；
- 切换：后台「多系统引导管理」卡片、串口 `boot audit|espsoup|muse`，或 `POST /api/system/boot`。

完整部署步骤、构建自检、真机验证清单与常见问题见
[docs/firmware-flashing.md §6](docs/firmware-flashing.md#6-附16mb-flash-三系统-triple-boot-部署说明)。

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
> （平台对 C5 的适配缺陷，与 C5 的 ROM/sdkconfig/esptool 均矛盾）。因此：
> - `build-firmware.sh`（合并镜像）显式按芯片指定偏移，不沿用 `pio upload` 默认值；
> - 直接 `pio run -e esp32c5_16mb -t upload` 会踩同一坑（bootloader 被写到 0x0，
>   上电 `invalid header: 0xa8030007` 无限复位）。已由
>   `firmware/tools/fix_c5_bootloader_offset.py`（`post:` 脚本）修正 esptool 命令行
>   的 bootloader 偏移到 `0x2000`，见 `[env:esp32c5_16mb]` 的 `extra_scripts`。
>   2026-11-13 真机实烧验证通过，详见 `docs/firmware-flashing.md` §5.7。

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
| `HOST` | `127.0.0.1` | 监听地址。默认只绑回环，HTTP 明文管理口令不会暴露到内网/公网；确需远程访问请走 HTTPS 反向代理 + IP 白名单，再显式设置 `HOST=0.0.0.0` |
| `ADMIN_TOKEN` | local-admin-token-change-me | 服务端管理接口口令（生成码 / 注册镜像）；**不再**因配置口令而自动改为监听 `0.0.0.0` |
| `TRUST_PROXY` | 0（忽略转发头） | 仅在服务部署于可信反向代理之后才置 `1`，此时 `verify` 限流采信 `X-Forwarded-For` 链尾地址；默认只取 TCP 对端 IP，杜绝伪造 XFF 绕过限流 |

> 服务端 `ADMIN_TOKEN` 与设备端后台口令是**两套独立凭据**：前者保护发码/注册等管理接口，
> 后者由固件首次上电随机生成并存入设备 NVS。另有构建脚本可识别的 `BASE` / `ESPTOOL` /
> `BUILD_DIR`，见「快速开始」。

## 已验证（验收清单对照）

- ✅ 无板子：verify 通过 → 烧录无串口失败 → 码未核销（可重试）
- ✅ 已核销的码再次 verify 被拒
- ✅ 镜像注册 0xE9 魔数校验 / 下载 md5 与 manifest 一致
- ✅ 烧录台 UI：校验通过、错误提示、进度条、控制台渲染正常
- ✅ 全 7 个镜像产出并注册（esp32/s2/s3/c3/c5/**c5_16mb**/c6，C5 经本地 libs 注入支持）
- ✅ 16MB 三系统构建自检（2026-11-12）：`esp32c5_16mb` 编译 SUCCESS，分区表反解
  `ota_0/1/2` 各 4032K、偏移 `0x10000/0x400000/0x7F0000`，合并镜像 4MB 且 `0x2000`=`0xE9`、
  `0x8000`=`0xAA50`，契约测试 41/41
- ✅ 固件后台 SPA 已内嵌（/api/scan、/api/target、/api/log、扩展 /api/info 编译通过）
- ✅ 2026-11-11 全量重建 6 芯片 v1.1.0 镜像并注册（4MB / 逐芯片），DB `md5`/`size`
  与磁盘逐字节一致；镜像内嵌 `admin.html` 解压后与源文件逐字节相同
- ✅ 后台鉴权回归：未带口令的 `/api/*` 返回 401，随机初始口令仅串口输出一次，
  旧版 `esp32admin` 升级后自动轮换
- ✅ 抓包模块回归：Sniffer / Airodump / Karma 共用 promiscuous 回调抓真实帧，
  握手状态并入 `/api/info`，冗余路由不再注册
- ✅ 2026-11-13 ESP32-C5N16R8 真机：5G/2.4G 邪恶双子 + 定向单播 Deauth 双频压制
  （主 5G ch149 在线设备 6→2、2.4G ch11 在线设备 1~3→0；双频同名目标加双子后
  两个频段同时被踢，详见 `tools/c5-feature-acceptance-report.md` §5）
- ✅ 2026-11-13 16MB 三系统真机（分区表、三槽 API、audit↔espsoup 切换、NVS 持久），
  见 `tools/C5-16MB-VERIFICATION-REPORT.md` §四
- ✅ 2026-11-13 `pio run -e esp32c5_16mb -t upload` 烧录闭环（bootloader 自动写 0x2000，
  串口无 `invalid header`、正常打印 v1.1.0 启动横幅）
- ⬜ 真机烧录 + 热点后台端到端（ESP32/S2/S3/C3/C6 板待补；C5 已验证）
- ⬜ 16MB 三系统剩余项（ota_2 / ESPsoup·Muse 真实固件行为 / Web Serial 刷写，
  见 `tools/C5-16MB-VERIFICATION-REPORT.md` §五）

## 变更记录

### 2026-11-13（五）C5 真机：定向单播 Deauth 双频压制 + bootloader 烧录偏移修复

- **真机根因定位（手机没被挤掉）**：① 广播 Deauth（`DA=FF:FF:FF:FF:FF:FF`）被
  Wi-Fi 6 终端驱动静默丢弃，帧数一直涨但目标毫无反应；② 双频同名 AP 的手机/网卡
  默认优先 5G，而克隆热点 `softAP(ch149)` 返回 true 却驻留在 2.4G，攻击发在错误频段。
- **定向单播踢线**（`cb1cd8b`）：Deauth 运行期开 promiscuous，从 ToDS/FromDS 数据帧
  学习目标 AP 下客户端 MAC（最多 12 个），改为单播 Deauth（DA=客户端、TA/BSSID=
  目标 AP），原因码 1/3/7/15 轮换，每 4 帧留 1 帧广播兜底；`/api/info` 与
  `/api/deauth/status` 暴露 `unicast / knownStas / prom / rxFrames / rxData / rxMatch`。
- **帧白名单与注入路径**：覆盖 `ieee80211_raw_frame_sanity_check`（配合
  `-Wl,--allow-multiple-definition`）解除 C5 对 Deauth/Disassoc 的驱动拒绝；
  信标类帧改走 STA 接口注入（AP 接口注入的 Beacon 空口不可见）。
- **5G / 双频链路**：5G 克隆先切 `WIFI_BAND_MODE_5G_ONLY` 再起 AP 并用
  `esp_wifi_get_channel` 校验真实信道（`14a8dc3`）；起 AP 顺序改为「先切频段再设带宽」
  消除 AUTO 下 `set_bandwidth` 报错（`f466a6b`）；探测 Deauth 前先开 promiscuous，
  并补阶段 2 的 `syncPromiscuousEngine()`（`0aeb60b` / `c806001`）。
- **真机结果**：目标 5G ch149（`…DD:72`）学到 5 台客户端、单播 1111+ 帧，
  真实 5G AP 在线设备 6→2；目标 2.4G ch11（`…DD:71`）在线设备 1~3→0。
  双频覆盖实测：主 5G + 双子 2.4G 每 2s 跳频，克隆热点在 5G ch149 与 2.4G ch11
  交替出现，`WiFi6` 两个频段均被压制（手机持续被踢）。
- **烧录坑修复**（`ff62eda`）：C5 二阶段 bootloader 位于 flash **0x2000**，
  而 `framework-arduinoespressif32/tools/platformio-build.py` 的 `FLASH_EXTRA_IMAGES`
  对 riscv 统一用 `0x0000` → `pio run -t upload` 把 bootloader 写错位置，上电
  `invalid header: 0xa8030007` 无限复位。新增 `firmware/tools/fix_c5_bootloader_offset.py`
  post 脚本同时修正 `FLASH_EXTRA_IMAGES` 与展开后的 `UPLOADERFLAGS`（仅 esp32c5 生效），
  `[env:esp32c5_16mb]` 加 `board_build.bootloader_addr = 0x2000` 并重写 `extra_scripts`。
  实烧验证：esptool 命令行出现 `0x2000 …bootloader.bin`，启动日志 `invalid header`=0。
- **真机操作备忘**：C5 原生 USB CDC（COM3）在射频反复重启后可能不再重新枚举，
  但 CH340 UART（COM5）始终可用；从 UART 正常启动的复位时序为 `DTR=1`（拉低 EN）
  → 200ms → `DTR=0`。克隆阶段软 AP 改名为目标 SSID（`WiFi6` 开放），管理热点
  `WiFi-12F9` 会暂时消失，属预期行为而非崩溃。

### 2026-11-12（四）审核加固：异步跑包 / 槽位容量校验 / 回环绑定 / 口令比较

- **烧录台**：外部固件刷写按目标分区校验容量（`ota_0/1/2` 上限 `0x3F0000`，整片写入 16MB），
  超限直接阻止并提示「文件大小 / 分区上限 / 剩余安全空间」，避免越界覆盖相邻分区。
- **服务端跑包**：新增 `crackHandshakeAsync`，每 25 条候选让出事件循环，长字典不再阻塞
  心跳/烧录等请求；自定义字典上限 100000 → 20000。请求体非法 JSON 统一返回 400，
  新增 `app.onError` 兜底。
- **绑定策略**：默认固定监听 `127.0.0.1`（不再因配置 `ADMIN_TOKEN` 而自动开放 `0.0.0.0`）；
  远程访问需显式 `HOST=0.0.0.0` 并配合 HTTPS 反向代理 / IP 白名单。
- **固件**：`tokenEquals` 以完整 `size_t` + 32 位累积量比较，消除 `uint8_t` 长度差截断；
  凭据表字段 `mac` → `clientIp`（API 同时输出 `clientIp` 与 `mac` 保持兼容）；
  AP 初始口令改由串口输出，不再进入网页日志。
- **体积**：4MB `esp32c5` 97.2%（1,910,455 / 1,966,080，+308 B）；`esp32s3` 80.3%、
  经典 `esp32` 66.9%、`esp32c5_16mb` 46.3%；RAM 14.9%。
- **测试**：`npm test` 56/56（新增 4 条审核加固契约：槽位容量、异步跑包 yielding 与字典限流、
  `HOST` 回环绑定、口令比较/字段名纠正）。

### 2026-11-12（四）P4-2/P4-3：WiFi OUI 厂商列 + ASTM F3411 Remote ID

- **P4-2 厂商列**：扫描页 BSSID、Airodump 的 AP / Station 在 MAC 下方显示 OUI 厂商名
  （公开 IEEE 注册表，经 `vendor_db.js` 查表）；首字节 bit1 置位的本地管理地址如实标注
  「随机 MAC」，不反查真实厂商。Sniffer 表格不加列，源/目的 MAC 用 `title` 悬停提示。
- **P4-3 Remote ID**：新增 `RidData` / `RidEntry` / `ridParseMessage` / `ridParsePack` /
  `ridFromWifiFrame` / `ieFindVendor` / `ridUpsert`，纯被动解析 BLE Service Data
  （0xFFFA + 0x0D）与 WiFi 厂商 IE（`FA-0B-BC` / 0x0D）中的 Basic ID / Location / System；
  同一 MAC 归并 BLE 与 WiFi 数据，2 分钟 TTL、上限 8 条。新增只读端点 `GET /api/rid`，
  `/api/ble/*` 与 `/api/sniffer/*` 既有字段不变。
- **UI**：Sniffer 页新增 Remote ID 卡片（UAS ID、机型 / ID 类型、无人机与操作员坐标、来源、
  RSSI、最后出现），坐标点击复制，不加载任何在线地图；BLE 设备行补 UAS ID / 坐标次行。
- **体积**：4MB `esp32c5` 97.2%（1,910,147 / 1,966,080，P4-2/P4-3 合计增量 5,968 B，余量 55,933 B）；
  RAM 14.9%；`esp32s3` 80.3%、经典 `esp32` 66.9%；`esp32c5_16mb` 46.3%。
- **测试**：`npm test` 52/52（新增 5 条：OUI 查表 / 随机 MAC、展示位置、Remote ID 9 条向量回放、
  `/api/rid` 字段与纯被动边界、卡片不加载在线地图）；真机信号验证待 C5 实板。

### 2026-11-12（四）P4-0/P4-1：BLE 设备画像 + 公开厂商表

- **数据源与生成脚本**：新增 `tools/gen-vendor-tables.mjs`，从 IEEE OUI + Bluetooth SIG
  Assigned Numbers 生成 `firmware/data/vendor_db.js`（OUI 512 / Company 256 / Service 84），
  支持 `--fetch` / `--check`；新增 `THIRD_PARTY.md` 记录数据来源，不引入任何第三方代码。
- **BLE 字段扩展**：`BleDeviceEntry` 增加 `companyId` / `svcUuid` / `svcData` / `devClass` /
  `randomMac` 与 `rid*` 预留字段；`onResult` 读取 Manufacturer Data、Service UUID、
  Service Data，全程只把定长前缀拷入临界区。
- **设备分类**：固件内按整数规则识别 AirTag/Find My、iBeacon、Eddystone、BTHome、小米、
  Govee、Ruuvi、Fast Pair、Remote ID；文案与厂商名由 `vendor_db.js` 映射，改文案不动 C++。
- **API / UI**：`/api/ble/status|devices` 只新增字段（旧字段保留）；BLE 页扩为 8 列，
  新增「厂商 / 类型」胶囊与「随机 MAC」提示；新增公开只读资源 `GET /vendor-db.js`。
- **体积**：4MB `esp32c5` 96.9%（1,904,179 / 1,966,080，P4-1 增量 13,616 B，余量 61,901 B）；
  RAM 14.7%；`esp32s3` 79.9%、经典 `esp32` 66.5%；`esp32c5_16mb` 46.1%。
- **测试**：`npm test` 47/47（新增 6 条 P4 契约：字段/10 条分类向量/纯被动/vendor_db 结构/
  内嵌同步/UI 列数）；真机分类效果待 C5 实板确认。

### 2026-11-12（四）16MB 三系统分区表接入构建

- **根因修复**：`partitions-16mb-triple.csv` 此前只有文档与契约测试引用，所有 env 仍用
  `min_spiffs.csv`，导致烧录台写入 `0x400000` / `0x7F0000` 的 ESPsoup / Muse 固件不对应
  任何可引导分区，后台与串口 `boot` 切换均报「未找到分区」。现新增 `[env:esp32c5_16mb]`
  （`extends = env:esp32c5`）并使用 16MB 三系统表，4MB 版 `esp32c5` 保持 `min_spiffs` 不变。
- **构建链路**：`build-firmware.sh` 的 `CHIPS` 增加 `esp32c5_16mb`，esptool 物理芯片型号
  经 `ESPTOOL_CHIP` 映射回 `esp32c5`（bootloader 偏移同为 `0x2000`）；`merge-bin` 仍按
  4MB pad，只覆盖 `ota_0` 范围，重复刷新审计固件不会抹掉 `ota_1`/`ota_2`。
- **分区表编码**：CSV 注释改为纯 ASCII —— Windows 下 PlatformIO 按系统默认编码（GBK）
  解析 `board_build.partitions`，中文注释会 `UnicodeDecodeError` 直接构建失败。
- **服务端 / 烧录台**：`CHIP_ALIASES` 与 `BOOTLOADER_OFFSET` 登记 `esp32c5_16mb`（`0x2000`）；
  烧录台显示「ESP32-C5 (16MB 三系统)」，且自动识别不再覆盖手动选中的同芯片变体镜像。
- **验证**：`pio run -e esp32c5_16mb` SUCCESS（Flash 45.8% / RAM 14.5%）；分区表反解确认
  `ota_0/1/2` 各 4032K、偏移与烧录台一致；合并镜像正好 4MB，`0x2000` 为 `0xE9`、
  `0x8000` 为 `0xAA50`；`npm test` 41/41 通过。
- **文档**：`firmware-flashing.md` §6 增补镜像/env 对应表、构建自检、真机验证清单与常见问题。
- ⬜ 真机验证待执行（需 ESP32-C5N16R8）：刷 16MB 镜像 → 分写 `ota_1`/`ota_2` → 切换 →
  重刷审计固件确认外部系统仍保留。

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

### 2026-11-14 CNA 全平台防拦截升级与脱机便携扩展 (v1.1.0-portable)

**Added & Enhanced**
- **Captive Portal 防弹窗拦截（全平台 CNA 深度适配）**：
  - 重构 `captiveRedirect()` 与 `notFound()` 逻辑，全覆盖 iOS、Android（含 MIUI/HyperOS、HarmonyOS、ColorOS、OriginOS）、Windows 11/10 的探活机制。
  - **iOS / macOS CNA**：拦截 `captive.apple.com/hotspot-detect.html` 与 `/library/test/success.html`，发送防缓存头 `Cache-Control: no-cache` 并注入 `<meta http-equiv="refresh">` 与 JS 双跳转，使 iOS 持续判定为受限网络并保持全屏 CNA 弹窗不自动关闭。
  - **Android / 鸿蒙 / 小米**：精准拦截 `/generate_204`、`/gen_204`、`/check_network` 等探测路径，严禁返回 204（避免系统误判有网不弹窗），统一返回 302 强制导流，触发系统“需要登录 Wi-Fi 网络”强提醒并调起系统验证窗。
  - **Windows NCSI**：拦截 `/connecttest.txt` 与 `/ncsi.txt`，触发 NCSI 机制弹出系统浏览器。
  - **全量保活兜底**：所有未知路径与 404 全量重定向至钓鱼门户或管理后台。
- **脱机便携硬件实装（0.96寸 OLED 屏幕 + 蜂鸣器）**：
  - 编写自主研发的超轻量 SSD1306 I2C 驱动（`firmware/src/ssd1306_tiny.h`），纯基于 `Wire.h` 实现，零第三方库依赖，仅占 1024 字节显存缓冲，编译极快、内存极省。
  - **屏幕双模式智能切换**：
    - **常规状态仪表盘**：实时显示软 AP SSID、当前运行模式（`[EvilTwin]` / `[Deauth]` / `[Idle]`）、锁定目标、连接客户端数、捕获凭据数、剩余内存与运行时间。
    - **凭据捕获大字直显页**：受害者在钓鱼页提交密码时，屏幕自动切屏以 12×16 像素双倍大字体明文展示密码与受害者 IP，彻底脱离电脑与手机后台。
  - **蜂鸣器声学反馈**：
    - 开机自检提示：短促双音 "嘟嘟"；
    - 验真成功捕获：三声上扬悦耳胜利音（代表密码经本地 PBKDF2 + MIC 校验 100% 真实可用）；
    - 未校验捕获：双声警报音。
  - **硬件引脚标准化**：OLED SDA=IO4, SCL=IO5; 蜂鸣器=IO13；适配开发板 `HW-982` / `ESP32-C5-DevKit V2.0`。
- **开发板双 Type-C 端口兼容**：全面兼容下方原生 USB 口（`-DARDUINO_USB_MODE=1 -DARDUINO_USB_CDC_ON_BOOT=1`），并提供免独占排错指南。

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
- C5 5GHz / BLE 5 / 802.15.4 能力扩展：P0（5G 抓包）与 P1（5G AP 非 DFS、5G 取消认证 /
  双子含 DFS 跳频）已实现；**2026-11-13 真机已验证 5G 克隆 AP + 5G 取消认证 +
  双频跳频压制**（见 `tools/c5-feature-acceptance-report.md` §5）。P2（BLE 广播嗅探，
  C3/C5/C6/S3 走 NimBLE，经典 ESP32 因 Bluedroid 体积与双 app 槽冲突而裁剪）与
  P3（802.15.4 纯被动嗅探 + 信道能量扫描，C5/C6 开放）已实现，C5 上已真机验证基本链路，
  其余芯片待复核。差距与改造清单见
  [docs/plans/2026-11-11-c5-5ghz-ble-802154-roadmap.md](docs/plans/2026-11-11-c5-5ghz-ble-802154-roadmap.md)
- P4 设备识别与指纹（BLE 厂商/类别、OUI 厂商名、ASTM F3411 Remote ID）：
  **P4-0/P4-1/P4-2/P4-3 已实现，C5 真机已验证 BLE / 802.15.4 / Karma 基本链路**
  （见 `tools/c5-feature-acceptance-report.md`）——公开数据生成 `vendor_db.js`、BLE 字段扩展与
  10 类设备画像、`/vendor-db.js` 资源路由、扫描/Airodump OUI 厂商名、BLE + WiFi Remote ID
  解析与 `GET /api/rid`、契约测试；4MB C5 实测 97.2%（P4 全增量 +19.6KB）。见
  [docs/plans/2026-11-12-p4-device-identification-roadmap.md](docs/plans/2026-11-12-p4-device-identification-roadmap.md)
- 其余 5 颗芯片（esp32/s2/s3/c3/c6）真机首刷 + 热点后台端到端待补（C5 已全链路验证）
