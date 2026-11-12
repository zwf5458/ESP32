# ESP32 无线固件烧录台 + 固件 设计文档

日期：2026-11-09
参考：[ESP32Marauder](https://github.com/justcallmekoko/ESP32Marauder)、[esp32.ssaa.cc.cd 烧录台](https://esp32.ssaa.cc.cd/)

## 1. 目标

复刻参考站的完整链路（本地版）：

> 网页连串口 → 校验一次性烧录码 → esptool-js 整片烧录（0x0 起）→ 成功后后端核销
> → 芯片重启出热点 `WiFi-xxxx`（密码 00000000）→ 连上访问 `http://192.168.4.1/admin.html` 管理后台

第一版范围（已确认）：

- 芯片：**全系列** ESP32 / ESP32-S2 / ESP32-S3 / ESP32-C3 / ESP32-C5 / ESP32-C6
  （C5 为实验性支持：镜像可出、真机待验证）
- 固件功能：AP 热点 + Web 后台（10 页 SPA，见 §4.1）；v1.1.0 起含 Evil Twin / Deauther /
  握手包 / Sniffer / Airodump / Karma / BLE 扫描教学验证模块，均为**真实空口实现**，
  使用边界见 §3.1（仅限自有或书面授权的受测环境）
- 烧录码：**真后端**发码 / 两段式核销（verify → redeem）
- 部署：先 localhost 跑通（Web Serial 对 localhost 放行），不上云
- 技术栈：Node.js（Hono + better-sqlite3）、纯静态前端（esptool-js）、PlatformIO + Arduino

## 2. 仓库结构

```
ESP32/
├── firmware/                     # PlatformIO 工程
│   ├── platformio.ini            # 6 个可编 [env:*]（c5 需 tools/install-c5-libs.sh 注入）
│   ├── src/main.cpp              # 共享固件逻辑（AP + 鉴权 API + 抓包/教学模块 + 日志/扫描/目标）
│   ├── src/admin_page.h          # 自动生成（data/admin.html deflate 内嵌数据）
│   ├── src/wifi_weak_dict.h      # 内置 7,153 条弱口令（tools/build-wordlist.mjs 生成）
│   ├── data/admin.html           # 固件后台 SPA 源文件（10 页）
│   └── tools/
│       ├── embed_admin_page.py   # 预构建脚本: admin.html → admin_page.h
│       └── patch-platformio-c5.py # espressif32 平台 C5 补丁（幂等可重跑）
├── flasher/                      # 烧录台纯静态前端（Neo-brutalism）
│   ├── index.html
│   ├── app.js                    # Web Serial + esptool-js 流程（含镜像 MD5/大小校验）
│   └── style.css
├── server/                       # Hono + better-sqlite3
│   ├── src/index.js              # 入口（serveStatic 使用绝对路径, 必须仓库根目录启动）
│   ├── src/logic.js              # 纯逻辑（nonce / 限流 / 口令常量时间比较 / 路径边界）
│   ├── src/wpa.js                # WPA 跑包（PBKDF2 / PRF / KDF / AES-CMAC / MIC / 帧解析）
│   ├── data/weak-passwords.txt   # 服务端字典（与固件同序同量）
│   ├── test/index.test.js        # 契约测试（38 项）
│   ├── firmware/                 # 合并镜像 bin 存放处（build-firmware.sh 注册）
│   └── db.sqlite                 # 运行时生成（git 忽略；含 -shm/-wal）
├── tools/                        # 构建与运维脚本（详见 README「目录结构」）
└── docs/plans/                   # 本文档
```

## 3. 固件设计

- PlatformIO 环境：`esp32 / esp32s2 / esp32s3 / esp32c3 / esp32c5 / esp32c6`
  六个 env 全部可编（`espressif32` v8.0.0，Arduino core 3.3.12，统一工具链 14.2.0+20260121）；
  `esp32c5` 因 v8 registry 缺 `esp32c5-libs`，由 `tools/install-c5-libs.sh` 本地注入
  lib-builder `idf-release_v5.5-b774170f` 预编译库 + 平台三处补丁（实验性支持，真机待验证）
- 工具链/框架包获取见 README「PlatformIO 编译环境搭建」：
  工具链用 espressif 官方 crosstool 注入，框架包用 `tools/dl-resume.sh` 断点续传
- 共用 `src/main.cpp`；6 个 env 编译同一份源码，5G / BLE 能力差异一律用编译期宏门控
  （`SOC_WIFI_SUPPORT_5G`、`FW_BLE_SUPPORTED = SOC_BLE_SUPPORTED && !FW_BLE_DISABLED`），
  不做源码分叉；经典 ESP32 因 Bluedroid 体积与 4MB 双槽冲突在 `platformio.ini` 里
  `-DFW_BLE_DISABLED` 裁剪 BLE
- 串口 UART 日志 115200（烧录台串口控制台可见；未启用 USB CDC 宏）
- AP：SSID `WiFi-` + MAC 尾 4 位十六进制，密码 `00000000`，信道 6
- Captive Portal（强制门户）：`DNSServer` UDP 53 通配 `*` 解析 → `192.168.4.1`；
  `notFound()` 对 iOS(`/hotspot-detect.html`) / Android(`/generate_204`) /
  Windows(`/connecttest.txt`) 探测路径与任意未知路径返回 302 → `/admin.html`，
  连热点自动弹后台；`/api/*` 保持 404 以不破坏后台 SPA fetch 契约
- 后台：`http://192.168.4.1/admin.html`，deflate 后内嵌（10 页，见 §4.1）：
  - 设备信息：芯片型号、MAC、固件版本、运行时长、可用内存
  - 主目标 / 双子目标信息（扫描页选定后回填，仅存 RAM）
  - 内存诊断：可用 / 最低水位 / 最大块 / 碎片率
  - 系统日志（环形缓冲 64 条，`GET /api/log?since=id` 增量拉取）
  - 复位按钮、恢复出厂按钮（V1：擦除 NVS 后重启）
- 后台鉴权：除强制门户用的 `POST /api/portal/submit` 外，所有 `/api/*` 需
  `X-Admin-Token`（兼容 `?token=`），401 时不执行业务 handler。首次上电用硬件 TRNG
  生成每台设备唯一的 12 位初始口令，仅 `Serial` 直出一次（不经 `log()`，不进遥测 /
  `/api/log`）；旧版静态 `esp32admin` 在升级时自动轮换，`/api/info` 的
  `mustChangeToken` 提示面板引导改密。
- 固件 API（device，均需鉴权）：
  - 信息 / 配置：`GET /api/info`、`GET /api/config`、`POST /api/config`、
    `POST /api/reset`、`POST /api/factory-reset`
  - 扫描 / 目标：`GET /api/scan`（APSTA）、`POST /api/target`（`role=primary|twin`）、
    `POST /api/twin`、`DELETE /api/twin`
  - 日志：`GET /api/log?since=`
  - 教学模块：`/api/eviltwin/*`、`/api/deauth/*`、`/api/handshake/*`、
    `/api/sniffer/*`、`/api/airodump/*`、`/api/karma/*`（清单见 README「设备端 API」）
  - 各模块状态（`evilTwin` / `deauth` / `handshake` / `sniffer` / `airodump` / `karma`）
    并入 `/api/info`；不提供 `/api/handshake/status`，跑包统一走
    `POST /api/handshake/crack`
- 镜像产出：每个 env 编译后
  `esptool merge-bin -o firmware-<target>-<ver>.bin`
  即 bootloader+partition+app 单文件，整片从 0x0 烧录。
  **bootloader 偏移按芯片 ROM 规定**（见 README「合并镜像布局」）：
  `esp32/s2=0x1000`、`esp32c5=0x2000`、其余 `=0x0`；
  partitions 固定 `0x8000`、app 固定 `0x10000`。
  后端注册时按对应偏移校验 `0xE9` 魔数。
  ⚠️ espressif32 v8 平台把 c5 也按 0x0 处理（适配缺陷），构建脚本显式按芯片指定。
- 版本：`FW_VERSION` 宏（如 "1.1.0"），后台显示 + 镜像文件名携带；发布构建由
  `tools/build-firmware.sh` 经 `PLATFORMIO_BUILD_FLAGS` 注入（PlatformIO 6.2 的
  `pio run` 无 `--build-flag`），直接 `pio run` 时由 `main.cpp` 的 `#ifndef` 兜底

## 3.1 合规边界

v1.1.0 起，教学验证模块（Evil Twin / Deauther / 握手包 / Sniffer / Airodump / Karma /
BLE 扫描）均为**真实空口实现**，对周边网络有真实影响；本节定义其使用边界，不构成对第三方网络的
使用许可。完整能力矩阵（6 颗芯片行为一致，README「功能范围与合规边界」同源）：

| 模块 | 状态 | 说明 |
|---|---|---|
| AP 热点 | ✅ 实现 | `WiFi-` + MAC 尾 4 位 / `00000000` / `192.168.4.1` |
| Web 后台 10 页 | ✅ 实现 | 状态总览 / 扫描与嗅探 / 邪恶双子 / Karma / 取消认证 / 数据包分析器 / Airodump / BLE 扫描 / 捕获凭据 / 配置（内嵌 SPA） |
| 后台口令鉴权 | ✅ 实现 | 每台设备随机初始口令（串口一次性输出）；`/api/*` 需 `X-Admin-Token`，面板内改密 |
| Captive Portal | ✅ 实现 | UDP 53 通配解析 + OS 探测路径 302 → 连热点自动弹后台 |
| 周边 AP 扫描 | ✅ 实现 | 被动列出 SSID/RSSI/信道/加密方式（合法观察） |
| 已连客户端计数 | ✅ 实现 | `softAPgetStationNum()` 只读 |
| 事件日志 | ✅ 实现 | 64 条环形缓冲，`/api/log?since=` |
| 内存/运行诊断 | ✅ 实现 | 堆 / PSRAM / 信道 / uptime |
| Evil Twin（邪恶双子） | ✅ 真实实现 | 攻击时热点真实改名为与主目标一模一样的 SSID（开放无密码、信道对齐主目标，2.4G 或 5G 非 DFS）→ 受害设备免密直连；同时自动对主目标持续注入 Deauth，并对双子目标（通常同路由 5G BSSID，可含 DFS）每 2s 跳频连发 3 帧注入，使目标双频段都无法联网；Captive Portal 自动弹钓鱼页，捕获首条凭据后自动停止干扰，手动停止恢复原热点名/密码/信道 |
| Deauth / 取消认证器 | ✅ 真实实现 | 经 `esp_wifi_80211_tx` 真实注入 Deauthentication 管理帧 (0x00c0)，广播踢出目标 AP 全部客户端；启动时经 `esp_wifi_set_channel` 自动对齐目标信道（临时切换、不写 NVS，已连设备短暂掉线后重连），停止时恢复配置信道 |
| 握手包捕获与跑包 | ✅ 真实实现 | `esp_wifi_set_promiscuous` 真实空口捕获 4-Way Handshake（M1~M4 + PMKID KDE）；板载内置 7,153 条弱口令跑包（PBKDF2-HMAC-SHA1 4096 轮 → PTK → MIC 比对，keyver 1/2）；keyver 3（PMF）导出交服务端 `POST /api/wpa/crack`（SHA256-KDF + AES-CMAC） |
| 数据包分析器 (Sniffer) | ✅ 真实实现 | 共用 promiscuous 回调抓管理/控制/数据帧，解析类型、源/目的 MAC、SSID、Deauth Reason；支持单信道停驻与 1-13 跳频，实时帧率统计 |
| Airodump 侦察 | ✅ 真实实现 | 从真实空口帧按 MAC 聚合对端（RSSI / 帧数 / 探测过的 SSID），支持 1-13 跳频；与 Evil Twin / Deauth / 握手并行时停驻当前信道 |
| Karma 探针诱捕 | ✅ 真实实现 | 监听真实 Probe Request，记录客户端 MAC / 目标 SSID / RSSI；SSID 命中克隆热点时标记「已诱捕」，并复用握手捕获链路同步收集 4-Way Handshake |
| BLE 广播嗅探 | ✅ 真实实现 | 纯被动监听周边 BLE 广播（ADV_IND / SCAN_RSP 等），解析 MAC / 名称 / RSSI / 广播类型 / 厂商数据摘要 / 广播计数；**不发 SCAN_REQ、不连接、不读特征值**。C3/C5/C6/S3 开放（NimBLE），经典 ESP32 因 Bluedroid 体积与 4MB 双槽冲突裁剪，S2 无蓝牙硬件 |

**v1.1.0 起定位为「教学验证」**：上述教学模块在**受控教学 / 自有授权设备**范围内启用
（用户明确决策，见变更记录 2026-11-09 三）。其中 Deauther、握手包、Sniffer、Airodump、
Karma 自 2026-11-10 / 2026-11-11 起为真实空口实现，影响真实周边网络，使用时须遵守：

① 仅在自有网络或取得书面授权的受测环境中使用；
② 不得对第三方网络/设备进行伪造 AP、解除认证或凭据收集；
③ 凭据捕获页（`addCredential`）记录的是受测端在本教学门户提交的口令，
   仅限演示，不应用于真实网络，实验后应清空。

法律提醒：干扰他人通信 / 伪造他人网络可触及《网络安全法》第 27 条等，
销售形态风险更高；C5 作为 WiFi 6 双频芯片对 raw TX 的 SDK 支持受限
（此时 Deauther 会返回 TX 错误码并在后台如实标注，不再计数）。
Deauther 自 2026-11-10 起为**真实空口帧注入**；握手包模块自 2026-11-10 起为
**真实空口抓包 + 真实离线跑包**（promiscuous 解析 EAPOL-Key 帧，MIC 校验与
aircrack-ng 官方向量一致）；Evil Twin 自 2026-11-10 起为**真实实现**
（热点真实改名 + 开放认证 + 联动 Deauth 双频段压制 + 真实凭据捕获）。
Sniffer / Airodump / Karma 自 2026-11-11 起为**真实抓包**（共用 promiscuous 回调，
Karma 监听真实 Probe Request 并复用握手捕获链路）。
UI 与法律声明页应明示「仅限授权教学」。

## 3.2 视觉规范（Neo-brutalism）

烧录台与固件后台统一视觉语言：
- 奶油底 `#f5f0e8` + 3px 黑描边 + 4~6px 硬投影（无渐变模糊阴影）
- 明快色块：黄 `#ffe14d` / 粉 `#ff9ecf` / 蓝 `#7fd9ff` / 绿 `#c8f7c2` / 紫 `#b7a4ff`
- 强调红字 `#d3230f`；控制台/日志区黑底绿字 `#33ff66`
- 等宽标题（SF Mono）+ PingFang SC 正文；按钮按下位移效果
- 暗色主题：同布局换深底配色（烧录台 + 后台均可切换、烧录台侧持久化）
- 后台骨架：黄色顶栏 + 汉堡抽屉（品牌条 / 分组导航 / 语言选择）+ 右上运行时间与内存条

## 3.3 Serial JSON 遥测协议（外部设备即插即用）

保留 WebServer 与文本日志不变，固件在 115200 串口**额外**输出 NDJSON
（每行一个 `{...}`）。以 `{` 开头即视为 JSON 事件，其余为文本日志，消费者按行判断。

帧格式：`{"v":1,"ts":<毫秒>,"event":"<type>", ...}`

| event | 触发 | 字段（全部只读） |
|---|---|---|
| `boot` | 上电 | chip / fw / ssid / mac / channel |
| `log` | 每次日志（`log()` 自动镜像） | id / line |
| `heartbeat` | 每 30s | clients / heap / minFree / uptime / ssid |
| `scan_result` | 扫描时每个 AP | ssid / rssi / ch / bssid / auth |
| `client_join` / `client_leave` | softAP 客户端数变化 | clients |
| `lab_state` | 教学模块启停 | module / running |
| `eviltwin` | Evil Twin 首次捕获到门户提交 | caught / client（客户端 IP，不含口令） |

**边界**：只镜像已有只读状态。不含 Probe Request/Response、802.11 管理帧、
EAPOL/握手材料（M1~M4、PMKID、nonce、MIC）、凭据或密码字段；捕获凭据的文本日志
只记录长度，明文仅保留在受后台口令保护的凭据表 API 中。后台初始口令只经 `Serial`
直出一次、不经过 `log()`，因此不会被镜像成 `log` 事件。
消费端 `tools/serial-telemetry.py`（pyserial）支持自动探测端口、按行解析、
`--event` 订阅过滤、`--raw` 原样输出、`--save` 导出 NDJSON。
烧录台控制台提示标注「文本日志 + NDJSON 遥测」，不做逐行富文本高亮
（串口是流式分片，避免改动 `terminalAppend` 引入解析 bug）。

## 4. 烧录台前端

单页 Neo-brutalism，左列步骤卡 + 右列控制台/信息卡：

1. ① 串口连接：`navigator.serial.requestPort`；「跳过自动复位」复选框
   （连不上时手动 BOOT 进下载模式）
2. ② 烧录码：输入框 + 「✓ 校验烧录码」→ `POST /api/codes/verify`（得一次性 nonce）；
   「本地发码」徽章提示取码方式
3. ③ 开发板与烧录：esptool-js 读芯片 → 从 manifest 自动匹配镜像（下拉联动）；
   「开始烧录」需先勾选《使用条款》；`writeFlash` 整片从 offset 0 写合并镜像
    （bootloader 在镜像内的偏移由 merge 阶段按芯片决定，见 §3）；
   条纹进度条实时百分比
4. ④ 当前固件版本：大号版本号（读 manifest）+ 覆盖芯片说明

右列：黑底绿字**串口控制台**（带时间戳；复位/复制/清屏）、
黄色**使用条款与法律声明**、蓝色**设备连接说明**（WiFi- / 00000000 / 后台地址）。

顶栏：品牌徽章 + 连接状态 pill + EN 占位 + ☀️ 暗色主题切换（localStorage 持久化）。

芯片下拉按 manifest 动态生成，全部 6 颗芯片均可手动预选
（串口自动识别成功后自动匹配优先，防止烧错镜像；C5 标注实验性）。

Web Serial 只在 HTTPS 或 localhost 可用 —— 本地跑 `http://localhost:8787` 合法。

## 4.1 固件后台（device admin SPA）

`firmware/data/admin.html`（内嵌，访问 `http://192.168.4.1/admin.html`），
hash 路由 10 页 + 汉堡抽屉。首次打开先显示口令登录层，口令存 `localStorage`，
所有 `api()` / 日志轮询 / POST 操作统一注入 `X-Admin-Token`：

- **状态总览**（`#dash`）：仪表板横幅、模块状态三卡、主/双子目标信息、内存诊断四指标
  （可用/最低水位/最大块/碎片率）、红色法律声明、绿字系统日志
- **扫描与嗅探**（`#scan`）：黑底 AP 表格（SSID/RSSI/信道/BSSID/安全/目标），
  全部/2.4G/5G 筛选；「设为主目标 / 设为双子」→ `POST /api/target`（`role`）
- **邪恶双子**（`#eviltwin`）：主/双子目标、克隆 SSID 输入框（留空跟随主目标，
  攻击中禁用）、实时状态条（克隆热点 / Deauth 帧数 / 双子跳频 / 接入设备）、捕获凭据入口
- **Karma**（`#karma`）：探针诱捕列表与启停；同屏展示 4-Way Handshake 捕获状态与跑包
- **取消认证**（`#deauth`）：帧率/Reason Code、信道对齐提示、真实 TX 计数
- **数据包分析器**（`#packet`）：帧类型统计、单信道/跳频、实时帧率
- **Airodump 侦察**（`#airodump`）：按 MAC 聚合的对端表（RSSI/帧数/探测 SSID）
- **BLE 扫描**（`#ble`）：纯被动广播嗅探，设备表（MAC/名称/RSSI/广播类型/厂商数据/
  广播计数/最后出现）、设备数与累计广播数、可选时长与导出 JSON；扫描期间 AP 保持
  在线但吞吐下降（50% 占空比），页面明确提示。无 BLE 硬件或已裁剪的芯片整页隐藏
- **捕获的凭据**（`#creds`）：门户提交记录，支持清空
- **配置**（`#cfg`）：热点 SSID/信道（`POST /api/config` 持久化 NVS）、后台口令修改、
  重启、恢复出厂；修改后需重启生效
- 首次仍使用初始口令时，顶部提示并引导到「配置」改密（`mustChangeToken`）
- 轮询：`/api/info` 2s、`/api/log?since=` 1.5s；模块页按 hash 定向轮询，避免重建 DOM

## 5. 后端 API

| 接口 | 说明 |
|---|---|
| `GET /api/health` | 服务健康探针 (状态/运行时间/固件镜像计数/时间戳) |
| `GET /api/firmware/manifest` | 芯片 → { version, md5, size, chipMagic } |
| `GET /api/firmware/bin/:chip` | 下载对应合并镜像 (支持 ETag / 304 缓存) |
| `POST /api/codes/verify` | 校验一次性码 → `{ nonce }`（15 分钟有效，滑动窗口限流与 Retry-After） |
| `POST /api/codes/redeem` | nonce+chip+md5 匹配才核销，单次消费 + 事务原子防并发，失败不扣 |
| `POST /api/admin/codes` | header `x-admin-token` 鉴权，批量生成 N 个码 |
| `GET /api/admin/codes` | 码列表与状态（未用/verified/redeemed） |
| `GET /api/admin/stats` | 管理统计（码 / 镜像 / 烧录历史汇总） |
| `GET /api/admin/flash-log` | 烧录历史（成功/失败、芯片、码、md5、时间） |
| `POST /api/admin/firmware/:chip` | 注册/替换某芯片镜像（带版本正则与工作区路径越界安全检查） |
| `POST /api/wpa/crack` | 服务端跑包（keyver 3 / 自定义字典），内置字典或 `dictionary`，返回命中/尝试数/耗时 |

> 服务端管理接口的 `ADMIN_TOKEN` 与设备端后台口令是两套独立凭据；管理接口校验为
> 定长 SHA-256 摘要 + `timingSafeEqual`。`verify` 限流默认只取 TCP 对端 IP，
> 仅 `TRUST_PROXY=1` 时采信可信代理的 `X-Forwarded-For` 链尾。

烧录码生命周期：`未用 → verified(15min) → redeemed`；
redeem 只在 writeFlash 完整成功后由前端触发，且后端按 nonce+chip+md5 匹配，
同码无法多机复用，失败可安全重试（重新 verify）。

## 6. 数据表

- `codes(code TEXT PK, status, verify_at, redeem_at, chip, remark, created_at)`
- `firmwares(chip TEXT PK, version, bin_path, md5, size, created_at)`
- `flash_log(id PK, chip, code, md5, result, ts)`

## 7. 错误处理

| 情况 | 行为 |
|---|---|
| 串口打不开/被占 | 提示换线 / 更新浏览器 / 勾跳过自动复位 |
| 芯片识别失败 | 引导手动 BOOT + 复位；不扣码 |
| 写入中断/失败 | 不核销，重新 verify 拿新 nonce 后可重试 |
| nonce 过期 | 提示重新校验 |
| 用过的码 | verify 直接拒绝，页面提示一次性规则 |

## 8. 验收清单（第一版完成标准）

1. `node server/src/index.js` 起服务，`npm run gen-code -- 3` 生成 3 个码 ✓
2. 无板子：verify 通过 → 烧录失败/取消 → DB 状态仍 `未用` ✓
3. 真机烧录：烧录完成 → 控制台启动日志 → 记录 `redeemed` + flash_log ⬜（待真机）
4. 手机连 `WiFi-xxxx` / `00000000` → Captive Portal 自动弹窗或手动
   `http://192.168.4.1/admin.html` → 用串口输出的随机初始口令登录，显示后台 10 页 + 版本 ⬜（待真机）
5. 二次烧用已核销的码 → verify 拒绝 ✓
6. 可编 6 颗芯片镜像全部产出并出现在 manifest ✓
   （esp32/s2/s3/c3/c5/c6 各 4MB 合并镜像；c5 为本地注入 libs 编出，实验性）
7. 代码审查修复回归（2026-11-09 二）✓：
   - 6 镜像 bootloader 落在其 ROM 规定偏移（0x1000 / 0x2000 / 0x0），该处 `0xE9` ✓
   - 后端按芯片偏移校验魔数：3 种偏移注册放行、坏镜像 400 拦截 ✓
   - verify 限流（第 11 次起 429）、nonce 过期清理、token 不打印 ✓
   - 烧录台 `consoleHint` 元素存在/零 JS 报错、静态托管脱离 cwd ✓
   - Captive Portal：6 env 全部编译 SUCCESS（DNSServer 引入无回归）✓

8. Serial JSON 遥测（2026-11-09 四）✓：
   - `emitJson`/`emitLabState` 编译通过（esp32 / esp32c5 代表性芯片 SUCCESS）
   - `tools/serial-telemetry.py` 语法/`--help`/伪串口消费逻辑/`--event` 过滤单测通过 ✓
   - 事件 schema 敏感字段扫描通过（无 password/eapol/M1-M4/pmkid/nonce/MIC/凭据）✓
   - ⬜ 真机串口输出实测（需接板子用脚本读 115200）

9. P0/P1 代码修复与系统健壮性优化（2026-11-10）✓：
   - 自动化测试套件 `npm test`（10 项单元测试全部 PASS，耗时 ~15ms）
   - 固件 `extractJson` 字符串/数字转义解析彻底修复，恢复全部 10 处 API 提取能力 ✓
   - 固件 `htmlEscape` 杜绝 XSS 注入；Captive Portal 重定向对齐 CNA 绝对 URI 规范 ✓
   - Nonce 单一活跃性保证与事务原子 Redeem，杜绝并发竞争与重放核销 ✓
   - 镜像注册路径越界防御（`isWithinRoot`）与版本号正则安全过滤 ✓
   - NVS 热点配置持久化（SSID / Channel），后台 SPA 与固件双向联动 ✓
   - 固件下载 ETag 304 缓存响应与限流 `Retry-After` 秒数标准响应头 ✓
   - 跨平台 CLI 工具 `tools/gen-code.mjs`（`npm run gen-code` / `codes` / `stats`）与 `tools/pack-admin.mjs` ✓
   - 串口遥测 `--reconnect` 支持动态端口自动探测恢复 ✓

10. 2026-11-11 安全加固 / 抓包真实化 / 全量重建 ✓：
   - 后台口令改设备唯一随机初始口令（TRNG + NVS，仅串口一次），旧版静态口令自动轮换；
     口令比较常量时间，`/api/*` 未带口令返回 401 且不执行业务 ✓
   - Sniffer / Airodump / Karma 改为共用 promiscuous 回调抓真实帧（去掉模拟计数），
     Karma 启停双响应修复 ✓
   - 删除冗余 `/api/handshake/status` 与 `/api/karma/crack`，握手/模块状态并入
     `/api/info`，契约测试补「不得回退」断言 ✓
   - 邪恶双子「克隆 SSID」输入框（留空跟随目标）与 `eviltwin` 遥测登记 ✓
   - 烧录台下载镜像后本地校验 manifest MD5/大小，latin1 串复用 ✓
   - `npm test` 38/38 通过 ✓
   - 6 芯片 v1.1.0 镜像全量重建并注册；DB `md5`/`size` 与磁盘逐字节一致，
     镜像内嵌 `admin.html` 与源文件逐字节一致 ✓
   - ⬜ 真机端到端（随机口令串口输出 / 首次登录跳配置 / 三模块真实抓包）

## 9. 后续阶段（非本期）

- 教学模块空口实现：Deauther / Evil Twin / 握手包 / Sniffer / Airodump / Karma 已完成
  真实实现；剩余为 C5 真机复核（双频并发压制、raw TX 支持度）与端到端验收。
  真抓包涉及监听他人网络的授权边界（法律风险高）
- 云部署（HTTPS 域名 + CDN 托管静态烧录台）
- 图文教程静态页（tw.html / az.html 等）
- ESP32-C5 真机验证（镜像已产出；espressif32 v8 无官方 c5-libs，
  由 tools/install-c5-libs.sh 本地注入编译，板级参数待真机复核）
- Web 发码管理页（当前仅 `tools/gen-code.mjs` CLI 发码 + `POST /api/admin/codes`）
- **C5 5GHz / BLE 5 / 802.15.4 能力扩展**：差距与改造清单见
  [C5 5GHz / BLE 5 / 802.15.4 能力差距与改造清单](./2026-11-11-c5-5ghz-ble-802154-roadmap.md)。
  当前 AP / 取消认证 / 双子的 5G 路径已实现（**P0** 5G 抓包停驻与跳频；
  **P1** 5G AP（非 DFS）、5G 取消认证/双子（含 DFS 跳频注入），均待 C5 真机验证）；
  **P2** BLE 广播嗅探已实现（纯被动，C3/C5/C6/S3 走 NimBLE，
  经典 ESP32 因 Bluedroid 体积与 4MB 双槽冲突裁剪），待真机验证；
  802.15.4（P3）无代码
- ~~CDN 本地化~~（已完成）：`flasher/vendor/` 内置 esptool-js 0.7.1 + crypto-js 4.2.0，
  烧录台不再依赖 unpkg，支持断网/内网，同时获得 C5 识别与整片 Flash 备份能力
- 异步 WiFi 扫描：把同步 `scanNetworks` 改为异步启动 + 轮询，
  避免 C5 双频扫描长时间阻塞触发 TWDT（评估后暂缓，需前端轮询配合）
- 串口探针免码升级：与一次性烧录码核销闭环冲突，**不采纳**

## 10. 文档修订记录

| 日期 | 修订 |
|---|---|
| 2026-11-09 | 初版（AP + 三页后台 + 烧录码闭环） |
| 2026-11-10 | 补 Deauther 真实帧注入、握手包真实抓包 + 跑包、Evil Twin 真实化（同名克隆 + 双频段压制） |
| 2026-11-11 | 后台扩为 9 页并加口令鉴权（设备唯一随机初始口令）；Sniffer / Airodump / Karma 改为真实抓包；删除冗余路由；补 `eviltwin` 遥测；6 芯片镜像全量重建并注册；修正「主动攻击模块不实现」「后台三页」等描述漂移 |
| 2026-11-11 | 新增 [C5 5GHz / BLE 5 / 802.15.4 能力差距与改造清单](./2026-11-11-c5-5ghz-ble-802154-roadmap.md)；§9 标记录 CDN 本地化已完成（esptool-js 0.7.1 + crypto-js 4.2.0 内置） |
| 2026-11-11 | 落地 **P2 BLE 广播嗅探**：后台扩为 10 页（新增「BLE 扫描」）、5 个 `/api/ble/*` 路由、`FW_BLE_SUPPORTED` 能力门控；经典 ESP32 因 Bluedroid 体积（+810KB）与 min_spiffs 双 app 槽冲突用 `-DFW_BLE_DISABLED` 裁剪，S2 无 BLE 硬件 |
| 2026-11-11 | P0 实现：C5 Sniffer / Airodump 支持 5G 停驻与跳频（含跳过 DFS、`band` 状态字段与 UI 分段），6 芯片编译回归通过，待真机验证 |
| 2026-11-11 | P1 实现：5G AP（非 DFS 36–48/149–165）与 5G 取消认证 / 双子（含 DFS 跳频注入）；主目标「2.4G 或 5G 非 DFS」，DFS 明确引导改用双子；状态 JSON 加 `band`；esp32c5/s3 编译通过，`npm test` 40/40，待真机验证 |

