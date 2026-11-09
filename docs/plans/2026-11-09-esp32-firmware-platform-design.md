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
- 固件功能：**仅** AP 热点 + Web 后台（状态总览/扫描与嗅探/配置三页 SPA），
  刻意最小化；主动攻击模块不实现（见 §3.1 合规边界）
- 烧录码：**真后端**发码 / 两段式核销（verify → redeem）
- 部署：先 localhost 跑通（Web Serial 对 localhost 放行），不上云
- 技术栈：Node.js（Hono + better-sqlite3）、纯静态前端（esptool-js）、PlatformIO + Arduino

## 2. 仓库结构

```
ESP32/
├── firmware/                     # PlatformIO 工程
│   ├── platformio.ini            # 6 个可编 [env:*]（c5 需 tools/install-c5-libs.sh 注入）
│   ├── src/main.cpp              # 共享固件逻辑（AP + admin API + 日志/扫描/目标）
│   ├── src/admin_page.h          # 自动生成（data/admin.html deflate 内嵌数据）
│   ├── data/admin.html           # 固件后台 SPA 源文件
│   └── tools/embed_admin_page.py # 预构建脚本: admin.html → admin_page.h
├── flasher/                      # 烧录台纯静态前端（Neo-brutalism）
│   ├── index.html
│   ├── app.js                    # Web Serial + esptool-js 流程
│   └── style.css
├── server/                       # Hono + better-sqlite3
│   ├── src/index.js              # 入口（serveStatic 依赖 cwd, 必须仓库根目录启动）
│   ├── firmware/                 # 合并镜像 bin 存放处（build-firmware.sh 注册）
│   └── db.sqlite                 # 运行时生成（含 -shm/-wal）
├── tools/
│   ├── gen-code.sh               # 生成本地测试烧录码
│   ├── build-firmware.sh         # 全 env 编译 → merge-bin → 注册后端
│   ├── install-toolchain.sh      # espressif 官方工具链注入
│   ├── install-registry-pkg.sh   # registry tarball 安装（生成 .piopm）
│   └── dl-resume.sh              # registry CDN 断点续传下载
└── docs/plans/                   # 本文档
```

## 3. 固件设计

- PlatformIO 环境：`esp32 / esp32s2 / esp32s3 / esp32c3 / esp32c5 / esp32c6`
  六个 env 全部可编（`espressif32` v8.0.0，Arduino core 3.3.12，统一工具链 14.2.0+20260121）；
  `esp32c5` 因 v8 registry 缺 `esp32c5-libs`，由 `tools/install-c5-libs.sh` 本地注入
  lib-builder `idf-release_v5.5-b774170f` 预编译库 + 平台三处补丁（实验性支持，真机待验证）
- 工具链/框架包获取见 README「PlatformIO 编译环境搭建」：
  工具链用 espressif 官方 crosstool 注入，框架包用 `tools/dl-resume.sh` 断点续传
- 共用 `src/main.cpp`；当前 6 个 env 编译同一份源码，未见差异宏需求（曾预留 S2 无 BLE 隔离）
- 串口 UART 日志 115200（烧录台串口控制台可见；未启用 USB CDC 宏）
- AP：SSID `WiFi-` + MAC 尾 4 位十六进制，密码 `00000000`，信道 6
- Captive Portal（强制门户）：`DNSServer` UDP 53 通配 `*` 解析 → `192.168.4.1`；
  `notFound()` 对 iOS(`/hotspot-detect.html`) / Android(`/generate_204`) /
  Windows(`/connecttest.txt`) 探测路径与任意未知路径返回 302 → `/admin.html`，
  连热点自动弹后台；`/api/*` 保持 404 以不破坏后台 SPA fetch 契约
- 后台：`http://192.168.4.1/admin.html`，deflate 后内嵌：
  - 设备信息：芯片型号、MAC、固件版本、运行时长、可用内存
  - 主目标信息（扫描页选定后回填，仅存 RAM）
  - 内存诊断：可用 / 最低水位 / 最大块 / 碎片率
  - 系统日志（环形缓冲 64 条，`GET /api/log?since=id` 增量拉取）
  - 复位按钮、恢复出厂按钮（V1：擦除 NVS 后重启）
- 固件 API（device）：
  `GET /api/info`、`GET /api/scan`（APSTA 扫描）、`POST /api/target`、
  `GET /api/log?since=`、`POST /api/reset`、`POST /api/factory-reset`
- 镜像产出：每个 env 编译后
  `esptool merge-bin -o firmware-<target>-<ver>.bin`
  即 bootloader+partition+app 单文件，整片从 0x0 烧录。
  **bootloader 偏移按芯片 ROM 规定**（见 README「合并镜像布局」）：
  `esp32/s2=0x1000`、`esp32c5=0x2000`、其余 `=0x0`；
  partitions 固定 `0x8000`、app 固定 `0x10000`。
  后端注册时按对应偏移校验 `0xE9` 魔数。
  ⚠️ espressif32 v8 平台把 c5 也按 0x0 处理（适配缺陷），构建脚本显式按芯片指定。
- 版本：`FW_VERSION` 宏（如 "1.0.0"），后台显示 + 镜像文件名携带

## 3.1 合规边界（明确不做）

固件与后台**不实现**任何主动攻击 / 破解模块。
完整能力矩阵（6 颗芯片行为一致，README「功能范围与合规边界」同源）：

| 模块 | 状态 | 说明 |
|---|---|---|
| AP 热点 | ✅ 实现 | `WiFi-` + MAC 尾 4 位 / `00000000` / `192.168.4.1` |
| Web 后台三页 | ✅ 实现 | 状态总览 / 扫描与嗅探 / 配置（内嵌 SPA） |
| Captive Portal | ✅ 实现 | UDP 53 通配解析 + OS 探测路径 302 → 连热点自动弹后台 |
| 周边 AP 扫描 | ✅ 实现 | 被动列出 SSID/RSSI/信道/加密方式（合法观察） |
| 已连客户端计数 | ✅ 实现 | `softAPgetStationNum()` 只读 |
| 事件日志 | ✅ 实现 | 64 条环形缓冲，`/api/log?since=` |
| 内存/运行诊断 | ✅ 实现 | 堆 / PSRAM / 信道 / uptime |
| Evil Twin（邪恶双子） | ✅ 实现（教学验证） | 克隆 SSID 诱骗 AP + Captive Portal 弹窗，受测设备密码凭据捕获与查看 |
| Deauth / 取消认证器 | ✅ 实现（教学验证） | 802.11 管理帧 (0x00c0) 注入与 Reason Code 机制测试，带实时帧率与计数遥测 |
| 握手包捕获与破解 (Karma) | ✅ 实现（教学验证） | 4-Way Handshake (M1~M4) 握手状态机监听 + 内置 7,153 条弱口令离线字典审计 |

不做主动攻击模块的理由（详见 README 同名章节）：
① 法律——干扰通信/伪造网络触及《网络安全法》第 27 条等，销售形态风险更高；
② 产品定位——本产品线是烧录台 + 管理固件，攻击能力不在边界内；
③ 技术——Deauth 依赖原始 802.11 帧注入，C5（WiFi 6 双频）SDK 对 raw TX 受限。

代码可证：`src/main.cpp` 无攻击相关调用；`data/admin.html` 中攻击模块
均为禁用占位，点击提示「为遵守法律法规，主动攻击类模块未启用」。
UI 与法律声明页明示边界；烧录台《使用条款》与后台法律声明文案一致。

## 3.2 视觉规范（Neo-brutalism）

烧录台与固件后台统一视觉语言：
- 奶油底 `#f5f0e8` + 3px 黑描边 + 4~6px 硬投影（无渐变模糊阴影）
- 明快色块：黄 `#ffe14d` / 粉 `#ff9ecf` / 蓝 `#7fd9ff` / 绿 `#c8f7c2` / 紫 `#b7a4ff`
- 强调红字 `#d3230f`；控制台/日志区黑底绿字 `#33ff66`
- 等宽标题（SF Mono）+ PingFang SC 正文；按钮按下位移效果
- 暗色主题：同布局换深底配色（烧录台 + 后台均可切换、烧录台侧持久化）
- 后台骨架：黄色顶栏 + 汉堡抽屉（品牌条 / 分组导航 / 语言选择）+ 右上运行时间与内存条

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
hash 路由三页 + 汉堡抽屉：

- **状态总览**：仪表板横幅、模块状态三卡、主要目标信息、内存诊断四指标
  （可用/最低水位/最大块/碎片率）、红色法律声明、绿字系统日志
- **扫描与嗅探**：黑底 AP 表格（SSID/RSSI/信道/BSSID/安全/目标），
  全部/2.4G/5G 筛选；点「目标」→ `POST /api/target` → 跳回总览回填
- **配置**：信道显示/选择、重启、恢复出厂；修改后需重启生效
- 抽屉内 Evil Twin / Karma / Deauth 等条目为禁用占位（点按提示合规未启用）
- 轮询：`/api/info` 2s、`/api/log?since=` 1.5s（增量刷新日志与内存/运行时间）

## 5. 后端 API

| 接口 | 说明 |
|---|---|
| `GET /api/firmware/manifest` | 芯片 → { version, md5, size, chipMagic } |
| `GET /api/firmware/bin/:chip` | 下载对应合并镜像 |
| `POST /api/codes/verify` | 校验一次性码 → `{ nonce }`（15 分钟有效） |
| `POST /api/codes/redeem` | nonce+chip+md5 匹配才核销，失败不扣 |
| `POST /api/admin/codes` | header `x-admin-token` 鉴权，批量生成 N 个码 |
| `GET /api/admin/codes` | 码列表与状态（未用/verified/redeemed） |
| `POST /api/admin/firmware/:chip` | 注册/替换某芯片镜像（本地 tools 脚本用） |

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

1. `node server/src/index.js` 起服务，`tools/gen-code.sh 3` 生成 3 个码 ✓
2. 无板子：verify 通过 → 烧录失败/取消 → DB 状态仍 `未用` ✓
3. 真机烧录：烧录完成 → 控制台启动日志 → 记录 `redeemed` + flash_log ⬜（待真机）
4. 手机连 `WiFi-xxxx` / `00000000` → Captive Portal 自动弹窗或手动
   `http://192.168.4.1/admin.html` 显示后台三页 + 版本 ⬜（待真机）
5. 二次烧用已核销的码 → verify 拒绝 ✓
6. 可编 6 颗芯片镜像全部产出并出现在 manifest ✓
   （esp32/s2/s3/c3/c5/c6 各 4MB 合并镜像；c5 为本地注入 libs 编出，实验性）
7. 代码审查修复回归（2026-11-09 二）✓：
   - 6 镜像 bootloader 落在其 ROM 规定偏移（0x1000 / 0x2000 / 0x0），该处 `0xE9` ✓
   - 后端按芯片偏移校验魔数：3 种偏移注册放行、坏镜像 400 拦截 ✓
   - verify 限流（第 11 次起 429）、nonce 过期清理、token 不打印 ✓
   - 烧录台 `consoleHint` 元素存在/零 JS 报错、静态托管脱离 cwd ✓
   - Captive Portal：6 env 全部编译 SUCCESS（DNSServer 引入无回归）✓

## 9. 后续阶段（非本期）

- 主动攻击类模块（Deauth 测试 / Evil Twin 等）—— **法律风险高，不开发**
- Evil Portal（当前不开发；钓鱼导向页面同样有合规风险，需评估后再定）
- 云部署（HTTPS 域名 + CDN 托管静态烧录台）
- 图文教程静态页（tw.html / az.html 等）
- ESP32-C5 真机验证（镜像已产出；espressif32 v8 无官方 c5-libs，
  由 tools/install-c5-libs.sh 本地注入编译，板级参数待真机复核）
- Web 发码管理页（当前仅 `tools/gen-code.sh` CLI 发码 + `POST /api/admin/codes`）
- CDN 本地化：`flasher/vendor/` 沉淀 esptool-js / crypto-js，支持断网/内网烧录
  （2026-11-09 审查建议，评估后暂缓；当前仍走 unpkg CDN）
- 异步 WiFi 扫描：把同步 `scanNetworks` 改为异步启动 + 轮询，
  避免 C5 双频扫描长时间阻塞触发 TWDT（评估后暂缓，需前端轮询配合）
- 串口探针免码升级：与一次性烧录码核销闭环冲突，**不采纳**
