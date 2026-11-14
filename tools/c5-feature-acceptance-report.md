# ESP32-C5 五功能真机验收报告

> 日期：2026-11-13 · 固件 v1.1.0 (esp32c5_16mb, ota_0)
> 设备：ESP32-C5N16R8，MAC `14:C1:9F:8A:12:F9`，COM3 (USB CDC)
> 验收方式：`tools\verify-*.py` 脚本化真机流程 + 合成目标（全程不碰真实网络）

> ⚠️ **重要后续更新（2026-11-13 当日晚些时候）**：本文 §1 记录的「Deauth 平台受限」
> 结论**已被后续提交推翻**，仅作为当时的实验记录保留。现已通过覆盖
> `ieee80211_raw_frame_sanity_check`（链接加 `-Wl,--allow-multiple-definition`）解除
> C5 帧类型白名单，并改用「从空口学习客户端 MAC → 单播定向 Deauth」把真实 Wi-Fi 6
> 客户端踢下线；同日补齐 5G 克隆 AP 与双频跳频压制，均已在真机复测通过。
> **以 §5 为准**；§1 的「诚实降级」分支现仅作为白名单确被解除前的兜底路径。

---

## 结论总览

| 功能 | 结果 | 说明 |
|------|------|------|
| BLE 扫描 | ✓ 有效 | 扫描启动/停止/设备计数正常 |
| 802.15.4 嗅探 | ✓ 有效（带服务窗口制） | 单射频共存问题已定位并修复 |
| Karma 探针捕获 | ✓ 有效 | 45s 捕获 26 个真实探针（含邻居 SSID） |
| Deauth 远程压制 | ✓ 有效（当日后续修复，见 §5） | 初测平台受限（§1 保留）；白名单已解除 + 单播定向踢线，真机把 5G/2.4G 客户端踢下线 |
| 邪恶双子 | ✓ 核心链路有效 | 克隆热点+凭据捕获+自动收尾+恢复；5G 克隆与双频跳频真机复测通过（§5） |

---

## 1. Deauth：平台限制真相（真机实验矩阵）

- `esp_wifi_80211_tx` 在 ESP32-C5 WiFi 库存在**帧类型白名单**：
  信标 / Probe / Action / 非 QoS 数据可发；**Deauth / Disassoc 返回错误码 258**。
- 排除的假设（均有真机实验数据）：promiscuous 开启状态、先成功发送白名单帧、
  加长帧（64B vendor IE 填充）、接口选择（AP/STA）、en_sys_seq、
  精确复刻唯一一次成功的前置序列、20 连发爆发（0/20 成功）。
- 唯一一次 `esp_wifi_80211_tx` Deauth 成功为**非确定性假象，不可复现**。
- **真实可用替代**：`esp_wifi_deauth_sta(0)` 真机验证可断开本机 AP 关联客户端
  （`AP_STA_DISCONNECTED` 事件，Windows 端被踢 <1ms 后可立即重连，无需复位）。
- 固件侧处理：启动时单帧试探 → 被拒则停引擎并返回 `platformBlocked:true`，
  不空转；引擎循环自检测 258 后调用 `stopDeauthEngine()` 收尾（消除驱动
  `unsupport frame type: 0c0` 刷屏，12s 观察窗口 0 条）。

## 2. 邪恶双子（全链路真机验收通过）

流程：设置合成目标 → 启动攻击 → 软 AP 改名（克隆 SSID + 开放认证 + 目标信道）
→ 受害者（Windows PC）连接克隆热点 → 门户提交伪凭据 `FakePass123!` →
凭据捕获（明文仅入凭据表，不写入日志）→ 自动收尾 `caught:true`（克隆热点保留）
→ 手动 stop → 恢复原热点 → PC 回连成功（约 4s）。

- Deauth 压制组件因平台限制自动跳过（`sDeauth.running = frameReady && !platformBlocked`）。
- 克隆热点连接的关键坑：**netsh WLAN profile 命名空间必须是
  `http://www.microsoft.com/networking/WLAN/profile/v1`**——写成
  `WLANProfile/v1` 会报 `0x80002 缺少 WLAN 配置文件元素`（曾导致历次连接失败）。

## 3. 802.15.4 共存（服务窗口制，真机验证）

- 根因：C5 单射频，`esp_ieee802154` 启用后 WiFi AP **只发不收**；
  `esp_ieee802154_disable` 无法恢复，唯 `esp_wifi stop/start` 重建。
- 机制：嗅探 60s → 停嗅探+重启射频 → 动态服务窗口（客户端回连保持 5s 等 DHCP，
  无人 45s 超时）→ 自动恢复嗅探（统计保留）；无条件周期执行。
- 扫描掉线：频段过滤修复已验证（提交 d7a6eb7 / 2861265）。

## 4. 事故记录：TWDT panic（已修复）

两次 loopTask panic 重启，coredump（0xFF0000）取证 + addr2line 定位：

- 链路：`handlePortalSubmit/sendPortalPage → log → emitJson → Serial.println
  → HWCDC::write`（卡在 tx_lock / TX 环形缓冲）。
- 根因：USB CDC 主机端口打开但不读取（背压）或刚关闭的标志翻转窗口内，
  `HWCDC::write` 每行最多阻塞 ~2s（20×100ms 封顶）；软 AP 重启/双子收尾的
  WiFi 事件风暴下，单次 `handleClient` 内多行日志累计 >60s 不喂 TWDT → panic。
- 修复：`serialSafe()` —— `isConnected()` 为假或 TX 环形缓冲空闲量不足时整行
  丢弃串口输出（环形日志/遥测/网页不受影响）。修复后全流程无重启。
- 附带成果：TWDT panic 模式成功救活设备并留存现场；`tools/parse-coredump.py`
  可解析 coredump ELF 并 addr2line 重建任务调用链。

---

## 5. 后续真机复测（2026-11-13）：真实 802.11 压制生效

本节记录 §1「平台受限」结论被推翻后的真机结果，提交 `14a8dc3` / `cb1cd8b` /
`c806001` / `0aeb60b` / `f466a6b` / `ff62eda`（均已 push 到 `origin/main`）。

### 5.1 两个叠加根因（手机此前「没被挤掉」）

1. **广播 Deauth 被丢弃**：`DA=FF:FF:FF:FF:FF:FF` 的解除认证帧在 Wi-Fi 6 手机/网卡
   上被驱动层静默丢弃 —— 帧计数一直涨、设备毫无反应。
2. **攻击频段与目标不符**：目标 `WiFi6` 是双频同名（2.4G ch11 = `…DD:71`、
   5G ch149 = `…DD:72`，均 WPA2 / 802.11ax），手机与 Windows AX210 默认优先 5G；
   而 `softAP(ch149)` 返回 true 却驻留在 2.4G（band mode 未切），攻击全发在错误频段。

### 5.2 修复链路（均为真实空口帧，经 `esp_wifi_80211_tx`）

- **解除白名单**（`227d545`）：`extern "C" int ieee80211_raw_frame_sanity_check(...) { return 0; }`
  覆盖 `libnet80211.a` 的强符号，链接加 `-Wl,--allow-multiple-definition`；
  C5 的 Deauth/Disassoc 不再返回 258。
- **单播定向踢线**（`cb1cd8b`）：Deauth 运行期开 promiscuous，从 ToDS/FromDS 数据帧
  学习该 AP 下客户端 MAC（最多 12 个，`learnClientMac`），发送单播 Deauth
  （DA=客户端 / TA=BSSID=目标 AP），原因码 1/3/7/15 轮换，每 4 帧留 1 帧广播兜底。
- **信标走 STA 接口**（`wifiBeaconTx`）：AP 接口注入的 Beacon 空口不可见，改由
  `WIFI_IF_STA` 发出（真机 4 次扫描 4 次命中）。
- **5G 克隆 / 频段顺序**（`14a8dc3` / `f466a6b`）：5G 目标先
  `esp_wifi_set_band_mode(WIFI_BAND_MODE_5G_ONLY)` 再起 AP，且顺序为「先切频段、再设
  HT20 带宽」（AUTO 下 `set_bandwidth` 会报错），启动后用 `esp_wifi_get_channel` 校验
  真实驻留信道。
- **promiscuous 时序**（`c806001` / `0aeb60b`）：直接进阶段 2 时
  `syncPromiscuousEngine()` 恢复被 `softAP` 重配清掉的混杂态；探测 Deauth 前先开
  promiscuous，避免误判「平台阻断」走 CSA。新增 `prom / rxFrames / rxData / rxMatch`
  诊断计数，用于区分「收不到帧」与「收到但没有目标 BSSID 的数据帧」。

### 5.3 量化结果（`/api/info` 实测）

| 目标 | 学到客户端 | 单播帧 | 真实 AP 在线设备变化 |
|---|---|---|---|
| 5G ch149 `…DD:72` | 5 台 | 1111+ 帧（count 1481，rxMatch 2865） | 6 → **2** |
| 2.4G ch11 `…DD:71` | 2 台 | 持续单播（每 8s +60 帧） | 1~3 → **0**（被踢光） |

克隆热点 `14:c1:9f:8a:12:f9` 同期只有 1 台（本机），说明其它设备确被踢下线。

### 5.4 双频同名一次覆盖（主 5G + 双子 2.4G）

把 2.4G `…DD:71`（ch11）加进「双子目标」后，主目标仍为 5G `…DD:72`（ch149）：
单射频靠 `TWIN_HOP_INTERVAL_MS=2000` 每 2s 跳到双子信道发一轮 Deauth 再跳回主信道。
真机现象：克隆 `WiFi6`（开放）在 **5G ch149** 与 **2.4G ch11** 交替出现；手机连
`WiFi6` 持续抖动 / 被踢；两个真实 BSSID 的在线设备数同时被打下来。

> 副作用（非崩溃）：克隆阶段管理热点 `WiFi-12F9` 会消失（软 AP 已改名为目标
> SSID）；原生 USB CDC（COM3）在射频反复重启后可能不再枚举，但 CH340 UART
> （COM5）始终可用，可抓日志 / 复位（`DTR=1`→200ms→`DTR=0` 正常启动）。
> 复位后攻击停止、热点恢复 `WiFi-12F9` / `00000000` / 口令 `admin888`。

### 5.5 烧录坑（同日修复，`ff62eda`）

`pio run -e esp32c5_16mb -t upload` 把 bootloader 写到 `0x0`（C5 应在 `0x2000`），
导致 `invalid header: 0xa8030007` 无限复位。已用 `post` 脚本
`firmware/tools/fix_c5_bootloader_offset.py` 修正 esptool 命令行偏移，实烧验证启动
日志 `invalid header`=0、正常打印 `v1.1.0` 横幅。详见 `docs/firmware-flashing.md` §5.7。

### 5.6 结论

**C5 的 5G 克隆 AP、真实 802.11 Deauth、5G 目标取消认证、双频跳频压制全链路真机通过**；
§1 的「平台受限 / 诚实降级」仅代表修复前的实验快照，兜底分支（CSA / 停用引擎）保留
应对个别平台仍拒绝 raw TX 的情况，不再是 C5 的常态。

---

## 相关提交

- d7a6eb7 / 2861265 扫描频段过滤
- 18dd6f3 / 2aa34cf / 8476894 / 5d05eef 真机验证与窗口制
- 15b4d0f 分区表新增 coredump 分区
- 067cabf i154 服务窗口共存修复
- 227d545 覆盖 `ieee80211_raw_frame_sanity_check` 解除 C5 帧类型白名单
- d1c5994 / 3fb604b Deauth 平台限制探测与诚实降级（修复前兜底，见 §1）
- 71b7df3 HWCDC 背压防护
- 4a5f56e 验收脚本集 + coredump 取证工具
- 14a8dc3 / cb1cd8b / c806001 / 0aeb60b / f466a6b / ff62eda 5G 克隆 / 单播定向
  Deauth / promiscuous 时序 / 频段带宽顺序 / bootloader 偏移（见 §5，均已 push）
