# ESP32-C5 五功能真机验收报告

> 日期：2026-11-13 · 固件 v1.1.0 (esp32c5_16mb, ota_0)
> 设备：ESP32-C5N16R8，MAC `14:C1:9F:8A:12:F9`，COM3 (USB CDC)
> 验收方式：`tools\verify-*.py` 脚本化真机流程 + 合成目标（全程不碰真实网络）

---

## 结论总览

| 功能 | 结果 | 说明 |
|------|------|------|
| BLE 扫描 | ✓ 有效 | 扫描启动/停止/设备计数正常 |
| 802.15.4 嗅探 | ✓ 有效（带服务窗口制） | 单射频共存问题已定位并修复 |
| Karma 探针捕获 | ✓ 有效 | 45s 捕获 26 个真实探针（含邻居 SSID） |
| Deauth 远程压制 | ✗ 平台受限（诚实降级） | C5 WiFi 库白名单拒绝，见下 |
| 邪恶双子 | ✓ 核心链路有效 | 克隆热点+凭据捕获+自动收尾+恢复 |

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

## 相关提交（均已提交未推送）

- d7a6eb7 / 2861265 扫描频段过滤
- 18dd6f3 / 2aa34cf / 8476894 / 5d05eef 真机验证与窗口制
- 15b4d0f 分区表新增 coredump 分区
- 067cabf i154 服务窗口共存修复
- d1c5994 Deauth 平台限制探测与诚实降级
- 3fb604b Deauth 引擎 258 后停止重试
- 71b7df3 HWCDC 背压防护
- 4a5f56e 验收脚本集 + coredump 取证工具
