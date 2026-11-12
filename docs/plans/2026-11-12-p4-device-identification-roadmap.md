# 设备识别与指纹（P4）改造清单

日期：2026-11-12
状态：**规划中**，P4-0/P4-1 为第一批；不阻塞 v1.1.0 首刷与 16MB 三系统部署
关联：[C5 5GHz / BLE / 802.15.4 roadmap](./2026-11-11-c5-5ghz-ble-802154-roadmap.md)、
[平台设计文档 §4 能力矩阵](./2026-11-09-esp32-firmware-platform-design.md)、
[刷固件说明 §6 三系统](../firmware-flashing.md#6-附16mb-flash-三系统-triple-boot-部署说明)

## 1. 结论与边界

P2/P3 已把「能看到什么」补齐（BLE 广播、802.15.4 帧、5G 抓包），但后台仍然只会显示
`mfgHex` 原始字节和 MAC，用户看不出「这是什么设备」。P4 的目标是把**已收到的广播/帧**
翻译成可读的设备画像：

- **做**：BLE 厂商/服务 UUID 名称、AirTag / iBeacon / Eddystone / BTHome 等类别标签、
  WiFi OUI 厂商名、ASTM F3411 Remote ID（BLE + WiFi Beacon）解析；
- **不做**：ELRS、DJI DroneID（OcuSync）、HDZero 等 **非 802.11 私有波形** —— 它们需要
  IQ/SDR 接收链路，不是前端识别逻辑能补的（见 §9）；
- **不复用 ESPsoup 代码**：其 App/前端**尚未选择许可证**（默认保留所有权利），
  `espsoup-firmware` 为 **GPL-3.0-or-later**。本仓库当前无 LICENSE，引入会改变整个固件的
  分发条件。P4 只使用**公开数据与公开规范**自行实现（见 §4 P4-0）。

## 2. 现状核对（代码事实）

| 项 | 现状 | 证据 |
|---|---|---|
| BLE 设备表 | 24 条，字段仅 MAC / 名称 / `mfgHex`(前 8 字节) / RSSI / 广播类型 / 计数 | `main.cpp:699` `BleDeviceEntry`、`:787` `onResult` |
| BLE 广播回调 | 只取 `getManufacturerData()`，未取 Service UUID / Service Data | `main.cpp:793-800` |
| BLE API | `GET /api/ble/status`、`GET /api/ble/devices` 输出 `mfgHex` 等 | `main.cpp:2677`、`:2747` |
| BLE 页 | 7 列（MAC/名称/RSSI/类型/厂商数据摘要/广播数/最后出现） | `admin.html:1114`、`:1034` `blePaintRows` |
| WiFi 扫描 | 输出 ssid/rssi/channel/bssid/auth，**无厂商名** | `main.cpp:1969-1999` |
| Sniffer | 只解析 SSID / Reason，无 Vendor IE 遍历 | `main.cpp:1285` `snifferObserve`、`:1269` `ieFindSsid` |
| IE 工具 | 只有 `ieFindSsid()`（id=0），可扩展为通用 IE/Vendor IE 查找 | `main.cpp:1269` |
| 4MB 版体积 | `esp32c5`：**1,890,563 / 1,966,080 = 96.2%**，仅剩 **75,517 B** | `pio run -e esp32c5` |
| 16MB 版体积 | `esp32c5_16mb`：1,890,563 / 4,128,768 = 45.8% | `pio run -e esp32c5_16mb` |
| 静态 RAM | 76,072 / 524,288 = 14.5%，余量充足 | 同上 |
| 后台资源 | `admin.html` 127,010 B → deflate **34,923 B**（27.5%），`send_P` 直出、不占 RAM | `embed_admin_page.py`、`main.cpp:1747` |
| 测试基线 | `npm test` 41/41 | `server/test/index.test.js` |

> **硬约束**：P4 的所有新增内容（固件代码 + 内嵌前端资源）必须控制在
> **≤ 20KB Flash**（4MB 版余量 75.5KB 的安全线），并在每次提交前实测
> `pio run -e esp32c5` 的 Flash 占用。

## 3. 能力矩阵（P4 前后）

| 识别对象 | 现在 | P4 后 |
|---|---|---|
| BLE 厂商 | 仅 8 字节十六进制 | Company ID + 厂商名 + 服务 UUID 名 |
| BLE 设备类别 | 无 | AirTag/Find My、iBeacon、Eddystone、BTHome、小米、Govee、Ruuvi、Fast Pair 等 |
| WiFi AP/STA 厂商 | 无 | OUI 厂商名（Top-512），随机 MAC 显式标注 |
| 无人机 | 无 | ASTM F3411 Remote ID：BLE 广播 + WiFi Beacon |
| ELRS / DJI DroneID | 无 | **仍无**（需 IQ 接收，明确不做） |

## 4. 改造清单

### P4-0：规范与数据准备（0.5 天）

- [ ] **数据来源固定**（全部可独立获取，不抄 ESPsoup）：
      - IEEE OUI / MA-L / MA-M / MA-S 公开注册表（厂商名，事实性数据）；
      - Bluetooth SIG Assigned Numbers（Company ID、16-bit Service UUID）；
      - ASTM F3411-22a / OpenDroneID（Apache-2.0）消息格式与测试向量。
- [ ] **生成脚本** `tools/gen-vendor-tables.mjs`：输入本地缓存的源 CSV/JSON，
      输出 `firmware/data/vendor_db.js`（带 `source` / `generatedAt` / `count` 头注释），
      支持 `--check`（校验已提交文件与源一致，供 CI 用）。
- [ ] **许可与署名**：`vendor_db.js` 头部注明数据来源与 OpenDroneID 归属；
      仓库根目录补 `THIRD_PARTY.md`（只记数据来源，不引入代码）。
- [ ] **测试向量**：`server/test/fixtures/p4-ble-adv.json`、
      `p4-odid.json`（含正常/截断/错误 OUI 三类样本）。

### P4-1：BLE 字段扩展与设备画像（1.5 天）

**字段扩展**（`main.cpp` `BleDeviceEntry`，+48 B/条 × 24 ≈ **1.2KB RAM**）：

| 新字段 | 类型 | 说明 |
|---|---|---|
| `companyId` | `uint16_t` | Manufacturer Data 前 2 字节（小端，`0x004C`=Apple） |
| `svcUuid` | `uint16_t` | 首个 16-bit Service UUID（0 = 无） |
| `svcData` | `uint8_t[8]` | Service Data 前 8 字节（Eddystone/BTHome 前缀、Remote ID 的 App Code） |
| `devClass` | `uint8_t` | 分类枚举（见下表），固件判定，UI 只做展示 |
| `ridFlags` | `uint8_t` | bit0 有 Remote ID、bit1 有位置、bit2 有操作员位置 |
| `ridUasId` | `char[21]` | 20 字节 UAS ID + NUL |
| `ridLat` / `ridLon` | `int32_t` | 1e-7 度；`INT32_MIN` = 无效 |
| `ridAlt` | `int16_t` | 米；`INT16_MIN` = 无效 |

**分类规则**（固件内查表，UI 只映射文案，便于契约测试覆盖）：

| 类别 | 判据 |
|---|---|
| AirTag / Find My | `companyId==0x004C && mfg[2]==0x12 && mfg[3]==0x19` |
| iBeacon | `companyId==0x004C && mfg[2]==0x02 && mfg[3]==0x15` |
| Eddystone | `svcUuid==0xFEAA` |
| BTHome | `svcUuid==0xFCD2` |
| 小米（MiBeacon） | `companyId==0xFE95` 或 `svcUuid==0xFE95` |
| Govee | `companyId==0xEC88` |
| Ruuvi | `companyId==0x0499` |
| Fast Pair | `svcUuid==0xFE2C` |
| Remote ID | `svcUuid==0xFFFA && svcData[0]==0x0D`（详细解析见 P4-3） |
| 随机 MAC | MAC 首字节 `& 0x02`（不参与 OUI 查询） |

- [ ] **取数**：`onResult` 增加 `getServiceUUID()/getServiceUUIDCount()`、
      `getServiceData()/getServiceDataUUID()`，只把定长前缀拷到栈上再进临界区；
      `getPayload()`（原始 AD 负载）可作为后续扩展入口，P4 暂不用；
- [ ] **归属合并**：同一 MAC 后续广播只补空字段，不覆盖已识别类别；
- [ ] **API（只增不改）**：`/api/ble/status|devices` 每条新增
      `companyId`、`svcUuid`、`svcData`（hex）、`devClass`、`rid`（对象，未命中为 `null`）；
- [ ] **UI**：BLE 页列扩为 8 列（增加「厂商 / 类型」），`devClass` 用状态胶囊显示；
      「导出 JSON」保持全字段；
- [ ] **门控**：全部包在 `#if FW_BLE_SUPPORTED` 内，经典 ESP32（`-DFW_BLE_DISABLED`）
      与 S2 行为不变。

**验收**：手机开 AirDrop/Find My 时 10s 内出现 AirTag/Find My 标签；iBeacon 信标显示
iBeacon；未知设备显示「未知」；导出 JSON 字段完整。

### P4-2：OUI 厂商名（0.5–1 天）

**体积预算（硬约束：4MB 版仅剩 75.5KB）**

| 方案 | 条目 | 原始 | deflate 后(≈33%) | 存放 | 结论 |
|---|---|---|---|---|---|
| Top-200 | 200 | ≈4.6KB | ≈1.5KB | `vendor_db.js` | 最低配置 |
| **Top-512** | 512 | ≈12KB | ≈4KB | `vendor_db.js` | **P4 默认** |
| Top-1024 | 1024 | ≈24KB | ≈8KB | `vendor_db.js` | 上限，不建议再涨 |
| 全量 IEEE（≈38k） | 38k | ≈900KB | ≈300KB | 独立资源 / SPIFFS | ❌ 4MB 不可行；16MB 仅作可选观察项 |

- [ ] **独立资源**：表不写进 `admin.html`（避免每次改表都动 SPA），新增
      `firmware/data/vendor_db.js`，由 `embed_admin_page.py` 扩展为压缩内嵌
      `src/vendor_db.h`，路由 `GET /vendor-db.js`（`Content-Encoding: deflate`、
      `Cache-Control: max-age=86400`）；
- [ ] **查询接口**：`vendorName(mac)` 取前 3 字节；首字节 `& 0x02` 直接返回「随机 MAC」；
      未命中返回空（UI 显示「未知厂商」）；
- [ ] **UI 落点**：扫描页 BSSID 列、Airodump 对端表、Sniffer 的 src/dst 悬浮提示；
      默认不新增列，避免移动端表格过宽；
- [ ] **注意**：现代手机普遍使用随机 MAC，OUI 对「手机」几乎无效，UI 必须如实标注，
      不要把它当设备身份。

**预算合计**：`vendor_db.js`（Top-512 OUI + Top-256 Company + Top-128 UUID）≈22KB 原始 /
≈7KB 压缩；P4-1 代码与 JSON ≈6KB；总计 **≤ 15KB**，留出 ≥ 60KB 余量。

### P4-3：ASTM F3411 Remote ID（2–3 天）

**解析范围（明确）**

| 载体 | 做不做 | 依据 / 备注 |
|---|---|---|
| BLE Legacy/Extended 广播 | ✅ | AD type `0x16`，UUID `0xFFFA`，App Code `0x0D`；`getServiceData()` 可取 |
| WiFi Beacon Vendor IE | ✅ | IE `0xDD`，OUI `FA-0B-BC`，OUI Type `0x0D`；扩展 `ieFindSsid` 为通用 IE 遍历 |
| WiFi NAN | ❌ | 需要 NAN 服务发现，P4 不做 |
| DJI DroneID (OcuSync 2/3) | ❌ | 私有 OFDM 波形，非 802.11；需 IQ 接收 |
| ELRS / FLRC / HDZero | ❌ | 私有 LoRa/OFDM 波形；需 IQ 接收 |

**消息类型**：只解析 `0x0` Basic ID、`0x1` Location、`0x4` System、`0xF` Message Pack；
`0x2` Auth / `0x3` Self-ID / `0x5` Operator ID 先跳过（保留原始 hex 供导出）。

**字段**：UA 类型（固定翼/多旋翼/直升机/火箭…）、ID 类型（序列号/CAA/UTM UUID/会话 ID）、
UAS ID（20 字节）、无人机经纬度/高度、操作员经纬度、RSSI、首末次出现时间。

- [ ] **BLE 侧**：在 `onResult` 内识别 `0xFFFA` 服务数据，**从完整 Service Data**
      （栈上定长 64B 缓冲，超长部分丢弃）解析 ODID 消息包，结果写入
      `BleDeviceEntry.rid*`；`svcData[8]` 只用于分类与展示，不承担完整解析；
      解析失败不改类别、不 crash；
- [ ] **WiFi 侧**：新增 `ieFindVendor(f,len,off,oui,ouiType,out,outLen)`；
      `snifferObserve` 对 Beacon/ProbeResp 调用一次，解析结果进 `sRid`（**8 条**环形，
      约 320B RAM）；`info[48]` 只放 `RemoteID: <UAS ID>` 摘要；
- [ ] **API**：新增 `GET /api/rid`（数组，最多 8 条），字段与 BLE 侧一致；
      遥测不新增事件类型（沿用 `lab_state`）；
- [ ] **UI**：BLE 页在名称旁显示「Remote ID」胶囊 + UAS ID；Sniffer 页新增
      「Remote ID」小卡片（UAS ID / 型号 / 经纬度 / 操作员位置 / 最后出现），
      坐标只做文本展示与复制，**不加载在线地图**（AP 模式通常无外网）；
- [ ] **安全**：所有长度按 IE/AD 实际长度校验；先 memcpy 到定长缓冲再解析；
      不因畸形包扩大 `info` 或越界读。

**验收**：用 OpenDroneID 官方/开源测试向量回放，Basic ID 与 Location 字段与向量一致；
截断包返回未识别；真机上如周边有 Remote ID 无人机，10s 内出现条目（无则如实为空）。

### P4-4：验证与文档（0.5–1 天）

- [ ] `pio run -e esp32c5`：Flash **< 99.0%**（基线 96.2%，新增 ≤ 20KB）；
      `pio run -e esp32c5_16mb`：正常产出，合并镜像仍 4MB；
- [ ] `npm test`：41 + 新增用例全绿；`npm run pack-admin` 后
      `admin_page.h` / `vendor_db.h` 与源文件逐字节一致；
- [ ] 真机（C5）：BLE 分类、OUI、Remote ID 三项分别验收；AP/5G/三系统切换不回归；
- [ ] 文档：`README` 功能表补「设备识别」，`docs/firmware-flashing.md` 不涉及刷机流程则不改；
      更新本文件的「状态」与落点表。

## 5. 关键设计决策

1. **分类在固件，文案在 UI**：`devClass` 由固件判定（纯整数、无堆分配、可被契约测试
   用向量覆盖）；厂商名/类别中文名放 `vendor_db.js`，改文案不需要动 C++。
2. **表不进 `admin.html`**：独立 `vendor_db.js` 压缩内嵌，避免 SPA 每次改表产生大 diff，
   也便于单独做体积断言。
3. **JSON 只增字段**：`/api/ble/*` 现有消费方（页面「导出 JSON」）不需改动；
   Remote ID 单独走 `/api/rid`，不挤占 `info[48]`。
4. **不追全量 OUI**：4MB 版只剩 75.5KB，全量表的投入产出比极低；Top-512 覆盖常见
   AP/路由/芯片厂商即可，随机 MAC 明确标注。
5. **不碰射频**：P4 全部是「已收到数据的解析与展示」，不新增任何发送/注入调用，
   保持 P2/P3 的纯被动边界。

## 6. 体积 / 内存预算

| 项 | 预算 | 依据 |
|---|---|---|
| `vendor_db.js` 原始 | ≤ 24KB | Top-512 OUI + Top-256 Company + Top-128 UUID |
| `vendor_db.js` 压缩 | ≤ 8KB | 实测 SPA 压缩比 ≈27.5% |
| 固件代码（解析/分类/JSON） | ≤ 6KB | 纯查表 + 定长解析，无动态分配 |
| 静态 RAM | ≤ 2KB | BLE 条目 +48B×24 + `sRid` 8 条 |
| 4MB 版总量 | ≤ 20KB（占余量 75.5KB 的 26%） | `pio run -e esp32c5` |
| 单次 API 响应 | +≤ 4KB | 24 条 BLE × 新增 ~150B |

## 7. 契约测试点

新增到 `server/test/index.test.js`（沿用现有「源码契约 + 向量」模式）：

1. **BLE 字段契约**：`main.cpp` 含 `companyId` / `svcUuid` / `svcData` / `devClass` / `ridUasId`；
   `handleBleStatus/Devices` 输出对应键；旧键（`mfgHex` / `advType` / `advCount`）仍在。
2. **BLE 分类向量**：`p4-ble-adv.json` 至少 9 条（AirTag、iBeacon、Eddystone、BTHome、
   小米、Govee、Ruuvi、Remote ID、未知）→ 期望 `devClass` 与固件判定一致（Node 镜像表）。
3. **纯被动不回归**：`setActiveScan(false)` 仍存在；不得新增 `esp_ble_gap_start_advertising`
   等发送调用；`esp_wifi_80211_tx` 调用点数量不增加。
4. **OUI 表契约**：`vendor_db.js` 条目 200–800；键格式 `^[0-9A-F]{6}$` 且无重复；
   文件 ≤ 32KB；`vendorName()` 对已知 OUI 返回非空、对随机 MAC 返回「随机 MAC」。
5. **Remote ID 向量**：`p4-odid.json` 的正常消息包 → 期望 UAS ID/UA 类型/经纬度；
   截断 1 字节 → 返回未识别（不得抛错/越界）。
6. **Remote ID 载体验证**：WiFi Beacon 测试帧（OUI `FA-0B-BC` + type `0x0D`）可解析；
   错误 OUI / 错误 type / 长度溢出 → 忽略。
7. **资源同步**：`vendor_db.h` 解压后与 `vendor_db.js` 逐字节一致（仿 `admin_page.h` 用例）；
   `admin_page.h` 同步用例继续通过。
8. **UI 契约**：BLE 表头 `<th>` 数与空态 `colspan` 一致；`blePaintRows` 引用
   `companyName` / `bleClassLabel` / `rid`；页面不引入公网 URL。
9. **体积契约**：`admin.html` ≤ 140KB、`vendor_db.js` ≤ 32KB；
   （可选）`tools/check-flash-budget.mjs` 读取 `.pio/build/*/firmware.bin` 与分区上限，
   在 CI/发布脚本中断言 < 99%。

## 8. 排期建议

| 顺序 | 内容 | 依赖 | 预估 |
|---|---|---|---|
| 0 | P4-0 数据源、生成脚本、测试向量 | 无 | 0.5 天 |
| 1 | P4-1 BLE 字段扩展 + 分类 + UI | P4-0 | 1.5 天（第一批提交） |
| 2 | P4-2 OUI 表 + 独立资源路由 | P4-0 | 0.5–1 天 |
| 3 | P4-3a Remote ID（BLE） | P4-1 | 1–1.5 天 |
| 4 | P4-3b Remote ID（WiFi Beacon + `/api/rid`） | P4-3a | 1–1.5 天 |
| 5 | P4-4 体积实测、真机验收、文档 | 全部 | 0.5–1 天 |

> 每批单独提交并跑全量 `npm test`；**P4-1 与 P4-2 先落地**，即使 Remote ID 延后，
> 设备页也已经有可用增量。

## 9. 明确不做

- **ELRS 识别**：LoRa/FLRC 私有 PHY，802.11 promiscuous 收不到；需 IQ 采样；
- **DJI DroneID / OcuSync 解析**：私有 OFDM 波形，同理；
- **BLE 广播注入 / Wi-Fi 帧注入**：P4 不改变「只收不发」边界；
- **全量 IEEE OUI 表**：4MB 版无空间，16MB 版也无明显收益（随机 MAC 为主）；
- **在线地图 / 云端查询**：AP 模式通常无外网，坐标只做本地展示与复制；
- **复制 ESPsoup 前端或固件代码**：许可证不允许（App 未选许可证、固件 GPL-3.0）。

## 10. 参考

- IEEE OUI / MA-L 公开注册表：<https://standards-oui.ieee.org/oui/oui.csv>
- Bluetooth SIG Assigned Numbers：<https://www.bluetooth.com/specifications/assigned-numbers/>
- ASTM F3411 Remote ID / OpenDroneID（Apache-2.0）：<https://github.com/opendroneid/opendroneid-core-c>
- ESPsoup（仅作能力对照，不引代码）：<https://github.com/pit711/ESPsoup>、
  <https://github.com/pit711/espsoup-firmware>（GPL-3.0-or-later）
- 本仓库：`firmware/src/main.cpp`（BLE/Sniffer/扫描）、`firmware/data/admin.html`（BLE/扫描页）、
  `firmware/tools/embed_admin_page.py`（内嵌压缩）、`server/test/index.test.js`（契约测试）
