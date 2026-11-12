# 设备识别与指纹（P4）改造清单

日期：2026-11-12
状态：**P4-0 ~ P4-3 已实现（待真机验证）**；不阻塞 v1.1.0 首刷与 16MB 三系统部署
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

| 项 | 现状（P4-3 后） | 证据 |
|---|---|---|
| BLE 设备表 | 24 条，字段含 MAC / 名称 / `mfg[8]` / `companyId` / `svcUuid` / `svcData[8]` / `devClass` / `randomMac` / `rid*` | `main.cpp` `BleDeviceEntry`、`BleAdvSample`、`onResult` |
| BLE 广播回调 | 取 `getManufacturerData()` + `getServiceUUID()` + `getServiceData()/getServiceDataUUID()`，并把完整 Service Data 送 Remote ID 解析 | `main.cpp` `onResult` |
| BLE API | `/api/ble/status|devices` 新增 `companyId` / `svcUuid` / `svcData` / `devClass` / `randomMac` / `rid`，旧字段保留 | `bleAppendDeviceJson()` |
| BLE 页 | 8 列（MAC/名称/RSSI/类型/厂商·类型/厂商数据/广播数/最后出现），次行补 UAS ID / 坐标 | `admin.html` `blePaintRows`、`bleVendorCell` |
| 厂商表 | `vendor_db.js`：OUI 512 + Company 256 + Service 84；`GET /vendor-db.js` 压缩直出；扫描/Airodump/Sniffer 共用 | `tools/gen-vendor-tables.mjs`、`vendor_db.h` |
| WiFi 扫描 | 输出 ssid/rssi/channel/bssid/auth，BSSID 次行显示 OUI 厂商名（随机 MAC 如实标注） | `main.cpp` `handleScan`、`admin.html` `vendorSub` |
| Sniffer | 解析 SSID / Reason，并遍历厂商 IE 解析 Remote ID；src/dst 悬停显示厂商名 | `main.cpp` `snifferObserve`、`ieFindVendor`、`ridFromWifiFrame` |
| Remote ID | `/api/rid` 最多 8 条 / 2 分钟 TTL；Basic ID + Location + System；BLE 与 WiFi 按 MAC 归并 | `main.cpp` `handleRid`、`admin.html` `paintRidCard` |
| 4MB 版体积 | `esp32c5`：**1,910,147 / 1,966,080 = 97.2%**，剩余 **55,933 B**（P4-2/P4-3 增量 5,968 B） | `pio run -e esp32c5` |
| 16MB 版体积 | `esp32c5_16mb`：1,910,147 / 4,128,768 = 46.3% | `pio run -e esp32c5_16mb` |
| 静态 RAM | 77,896 / 524,288 = 14.9% | 同上 |
| 后台资源 | `admin.html` 134,833 B → deflate **37,134 B**；`vendor_db.js` 25,299 B → **8,721 B** | `embed_admin_page.py`、`pio run` |
| 测试基线 | `npm test` **52/52** | `server/test/index.test.js` |

> **硬约束**：P4 的所有新增内容（固件代码 + 内嵌前端资源）必须控制在
> **≤ 20KB Flash**（P4-1 实测 13.6KB；P4-1 后 4MB 版余量 61.9KB），并在每次提交前实测
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

- [x] **数据来源固定**（全部可独立获取，不抄 ESPsoup）：
      - IEEE OUI / MA-L / MA-M / MA-S 公开注册表（厂商名，事实性数据）；
      - Bluetooth SIG Assigned Numbers（Company ID、16-bit Service UUID）；
      - ASTM F3411-22a / OpenDroneID（Apache-2.0）消息格式与测试向量（P4-3 使用）。
- [x] **生成脚本** `tools/gen-vendor-tables.mjs`：读取本地缓存的三份源文件，
      输出 `firmware/data/vendor_db.js`（带来源 / `generatedAt` / 条目数头注释），
      支持 `--check`（校验已提交文件与源一致）与 `--fetch`（按需下载源文件）。
- [x] **许可与署名**：`vendor_db.js` 头部注明数据来源；仓库根目录新增
      `THIRD_PARTY.md`（只记数据来源，不引入代码）。
- [x] **测试向量**：`server/test/fixtures/p4-ble-adv.json`（10 条 BLE 分类向量）；
      `server/test/fixtures/p4-odid.json`（9 条 Remote ID 向量：BLE 单消息 / Message Pack /
      WiFi Beacon / 截断 / 错误 OUI / 特殊字符）。

### P4-1：BLE 字段扩展与设备画像（1.5 天）

**字段扩展**（`main.cpp` `BleDeviceEntry`；P4-1 实测 RAM +768 B）：

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
| 随机 MAC | MAC 首字节 `& 0x02`（独立布尔 `randomMac`，不占用 `devClass`，不参与 OUI 查询） |

> `ridFlags` / `ridUasId` / `ridLat` / `ridLon` / `ridAlt` 在 P4-1 预留，P4-3 补齐解析，
> 并由 `ridFlags` 决定字段是否有效（未命中时 `rid: null`）。

- [x] **取数**：`onResult` 增加 `getServiceUUID()/getServiceUUIDCount()`、
      `getServiceData()/getServiceDataUUID()`，只把定长前缀拷到栈上再进临界区；
      `getPayload()`（原始 AD 负载）可作为后续扩展入口，P4 暂不用；
- [x] **归属合并**：同一 MAC 后续广播只补空字段，不覆盖已识别类别；
- [x] **API（只增不改）**：`/api/ble/status|devices` 每条新增
      `companyId`、`svcUuid`、`svcData`（hex）、`devClass`、`randomMac`、`rid`（对象，未命中为 `null`）；
- [x] **UI**：BLE 页列扩为 8 列（增加「厂商 / 类型」），`devClass` 用状态胶囊显示；
      「导出 JSON」保持全字段；
- [x] **门控**：全部包在 `#if FW_BLE_SUPPORTED` 内，经典 ESP32（`-DFW_BLE_DISABLED`）
      与 S2 行为不变。

**已实现落点**：`firmware/src/main.cpp`（`BleDeviceEntry` / `BleAdvSample` / `bleClassify` /
`bleAppendDeviceJson`）、`firmware/data/admin.html`（`bleVendorCell`）、
`firmware/data/vendor_db.js`、`tools/gen-vendor-tables.mjs`、`server/test/fixtures/p4-ble-adv.json`。
**验收状态**：构建与契约测试已通过（C5 97.2%、S3 80.3%、经典 ESP32 66.9%）；真机分类效果待 C5 实板确认。

**验收**：手机开 AirDrop/Find My 时 10s 内出现 AirTag/Find My 标签；iBeacon 信标显示
iBeacon；未知设备显示「未知」；导出 JSON 字段完整。

### P4-2：OUI 厂商名（0.5–1 天）

**体积预算（硬约束：4MB 版 P4-1 后仅剩 61.9KB）**

| 方案 | 条目 | 原始 | deflate 后 | 存放 | 结论 |
|---|---|---|---|---|---|
| Top-200 | 200 | ≈6KB | ≈2KB | `vendor_db.js` | 最低配置 |
| **Top-512** | 512 | ≈15.7KB | ≈5.8KB | `vendor_db.js` | **P4 默认（实测）** |
| Top-1024 | 1024 | ≈31KB | ≈11KB | `vendor_db.js` | 上限，不建议再涨 |
| 全量 IEEE（≈38k） | 38k | ≈1.2MB | ≈430KB | 独立资源 / SPIFFS | ❌ 4MB 不可行；16MB 仅作可选观察项 |

> **实测（P4-1）**：`vendor_db.js` = OUI 512（15,701 B）+ Company 256（6,724 B）+
> Service 84（2,220 B），文件 25,299 B → deflate **8,721 B**。

- [x] **独立资源**：表不写进 `admin.html`（避免每次改表都动 SPA），新增
      `firmware/data/vendor_db.js`，由 `embed_admin_page.py` 扩展为压缩内嵌
      `src/vendor_db.h`，路由 `GET /vendor-db.js`（`Content-Encoding: deflate`、
      `Cache-Control: max-age=86400`）；P4-1 已提前落地，供 BLE 页使用；
- [x] **查询接口**：`vendorName(mac)` 取前 3 字节；首字节 `& 0x02` 直接返回「随机 MAC」；
      未命中返回空（UI 显示「未知厂商」）；实现在 `admin.html`（`vendor_db.js` 已在浏览器侧，
      固件不再重复实现一份查表逻辑，省 Flash）；
- [x] **UI 落点**：扫描页 BSSID 列、Airodump 对端表（AP + Station）次行显示厂商名；
      Sniffer 的 src/dst 用 `title` 悬浮提示，不新增列；
- [x] **注意**：现代手机普遍使用随机 MAC，OUI 对「手机」几乎无效，UI 必须如实标注，
      不要把它当设备身份（扫描 / Airodump / BLE 页均已加提示）。

**预算合计（实测）**：`vendor_db.js` 原始 25,299 B / deflate 8,721 B；P4-1 固件与
前端增量 13,616 B（含压缩后的 vendor_db.h）；4MB C5 剩余 61,901 B。

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

- [x] **BLE 侧**：在 `onResult` 内识别 `0xFFFA` 服务数据，**从完整 Service Data**
      解析 ODID 消息包（读取前先校验长度），结果写入 `BleDeviceEntry.rid*`；
      `svcData[8]` 只用于分类与展示，不承担完整解析；解析失败不改类别、不 crash；
- [x] **WiFi 侧**：新增 `ieFindVendor(f,len,off,oui,ouiType,out,outLen)`；
      `onPromiscuousFrame` 对 Beacon/ProbeResp 解析一次，结果进 `sRid`（**8 条**环形，
      2 分钟 TTL）；`info[48]` 只放 `RemoteID: <UAS ID>` 摘要；
- [x] **API**：新增 `GET /api/rid`（数组，最多 8 条），字段与 BLE 侧一致（`ridAppendFields`
      共用同一份 JSON 片段）；遥测不新增事件类型（沿用 `lab_state`）；
- [x] **UI**：BLE 页在厂商/类型胶囊下显示 UAS ID 与坐标；Sniffer 页新增
      「Remote ID」卡片（UAS ID / 机型 / 经纬度 / 操作员位置 / 来源 / RSSI / 最后出现），
      坐标只做文本展示与点击复制，**不加载在线地图**（AP 模式通常无外网）；
- [x] **安全**：所有长度按 IE/AD 实际长度校验；不因畸形包扩大 `info` 或越界读；
      UAS ID 中不可打印字符与 `"` / `\` 在解析时即替换为 `.`，可直接拼入 JSON。

**实测**：`p4-odid.json` 9 条向量（BLE 单消息 / BLE Message Pack / WiFi Beacon 厂商 IE /
(0,0) 坐标 / 截断包 / 短包 / 错误 OUI / 错误 OUI Type / UAS ID 特殊字符）；`npm test` 52/52。

**验收**：用 OpenDroneID 官方/开源测试向量回放，Basic ID 与 Location 字段与向量一致；
截断包返回未识别；真机上如周边有 Remote ID 无人机，10s 内出现条目（无则如实为空）。

### P4-4：验证与文档（0.5–1 天）

- [x] `pio run -e esp32c5`：Flash **97.2%**（1,910,147 / 1,966,080，P4-2/P4-3 合计新增 5,968 B，
      P4 全增量 19,584 B ≤ 20KB，余量 55,933 B）；RAM 14.9%；
      `esp32c5_16mb` 正常产出（46.3%）；`esp32`（BLE 裁剪）66.9%、`esp32s3`（NimBLE）80.3%；
- [x] `npm test`：52/52 全绿；`admin_page.h` / `vendor_db.h` 与源文件逐字节一致；
- [ ] 真机（C5）：BLE 分类、OUI、Remote ID 三项分别验收；AP/5G/三系统切换不回归；
- [x] 文档：`README` 功能表补「设备识别」，新增 `THIRD_PARTY.md`，更新本文件的状态与落点表。

## 5. 关键设计决策

1. **分类在固件，文案在 UI**：`devClass` 由固件判定（纯整数、无堆分配、可被契约测试
   用向量覆盖）；厂商名/类别中文名放 `vendor_db.js`，改文案不需要动 C++。
2. **表不进 `admin.html`**：独立 `vendor_db.js` 压缩内嵌，避免 SPA 每次改表产生大 diff，
   也便于单独做体积断言。
3. **JSON 只增字段**：`/api/ble/*` 现有消费方（页面「导出 JSON」）不需改动；
   Remote ID 单独走 `/api/rid`，不挤占 `info[48]`。
4. **不追全量 OUI**：4MB 版 P4-1 后只剩 61.9KB，全量表的投入产出比极低；Top-512 覆盖常见
   AP/路由/芯片厂商即可，随机 MAC 明确标注。
5. **不碰射频**：P4 全部是「已收到数据的解析与展示」，不新增任何发送/注入调用，
   保持 P2/P3 的纯被动边界。

## 6. 体积 / 内存预算

| 项 | 预算 / 实测 | 依据 |
|---|---|---|
| `vendor_db.js` 原始 | **25,299 B** | OUI 512 + Company 256 + Service 84 |
| `vendor_db.js` 压缩 | **8,721 B** | Python zlib level 9 |
| `admin.html` 压缩 | **35,657 B**（原 34,923，+734 B） | P4-1 新增厂商/类型列 |
| 固件代码（解析/分类/JSON） | **≈4,161 B** | 总增量 13,616 − 表 8,721 − 页面 734 |
| 静态 RAM | **768 B**（76,072 → 76,840） | BLE 条目扩展 + `rid*` 预留 |
| 4MB 版总量 | **13,616 B**（余量 61,901 B） | `pio run -e esp32c5` |
| 单次 API 响应 | +≈2KB | 24 条 BLE × 新增字段 |

## 7. 契约测试点

新增到 `server/test/index.test.js`（沿用现有「源码契约 + 向量」模式）：

1. ✅ **BLE 字段契约**：`main.cpp` 含 `companyId` / `svcUuid` / `svcData` / `devClass` / `ridUasId`；
   `handleBleStatus/Devices` 输出对应键；旧键（`mfgHex` / `advType` / `advCount`）仍在。
2. ✅ **BLE 分类向量**：`p4-ble-adv.json` 10 条（AirTag、iBeacon、Eddystone、BTHome、
   小米、Govee、Ruuvi、Fast Pair、Remote ID、未知）→ 期望 `devClass` 与固件判定一致（Node 镜像表）。
3. ✅ **纯被动不回归**：`setActiveScan(false)` 仍存在；不得新增 `esp_ble_gap_start_advertising`
   等发送调用；`esp_wifi_80211_tx` 调用点固定为 3 处（双子/Deauth）。
4. ✅ **OUI 表契约**：`vendor_db.js` 条目 200–800；键格式 `^[0-9A-F]{6}$`；
   文件 ≤ 32KB；Company/Service 关键条目存在。（`vendorName(mac)` 属 P4-2，待补）
5. ⏳ **Remote ID 向量**：`p4-odid.json` 的正常消息包 → 期望 UAS ID/UA 类型/经纬度；
   截断 1 字节 → 返回未识别（不得抛错/越界）。P4-3 落地。
6. ⏳ **Remote ID 载体验证**：WiFi Beacon 测试帧（OUI `FA-0B-BC` + type `0x0D`）可解析；
   错误 OUI / 错误 type / 长度溢出 → 忽略。P4-3 落地。
7. ✅ **资源同步**：`vendor_db.h` 解压后与 `vendor_db.js` 逐字节一致；
   `admin_page.h` 同步用例继续通过。
8. ✅ **UI 契约**：BLE 表头 `<th>` 数与空态 `colspan` 一致；`bleVendorCell` 引用
   Company / classes；页面不引入公网 URL。
9. ✅ **体积契约**：`admin.html` ≤ 140KB、`vendor_db.js` ≤ 32KB；
   （可选）`tools/check-flash-budget.mjs` 留待 CI 化。

## 8. 排期建议

| 顺序 | 内容 | 依赖 | 预估 | 状态 |
|---|---|---|---|---|
| 0 | P4-0 数据源、生成脚本、测试向量 | 无 | 0.5 天 | ✅ 已完成 |
| 1 | P4-1 BLE 字段扩展 + 分类 + UI | P4-0 | 1.5 天（第一批提交） | ✅ 已完成（待真机） |
| 2 | P4-2 OUI 表 + 独立资源路由 | P4-0 | 0.5–1 天 | 🟡 资源/路由已完成，WiFi 页待接 |
| 3 | P4-3a Remote ID（BLE） | P4-1 | 1–1.5 天 | ⏳ |
| 4 | P4-3b Remote ID（WiFi Beacon + `/api/rid`） | P4-3a | 1–1.5 天 | ⏳ |
| 5 | P4-4 体积实测、真机验收、文档 | 全部 | 0.5–1 天 | 🟡 构建/测试/文档已完成，真机待验 |

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
