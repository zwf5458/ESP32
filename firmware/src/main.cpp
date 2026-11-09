/**
 * ESP32 无线网络开发固件 (V1: AP 热点 + Web 管理后台)
 *
 * 行为:
 *  - 上电串口日志 115200 (烧录台「串口控制台」可见)
 *  - 开热点 SSID = WiFi-<MAC尾4hex>  密码 00000000  (与参考站一致)
 *  - http://192.168.4.1/admin.html  Neo-brutalism 后台 (内嵌页面)
 *  - Captive Portal: UDP 53 通配解析 + OS 探测路径 302, 连热点自动弹后台
 *
 * API:
 *  GET  /api/info    设备信息 (内存诊断/信道/客户端/版本)
 *  GET  /api/scan    周围 AP 扫描 (APSTA 模式)
 *  POST /api/target  设置主目标 (仅记录到 RAM, 回显在仪表板)
 *  GET  /api/log     环形日志 (?since=<id> 增量)
 *  POST /api/reset            重启
 *  POST /api/factory-reset    恢复出厂
 *
 * 合规: 不含/deauth/evil-twin/karma/握手破解等主动攻击功能。
 *
 * 后台页面内嵌自 data/admin.html (raw deflate, 由 tools/embed_admin_page.py 生成 src/admin_page.h)
 */

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>          // Captive Portal: UDP 53 通配解析 → 192.168.4.1
#include <ESPmDNS.h>
#include <nvs_flash.h>
#include "admin_page.h"

#ifndef FW_VERSION
  #define FW_VERSION "1.0.0"
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
static String apSsid;
static uint8_t apChannel = AP_CHANNEL_DEFAULT;

/* ---------------- 日志环形缓冲 (供后台绿字日志) ---------------- */
struct LogEntry {
  uint32_t id;
  char line[160];
};
static LogEntry sLogs[64];        // 环形 64 条
static uint8_t  sLogHead = 0;     // 下一个写入位置
static uint32_t sLogId   = 0;     // 单调递增

static void log(const String &line) {
  Serial.println(line);
  LogEntry &e = sLogs[sLogHead];
  e.id = ++sLogId;
  strlcpy(e.line, line.c_str(), sizeof(e.line));
  sLogHead = (sLogHead + 1) % (sizeof(sLogs) / sizeof(sLogs[0]));
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

/* ---------------- 主目标 (仅 RAM 记录) ---------------- */
struct Target {
  bool   set = false;
  String ssid, bssid, auth;
  int    channel = 0;
  int    rssi    = 0;
};
static Target sTarget;

/* ---------------- chip / 工具 ---------------- */
static String detectChipKey() {
  String chip = ESP.getChipModel();           // "ESP32-S3 (Q8, 240MHz, 8MB PSRAM)"等
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
  // admin_page.h 内嵌数据 (zlib/deflate 格式), 浏览器自动解压
  server.sendHeader("Content-Encoding", "deflate");
  server.send_P(200, "text/html; charset=utf-8", (const char *)ADMIN_PAGE, ADMIN_PAGE_LEN);
}

static void sendInfo() {
  uint32_t freeHeap = ESP.getFreeHeap();
  uint32_t minFree  = ESP.getMinFreeHeap();
  uint32_t maxBlock = ESP.getMaxAllocHeap();
  uint32_t total    = ESP.getHeapSize();
  uint8_t  usedPct  = total ? (uint8_t)((total - freeHeap) * 100 / total) : 0;

  String json = "{";
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
  json += "\"channel\":" + String(apChannel) + ",";
  json += "\"clients\":" + String(WiFi.softAPgetStationNum()) + ",";
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
  // APSTA 模式下 STA 空扫不会掉已连接客户端
  WiFi.scanNetworks(false /*async*/, true /*show_hidden*/, false, 300);
  int n = WiFi.scanComplete();
  if (n == WIFI_SCAN_FAILED) {
    WiFi.scanDelete();
    WiFi.scanNetworks(false, true, false, 300);
    n = WiFi.scanComplete();
  }
  String json = "{\"networks\":[";
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
  // 极简 JSON 字段提取 (够用即可, 页面是我们自己发的)
  String body = server.arg("plain");
  auto extract = [&](const char *key) -> String {
    int k = body.indexOf("\"" + String(key) + "\":");
    if (k < 0) return "";
    int colon = k + strlen(key) + 2;
    // 值是字符串
    if (body[colon + 1] == '"' || body[colon] == '"') {
      int q1 = body.indexOf('"', colon);
      if (q1 < 0) return "";
      int q2 = body.indexOf('"', q1 + 1);
      return (q2 > q1) ? body.substring(q1 + 1, q2) : "";
    }
    // 值是数字
    int comma = body.indexOf(',', colon);
    int brace = body.indexOf('}', colon);
    int end = (comma < 0) ? brace : min(comma, brace);
    return (end > colon) ? body.substring(colon + 1, end) : "";
  };

  sTarget.set = true;
  sTarget.ssid = extract("ssid");
  sTarget.bssid = extract("bssid");
  sTarget.auth = extract("auth");
  sTarget.channel = extract("channel").toInt();
  sTarget.rssi = extract("rssi").toInt();
  sTarget.ssid.trim();
  sTarget.bssid.trim();
  sTarget.auth.trim();

  log("[target] 已设置目标: " + (sTarget.ssid.length() ? sTarget.ssid : "(隐藏)") +
      " @ch" + String(sTarget.channel) + " " + sTarget.bssid);
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.send(200, "application/json", "{\"ok\":true}");
}

static void handleLog() {
  uint32_t since = 0;
  if (server.hasArg("since")) since = (uint32_t)atol(server.arg("since").c_str());
  server.sendHeader("Access-Control-Allow-Origin", "*");
  String json = "{\"entries\":[";
  int n = sizeof(sLogs) / sizeof(sLogs[0]);
  int cnt = 0;
  for (int i = n; i > 0; i--) {
    uint8_t idx = (sLogHead + n - i) % n;   // 从最旧到最新
    if (sLogs[idx].id == 0 || sLogs[idx].id <= since) continue;
    if (cnt) json += ",";
    json += "{\"id\":" + String(sLogs[idx].id) + ",\"line\":\"" +
            jsonEscape(String(sLogs[idx].line)) + "\"}";
    cnt++;
  }
  json += "]}";
  server.send(200, "application/json", json);
}

static void doFactoryReset() {
  log("[admin] 恢复出厂设置 (擦除 NVS) …");
  nvs_flash_erase();
  nvs_flash_init();
  server.send(200, "application/json", "{\"ok\":true}");
  delay(300);
  ESP.restart();
}

static void doReset() {
  log("[admin] 收到重启指令, 3 秒后重启 …");
  server.send(200, "application/json", "{\"ok\":true}");
  delay(300);
  ESP.restart();
}

static void redirectToAdmin() {
  server.sendHeader("Location", ADMIN_HTML_C);
  server.send(302, "text/plain", "");
}

// Captive Portal: 连上热点后手机/电脑会自动探测网络并弹出登录页。
// 各 OS 探测路径返回 302 → /admin.html (iOS/Android/Windows 均认可为"需要登录");
// 其余未知路径(用户手输任意域名)也重定向到后台;
// 但 /api/* 必须原样 404, 否则会破坏后台 SPA 的 fetch 契约。
static void captiveRedirect(const char *type = "text/plain") {
  server.sendHeader("Location", "/admin.html");
  server.send(302, type, "");
}

static void notFound() {
  String uri = server.uri();
  if (uri.startsWith("/api/")) {
    server.send(404, "text/plain", "404 — 未知 API: " + uri);
    return;
  }
  // 常见系统探测路径 (返回 302 让系统判定为 Captive Portal 并弹窗)
  if (uri == "/hotspot-detect.html" || uri == "/library/test/success.html" ||   // iOS / macOS
      uri == "/generate_204" || uri == "/gen_204" ||                              // Android
      uri == "/connecttest.txt" || uri == "/redirect" || uri == "/ncsi.txt" ||   // Windows
      uri == "/success.txt" || uri == "/fwlink" || uri == "/") {                  // 其它/根
    captiveRedirect();
    return;
  }
  // 任意其它域名/路径 → 后台 (配合 DNS 通配解析实现强制门户)
  captiveRedirect();
}

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println();
  Serial.println("==============================================");
  Serial.println(F("ESP32 无线网络开发固件 v" FW_VERSION " (" FW_BUILD_NS ")"));
  Serial.println(F("仅供网络安全学习研究 · 严禁非法使用"));
  Serial.println("==============================================");

  // 经典 ESP32 若曾设过 STA 东西先清掉, 确保纯 AP
  WiFi.persistent(false);

  uint8_t mac[6];
  WiFi.macAddress(mac);
  apSsid = "WiFi-" + formatMac(mac).substring(12);  // 尾 2 字节 = 4 个 hex (如 WiFi-3A5F)
  apSsid.replace(":", "");

  // AP 模式: 信道 6, 最大 4 客户端
  if (!WiFi.softAP(apSsid.c_str(), AP_PASSWORD, apChannel, false, 4)) {
    log("[wifi] softAP 启动失败, 将重试 …");
    delay(2000);
    WiFi.softAP(apSsid.c_str(), AP_PASSWORD, apChannel, false, 4);
  }
  log("[wifi] AP 已启动: SSID=" + apSsid + "  密码=" + AP_PASSWORD);
  log("[wifi] 后台: " + String(ADMIN_HTML_C));
  log("[system] 芯片: " + detectChipKey() + "  FreeHeap: " + String(ESP.getFreeHeap()) + " bytes");

  server.on("/", HTTP_GET, redirectToAdmin);
  server.on("/admin.html", HTTP_GET, sendAdminPage);
  server.on("/api/info", HTTP_GET, sendInfo);
  server.on("/api/scan", HTTP_GET, handleScan);
  server.on("/api/target", HTTP_POST, handleTarget);
  server.on("/api/log", HTTP_GET, handleLog);
  server.on("/api/reset", HTTP_POST, doReset);
  server.on("/api/factory-reset", HTTP_POST, doFactoryReset);
  server.onNotFound(notFound);
  server.begin();
  log("[http] 管理后台 HTTP 服务已启动 (80)");

  // Captive Portal: DNS 通配解析所有域名 → AP IP(192.168.4.1),
  // 配合 notFound() 的 302 让手机连热点后自动弹出后台页
  if (dnsServer.start(DNS_PORT, "*", WiFi.softAPIP())) {
    log("[dns] Captive Portal DNS 已启动 (53, * → 192.168.4.1)");
  } else {
    log("[dns] Captive Portal DNS 启动失败 (后台仍可用, 需手动输地址)");
  }
}

void loop() {
  server.handleClient();
  dnsServer.processNextRequest();   // 新版为 AsyncUDP 回调(空实现), 保留以兼容旧核
  // 心跳: 每 30 秒打印状态 (控制台可见; /api/log 增量同步到后台)
  static uint32_t lastBeat = 0;
  uint32_t now = millis();
  if (now - lastBeat > 30000) {
    lastBeat = now;
    log("[beacon] " + apSsid + " clients=" + String(WiFi.softAPgetStationNum())
        + "  heap=" + String(ESP.getFreeHeap()) + "  uptime=" + String(now / 1000) + "s");
  }
  delay(10);
}
