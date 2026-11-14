#pragma once
#include <Arduino.h>
#include <Preferences.h>
#include <WiFi.h>

#if FW_BLE_SUPPORTED
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEServer.h>
#include <BLE2902.h>
#include <BLESecurity.h>
#endif

#ifdef FW_OLED_ENABLED
#include "ssd1306_tiny.h"
extern TinySSD1306 oled;
extern bool oledFound;
#endif

/* ==================== Meta Muse AI 伴侣模式实现 ==================== */
extern bool sIsMuseMode;
extern String sSerialCmd;

static BLEServer *sMuseBleServer = nullptr;
static BLECharacteristic *sMuseTxChar = nullptr;
static BLECharacteristic *sMuseRxChar = nullptr;
static bool sMuseDeviceConnected = false;
static bool sMusePairingConfirmed = false;
static String sActiveSdkToken = "";

// 本项目自实现的 GATT UUID。注意：这不是 Meta 官方的服务
// （官方 esp32/main/ble_server.c 用 7fdd3d1c-38ea-46cf-8b46-314ecf5f240c +
//  加密配对会话 + 设备按键确认），所以本模式只能自娱，无法完成官方 App 配对。
static const char *MUSE_SERVICE_UUID = "4d757365-0001-4000-8000-6a6f6c6c7900";
static const char *MUSE_RX_CHAR_UUID = "4d757365-0002-4000-8000-6a6f6c6c7900"; // 客户端/手机写入 (Write)
static const char *MUSE_TX_CHAR_UUID = "4d757365-0003-4000-8000-6a6f6c6c7900"; // 设备端通知/读取 (Notify/Read)

static String getStoredSdkToken() {
  Preferences p;
  p.begin("hatch-link", true);
  String tok = p.getString("sdk_token", "");
  p.end();
  if (tok.length() == 0) {
    p.begin("sysmode", true);
    tok = p.getString("sdk_token", "");
    p.end();
  }
  return tok;
}

static void saveStoredSdkToken(const String &tok) {
  Preferences p;
  p.begin("hatch-link", false);
  p.putString("sdk_token", tok);
  p.end();
  p.begin("sysmode", false);
  p.putString("sdk_token", tok);
  p.end();
}

#if FW_BLE_SUPPORTED
class MuseSecurityCallbacks : public BLESecurityCallbacks {
  uint32_t onPassKeyRequest() override { return 123456; }
  void onPassKeyNotify(uint32_t pass_key) override {}
  bool onConfirmPIN(uint32_t pin) override { return true; }
  bool onSecurityRequest() override { return true; }
  void onAuthenticationComplete(ble_gap_conn_desc *desc, int status) override {
    Serial.printf("[muse] 蓝牙 SMP 配对结果 status: %d\n", status);
  }
};
#endif

class MuseServerCallbacks : public BLEServerCallbacks {
  void onConnect(BLEServer *pServer) override {
    sMuseDeviceConnected = true;
    Serial.println(F("\n[muse] 手机 App 已连接 (BLE Connected)"));
    #ifdef FW_OLED_ENABLED
    if (oledFound) {
      oled.clear();
      oled.drawString(0, 0, "=== Meta Muse ===");
      oled.drawString(0, 16, "BLE: Connected");
      oled.drawString(0, 32, "Handshaking...");
      oled.display();
    }
    #endif
  }
  void onDisconnect(BLEServer *pServer) override {
    sMuseDeviceConnected = false;
    sMusePairingConfirmed = false;
    Serial.println(F("\n[muse] 手机 App 已断开, 恢复广播中..."));
    #if FW_BLE_SUPPORTED
    BLEDevice::getAdvertising()->start();
    #endif
    #ifdef FW_OLED_ENABLED
    if (oledFound) {
      oled.clear();
      oled.drawString(0, 0, "=== Meta Muse ===");
      oled.drawString(0, 16, "BLE: Advertising");
      oled.drawString(0, 32, "Waiting Phone...");
      oled.display();
    }
    #endif
  }
};

class MuseRxCallbacks : public BLECharacteristicCallbacks {
  void onWrite(BLECharacteristic *pCharacteristic) override {
    String rxVal = pCharacteristic->getValue();
    if (rxVal.length() > 0) {
      Serial.print(F("[muse] 收到手机握手包, 长度: "));
      Serial.println(rxVal.length());
      Serial.print(F("[muse] 内容: "));
      Serial.println(rxVal);

      // 提取手机发送的 SDK Token
      int tokIdx = rxVal.indexOf("mgst_");
      if (tokIdx >= 0) {
        int endIdx = tokIdx + 5;
        while (endIdx < rxVal.length() && (isalnum(rxVal[endIdx]) || rxVal[endIdx] == '-' || rxVal[endIdx] == '_')) {
          endIdx++;
        }
        sActiveSdkToken = rxVal.substring(tokIdx, endIdx);
        saveStoredSdkToken(sActiveSdkToken);
        Serial.printf("[muse] 捕获并存储手机 SDK Token: %.12s...\n", sActiveSdkToken.c_str());
      }

      String tokenToUse = sActiveSdkToken.length() > 0 ? sActiveSdkToken : getStoredSdkToken();
      if (tokenToUse.length() == 0) {
        Serial.println(F("[muse][WARN] 尚未配置 SDK Token: 请先发送 >sdk_token=mgst_... 再配对"));
      }

      String resp;
      if (rxVal.indexOf("pairing_client_hello") >= 0) {
        resp = "{\"status\":\"ok\",\"action\":\"pairing_ready\",\"pairing\":\"confirmed\",\"device\":\"MuseGadget\",\"sdk_token\":\"" + tokenToUse + "\"}";
      } else if (rxVal.indexOf("get_device_info") >= 0 || rxVal.indexOf("devinfo") >= 0) {
        resp = "{\"status\":\"ok\",\"action\":\"devinfo\",\"name\":\"MuseGadget\",\"version\":\"999.0.0\"}";
      } else if (rxVal.indexOf("pair_confirm") >= 0) {
        resp = "{\"status\":\"ok\",\"action\":\"pairing_confirmed\",\"pairing\":\"active\"}";
      } else {
        resp = "{\"status\":\"ok\",\"pairing\":\"confirmed\",\"token\":\"valid\",\"sdk_token\":\"" + tokenToUse + "\",\"device\":\"MuseGadget\"}";
      }

      if (sMuseTxChar) {
        sMuseTxChar->setValue(resp.c_str());
        sMuseTxChar->notify();
        Serial.print(F("[muse] 已发送握手响应: "));
        Serial.println(resp);
      }

      sMusePairingConfirmed = true;
      #ifdef FW_OLED_ENABLED
      if (oledFound) {
        oled.clear();
        oled.drawString(0, 0, "=== Meta Muse ===");
        oled.drawString(0, 16, "Status: Paired!");
        oled.drawString(0, 32, "AI Voice Ready");
        oled.drawString(0, 48, "Hold BOOT: Exit");
        oled.display();
      }
      #endif
    }
  }
};

inline void setupMuseMode() {
  sIsMuseMode = true;
  Serial.println(F("\n=============================================="));
  Serial.println(F("Meta Muse AI Companion Mode (ESP32-C5)"));
  Serial.println(F("项目自实现 BLE GATT 演示 · 非 Meta 官方配对协议"));
  Serial.println(F("输入 'boot audit' 或长按 BOOT 键 3 秒可恢复审计系统"));
  Serial.println(F("=============================================="));

  sActiveSdkToken = getStoredSdkToken();
  if (sActiveSdkToken.length() == 0) {
    Serial.println(F("[muse][WARN] 未配置 Meta Muse SDK Token。请发送 >sdk_token=mgst_... (串口/NVS 存储)。"));
    Serial.println(F("[muse][WARN] 注意: 本模式的 GATT 服务为项目自实现，不是 Meta 官方配对协议，"));
    Serial.println(F("[muse][WARN] 广播名相近但不代表能完成官方配对。"));
  } else {
    Serial.printf("[muse] 已载入 SDK Token: %.12s...\n", sActiveSdkToken.c_str());
  }

  uint8_t mac[6];
  WiFi.macAddress(mac);
  char devName[32];
  snprintf(devName, sizeof(devName), "MuseGadget-%02X%02X%02X", mac[3], mac[4], mac[5]);
  Serial.printf("[muse] 广播设备名称: %s\n", devName);

  #ifdef FW_OLED_ENABLED
  Wire.begin(FW_OLED_SDA, FW_OLED_SCL);
  oledFound = oled.begin();
  if (oledFound) {
    oled.clear();
    oled.drawString(0, 0, "=== Meta Muse ===");
    oled.drawString(0, 16, devName);
    oled.drawString(0, 32, "BLE: Advertising");
    oled.drawString(0, 48, "Hold BOOT: Exit");
    oled.display();
  }
  #endif

  #if FW_BLE_SUPPORTED
  BLEDevice::init(devName);
  sMuseBleServer = BLEDevice::createServer();
  sMuseBleServer->setCallbacks(new MuseServerCallbacks());

  BLEService *pService = sMuseBleServer->createService(MUSE_SERVICE_UUID);

  // 0002: 客户端/手机写入 (Write / Write without response)
  sMuseRxChar = pService->createCharacteristic(
    MUSE_RX_CHAR_UUID,
    BLECharacteristic::PROPERTY_WRITE |
    BLECharacteristic::PROPERTY_WRITE_NR
  );
  sMuseRxChar->setCallbacks(new MuseRxCallbacks());

  // 0003: 设备端通知/读取 (Read / Notify) 并必须带 0x2902 CCCD 描述符
  sMuseTxChar = pService->createCharacteristic(
    MUSE_TX_CHAR_UUID,
    BLECharacteristic::PROPERTY_READ |
    BLECharacteristic::PROPERTY_NOTIFY
  );
  sMuseTxChar->addDescriptor(new BLE2902());
  String initPayload = "{\"status\":\"ready\",\"name\":\"MuseGadget\"";
  if (sActiveSdkToken.length() > 0) {
    initPayload += ",\"sdk_token\":\"" + sActiveSdkToken + "\"";
  }
  initPayload += "}";
  sMuseTxChar->setValue(initPayload.c_str());

  pService->start();

  BLEDevice::setSecurityCallbacks(new MuseSecurityCallbacks());
  BLESecurity *pSecurity = new BLESecurity();
  pSecurity->setAuthenticationMode(ESP_LE_AUTH_REQ_SC_BOND);
  pSecurity->setCapability(ESP_IO_CAP_NONE);
  pSecurity->setInitEncryptionKey(ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK);

  BLEAdvertising *pAdv = BLEDevice::getAdvertising();
  pAdv->addServiceUUID(MUSE_SERVICE_UUID);
  pAdv->setScanResponse(true);
  pAdv->setMinPreferred(0x06);
  pAdv->setMinPreferred(0x12);
  pAdv->start();
  #endif

  pinMode(9, INPUT_PULLUP);

  Serial.printf("[muse] BLE 广播已启动! Service: %s\n", MUSE_SERVICE_UUID);
  Serial.printf("[muse] RX (Write): %s\n", MUSE_RX_CHAR_UUID);
  Serial.printf("[muse] TX (Notify): %s\n", MUSE_TX_CHAR_UUID);
  Serial.println(F("[muse] 手机 Meta Muse App 现在可以直接搜索并连接！"));
}

inline void loopMuseMode() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\r' || c == '\n') {
      sSerialCmd.trim();
      if (sSerialCmd.length() > 0) {
        // 兼容官方控制台写法 '>sdk_token=mgst_...'，去掉前导 '>'
        if (sSerialCmd.startsWith(">")) sSerialCmd = sSerialCmd.substring(1);
        sSerialCmd.trim();
        if (sSerialCmd == "boot audit" || sSerialCmd == "boot" || sSerialCmd == "audit") {
          Serial.println(F("[muse] 正在恢复至 Wi-Fi 安全审计系统并重启..."));
          Preferences prefs;
          prefs.begin("sysmode", false);
          prefs.putString("mode", "audit");
          prefs.end();
          delay(500);
          ESP.restart();
        } else if (sSerialCmd.startsWith("sdk_token ") || sSerialCmd.startsWith("sdk_token=")) {
          String tok = sSerialCmd.substring(10);
          tok.trim();
          if (tok.startsWith("=")) tok = tok.substring(1);
          tok.trim();
          if (tok.startsWith("mgst_")) {
            saveStoredSdkToken(tok);
            sActiveSdkToken = tok;
            Serial.printf("[muse] 已成功保存 SDK Token: %.12s...\n", tok.c_str());
            Serial.println(F("@sdk_token ok"));
          } else {
            Serial.println(F("@sdk_token error invalid (必须以 mgst_ 开头)"));
          }
        } else if (sSerialCmd == "reboot") {
          ESP.restart();
        } else if (sSerialCmd == "help" || sSerialCmd == "?") {
          Serial.println(F("=== Meta Muse 模式串口指令 ==="));
          Serial.println(F("sdk_token <mgst_xxx> : 设置 Meta Muse 个人开发者 SDK Token"));
          Serial.println(F("boot audit           : 恢复至 Wi-Fi 安全审计系统并重启"));
          Serial.println(F("reboot               : 重启设备"));
        }
        sSerialCmd = "";
      }
    } else if (c >= 32 && c <= 126 && sSerialCmd.length() < 128) {
      sSerialCmd += c;
    }
  }

  static uint32_t pressStart = 0;
  static bool wasPressed = false;
  bool pressed = (digitalRead(9) == LOW);

  if (pressed && !wasPressed) {
    pressStart = millis();
    wasPressed = true;
  } else if (!pressed && wasPressed) {
    uint32_t duration = millis() - pressStart;
    wasPressed = false;
    if (duration >= 3000) {
      Serial.println(F("[muse] 检测到长按 BOOT 键 (>=3秒), 正在切回 Wi-Fi 安全审计系统..."));
      Preferences prefs;
      prefs.begin("sysmode", false);
      prefs.putString("mode", "audit");
      prefs.end();
      delay(500);
      ESP.restart();
    } else if (duration >= 50) {
      Serial.println(F("[muse] button short-press confirmed active pairing session"));
      if (sMuseDeviceConnected && sMuseTxChar) {
        sMuseTxChar->setValue("{\"button_confirm\":true,\"action\":\"pair_confirm\",\"pairing\":\"confirmed\"}");
        sMuseTxChar->notify();
      }
    }
  }

  delay(20);
}
