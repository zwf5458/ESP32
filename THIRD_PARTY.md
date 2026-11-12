# 第三方数据与规范来源

本仓库的固件与前端代码均为独立实现；下表仅记录**公开数据/规范**来源。P4 未复制
ESPsoup（App 未选择许可证、固件 GPL-3.0）的任何代码。

| 数据 / 规范 | 用途 | 来源 | 说明 |
|---|---|---|---|
| IEEE OUI / MA-L 注册表 | WiFi BSSID / 客户端 MAC 厂商名 | <https://standards-oui.ieee.org/oui/oui.csv> | 仅提取 `Assignment` + `Organization Name` 事实字段；生成 `firmware/data/vendor_db.js` |
| Bluetooth SIG Company Identifiers | BLE Manufacturer Data 的 Company ID 名称 | <https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml> | 仅提取数值与名称；生成 `firmware/data/vendor_db.js` |
| Bluetooth SIG Service UUIDs | GATT 16-bit Service UUID 名称 | <https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/service_uuids.yaml> | 仅提取数值与名称；生成 `firmware/data/vendor_db.js` |
| 公开生态协议前缀 | Eddystone / BTHome / Fast Pair / Remote ID 等展示名 | Bluetooth SIG 成员 UUID 与各公开规范 | 仅补充 UUID → 名称映射，不含第三方代码 |
| ASTM F3411 / OpenDroneID | Remote ID 消息格式与测试向量（P4-3 计划） | <https://github.com/opendroneid/opendroneid-core-c>（Apache-2.0） | 计划仅参考字段定义；如引入测试向量，将在实现处保留 Apache-2.0 署名 |

## 生成方式

```bash
# 下载公开注册表到本地缓存（tools/vendor-src/ 不入库）
npm run gen-vendor

# 或使用已有缓存
node tools/gen-vendor-tables.mjs --src tools/vendor-src

# 校验已提交的 vendor_db.js 是否与源一致
node tools/gen-vendor-tables.mjs --src tools/vendor-src --check
```

生成物 `firmware/data/vendor_db.js` 由构建脚本压缩内嵌为 `firmware/src/vendor_db.h`，
通过 `GET /vendor-db.js` 提供给后台页面。该文件只含公开注册数据的事实字段，不含任何
第三方项目代码。
