# 烧录台前端依赖（本地固定版本）

这两个文件是未改动的上游发行包，直接从 npm 包复制，避免页面依赖公网 CDN：

| 文件 | 上游 | 版本 | 许可证 |
|---|---|---|---|
| `esptool-js-0.7.1.js` | [espressif/esptool-js](https://github.com/espressif/esptool-js) `bundle.js` | 0.7.1 | Apache-2.0（见 `LICENSE-esptool-js.txt`） |
| `crypto-js-4.2.0.js` | [brix/crypto-js](https://github.com/brix/crypto-js) `crypto-js.js`（完整 UMD 版） | 4.2.0 | MIT（见 `LICENSE-crypto-js.txt`） |

说明：

- `esptool-js` 必须 ≥ 0.7.0 才有 `detectFlashSize()` 与 ESP32-C5 目标；
  0.5.x 既不能识别 C5，也没有读 Flash（备份）能力。
- 0.7.x 的 `writeFlash({ fileArray: [{ data: Uint8Array, address }] })` 只接受
  `Uint8Array`，0.5.x 的 latin1 字符串入参已废弃。
- `crypto-js` 要用 `crypto-js.js`（完整 UMD 构建）而不是 `index.js`：
  后者是 CommonJS 包装，浏览器里 `<script>` 直接引入会因 `require` 未定义而失败。
- Web Serial 只要求安全上下文（`http://localhost` 或 HTTPS），与 CDN 无关；
  本地固定版本可在离线/内网环境直接用。

升级步骤：`npm pack <pkg>@<version>`（或 `npm i` 到临时目录）后复制 `bundle.js` /
`crypto-js.js` 覆盖，并同步更新本文件与 `index.html` / `app.js` 中的路径。
