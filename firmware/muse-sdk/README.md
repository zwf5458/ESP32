# 把 Meta Muse Gadget SDK 编进本工程的三系统布局（实验 / 进阶）

本目录只放**构建覆盖文件**，不含官方源码。目标：让 `muse-gadget.bin` 认本工程的分区表
（表 `0x8000`、`ota_2 @0x7F0000`，槽位 3.9375MB），从而与审计固件（`ota_0`）、
ESPsoup（`ota_1`）共存。

- `partitions_c5_16mb_triple.csv` —— 与 `firmware/partitions-16mb-triple.csv` 的分区行
  **完全一致**（契约测试会校验，防止漂移）；只允许改注释头。
- `sdkconfig.c5-16mb-triple` —— sdkconfig overlay：`CONFIG_PARTITION_TABLE_OFFSET=0x8000`
  + 自定义分区表文件名 + 16MB Flash。

## 为什么需要覆盖

Meta 官方 `esp32/partitions_muse.csv`（16MB 板）用的是：表 `0x10000`、`nvs 0x11000`、
`otadata 0x1D000`、app `ota_0 @0x20000`（4M）、`prod_data 0x820000` 等。与本工程的
三系统布局（表 `0x8000`、`otadata 0xD000`、`ota_0 0x10000`）互斥。

官方 app 编译时写死了 `CONFIG_PARTITION_TABLE_OFFSET=0x10000`，所以直接把它写进
`0x10000` 后：① 覆盖 `ota_0` 的审计固件；② app 启动后按 0x10000 读分区表，读到的却是
自己的镜像头 → `esp_ota_get_running_partition()` 断言崩溃。详见
`docs/firmware-flashing.md` §6.6。

## 步骤

```powershell
# 0) 一次性准备 ESP-IDF v6.0.3（官方只支持这个版本；浅克隆 + 并行子模块快很多）
git clone --depth 1 -b v6.0.3 --recurse-submodules --shallow-submodules --jobs 8 `
  https://github.com/espressif/esp-idf.git E:\code\esp-idf-v6.0.3
cd E:\code\esp-idf-v6.0.3
.\install.ps1 esp32c5
. .\export.ps1

# 1) 取官方 SDK，并同步本目录的覆盖文件
git clone https://github.com/facebookincubator/muse-gadget-sdk E:\code\muse-gadget-sdk
powershell -ExecutionPolicy Bypass -File E:\code\ESP32\firmware\muse-sdk\sync-to-sdk.ps1

# 2) 构建（约 1.7MB，C5 DevKitC-1 无屏配置）
cd E:\code\muse-gadget-sdk\esp32
idf.py -B build-c5-16mb-triple -DIDF_TARGET=esp32c5 `
  -DSDKCONFIG=build-c5-16mb-triple/sdkconfig `
  -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;devices/sdkconfig.c5-16mb-triple" `
  build

# 3) 写入 ota_2 并切过去
cd E:\code\ESP32
esptool --chip esp32c5 -p COM5 -b 460800 write-flash 0x7F0000 `
  E:\code\muse-gadget-sdk\esp32\build-c5-16mb-triple\muse-gadget.bin
# 串口写个人 Token（每台设备一个，也可以只在这里写而不编进固件）
#   >sdk_token=mgst_...
# 然后串口发 boot muse （或后台「切换至 Meta Muse」）
```

## 实测结果（2026-11-14）

ESP-IDF v6.0.3 + idf-component-manager 3.1.2 构建通过，**并已在 C5N16R8 真机上启动**：

- `muse-gadget.bin` = **1,708,032 B**（0x1A1000，`ota_2` 3.9375MB 槽剩余 59%）；
- `build-c5-16mb-triple/partition_table/partition-table.bin` 解出与本工程
  `firmware/partitions-16mb-triple.csv` 逐行一致（表 `0x8000`、`ota_2 @0x7F0000` 4032K）；
- `CONFIG_GADGET_SDK_TOKEN=""`（空值 + 构建警告，Token 走串口 `>sdk_token=mgst_…`）；
- 镜像内可检索到官方 GATT 服务 UUID（`7fdd3d1c-…`）与 RX 特征（`4d593029-…`）的
  128 位二进制，说明用的是官方协议栈而非本工程自实现的那套；
- **真机实测**：写入后正常引导 —— `app_init: Project name: muse-gadget`、
  `link.identity: ble_name=MuseGadget-8A12F8`、`SDK token: (none)`、LED ok，
  BLE 正常广播，无 panic / 重启循环；`>sdk_token=` 通道也有响应。
  官方 App 的实际配对仍未闭环（只差用户自己的 `mgst_` Token）。

> `build-triple` 与 `build-c5-16mb-triple` 的 `sdkconfig` 逐行相同，产物哈希只因编译
> 时间戳不同——两者功能等价。仓库里提交的是真机实测通过的那份（`build-triple`）。

产物已复制到本仓库 `server/firmware/muse-gadget.bin`（1,708,032 B，SHA256
`C5C18D453B73A47AE3C68EEFE7236E3DC76CF4E71AF3DFF2F0491D1996045033`），
由 `GET /api/firmware/muse` 下发给烧录台；该文件**必须入库**（不要再加回 `.gitignore`），
否则别人 clone 后烧录台的「载入已适配的 Muse 固件」会 404。

## 构建环境两个坑（与工程代码无关）

1. **二次 configure 解析失败**
   ```
   ERROR: Cannot parse CMake requirements line: idf_build_get_property(__cm_sdkconfig SDKCONFIG)
   ```
   component manager 会往 `component_requires.temp.cmake` 追加原生 CMake 语句（备份/恢复
   sdkconfig），下次 `load()` 又把它们当需求行解析。最小补丁：只解析
   `__component_set_property` 开头的行——
   `<idf python env>\Lib\site-packages\idf_component_manager\cmake_component_requirements.py`
   的 `load()` 里把 `if line.strip():` 换成
   `if line.lstrip().startswith('__component_set_property'):`。
2. **GBK 控制台编码崩溃**：`idf.py` 输出里含 `ϵ` 等字符时报
   `UnicodeEncodeError: 'gbk' codec ...`。构建前设 `PYTHONIOENCODING=utf-8`、
   `PYTHONUTF8=1`（或先 `chcp 65001`）。

## 已知限制

- 官方 SDK 的配对是 NimBLE 加密会话 + 设备按键确认，Muse 手机 App 侧还会校验设备
  `link.register` 等上报；能否在非官方板型上完全跑通需要真机验证，本目录只解决**分区/启动**
  这一层。
- 官方 OTA 默认关闭（`CONFIG_HOMEHUB_OTA_ENABLED=n`）。三系统场景请保持关闭：开着的话
  官方 OTA 会写「非运行槽位」，可能覆盖 `ota_1` 的 ESPsoup。
- `spiffs` 与官方 `apps` / `files`（LittleFS）不是同一个分区；依赖 Wasm 应用的构建
  （`MUSE_APPS=1`）需要另行规划分区。
