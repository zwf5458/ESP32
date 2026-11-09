// 烧录台前端主逻辑: Web Serial + esptool-js 0.5.1 (ESM CDN)
import { ESPLoader, Transport } from "https://unpkg.com/esptool-js@0.5.1/bundle.js";

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const two = (n) => String(n).padStart(2, "0");
const nowTs = () => {
  const d = new Date();
  return `[${two(d.getHours())}:${two(d.getMinutes())}:${two(d.getSeconds())}]`;
};

// ---------- 状态 ----------
const state = {
  manifest: { chips: {}, supported: [] },
  chipManual: false,
  port: null,          // 已授权 SerialPort
  transport: null,
  esploader: null,
  chip: null,          // manifest 键: esp32 / esp32s3 ...
  bin: null,           // ArrayBuffer
  binMd5: null,
  flashVersion: null,
  code: null,          // 已校验的烧录码
  nonce: null,
  consoleConn: false,  // 是否处于控制台读取模式
};

const BAUD_FLASH = 921600;
const BAUD_CONSOLE = 115200;

// ---------- 通用 UI ----------
function setStatus(connected, text) {
  const el = $('serialStatus');
  el.classList.toggle('on', connected);
  $('serialStatusText').textContent = text;
}
function msg(text, cls = '') {
  const el = $('codeHint');
  el.textContent = text;
  el.className = 'hint ' + cls;
}
function progress(pct, label) {
  $('progress').style.width = pct + '%';
  $('progressLabel').textContent = label;
}
function terminalAppend(text) {
  const el = $('console');
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 4;
  el.textContent += text;
  if (atBottom) el.scrollTop = el.scrollHeight;
}

// esptool-js 终端适配器: 把 loader 输出导向我们的控制台
const loaderTerminal = {
  clean() { $('console').textContent = ''; },
  writeLine(d) { terminalAppend(nowTs() + ' ' + d + '\n'); },
  write(d) { terminalAppend(d); },
};

// ---------- 开机欢迎信息 (对齐参考站控制台样式) ----------
function bootBanner() {
  $('console').textContent =
    `${nowTs()} ESP32无线网络开发固件烧录台就绪\n` +
    `${nowTs()} 流程: ①选择串口（自动连接） → ②输入并校验烧录码 → ③选择开发板 → ④勾选免责声明 → ⑤烧录\n` +
    `${nowTs()} 波特率固定: 烧录 ${BAUD_FLASH / 1000} / 控制台 ${BAUD_CONSOLE / 1000}\n` +
    `${nowTs()} 注意: 每个烧录码只能成功烧录一次；烧录失败不消耗烧录码。\n`;
}

// ---------- 固件清单 ----------
async function loadManifest() {
  try {
    const r = await fetch('/api/firmware/manifest');
    state.manifest = await r.json();
    const chips = Object.entries(state.manifest.chips);
    if (!chips.length) {
      terminalAppend(`${nowTs()} [manifest] 服务端暂无固件镜像, 请先运行 tools/build-firmware.sh 编译注册\n`);
      return;
    }
    // 版本取所有芯片一致值 (同一次构建)
    const versions = [...new Set(chips.map(([, v]) => v.version))];
    const ver = versions[0];
    state.fwVersion = ver;
    $('fwLabel').textContent = ver;
    $('fwLabel-mini').textContent = 'v' + ver;
    const totalKB = chips.reduce((a, [, v]) => a + v.size, 0) / 1024;
    const names = chips.map(([k]) => k.replace(/^esp32/, '').toUpperCase() || 'ESP32').join('/');
    $('fwNote').textContent = `${ver} 版本覆盖 ${chips.length} 个芯片系列 (${names})，合计镜像 ${(totalKB / 1024).toFixed(1)} MB`;
    terminalAppend(`${nowTs()} [manifest] 可用镜像: ${chips.map(([k, v]) => `${k} @v${v.version}`).join(' ')}\n`);
    terminalAppend(`${nowTs()} 请先连接串口识别开发板型号。\n`);
    populateChipSelect();
  } catch (e) {
    terminalAppend(`${nowTs()} [manifest] 加载失败: ${e.message}\n`);
  }
}

function populateChipSelect() {
  const sel = $('chipLabel');
  sel.innerHTML = '<option value="">— 自动识别（推荐）—</option>';
  for (const key of state.manifest.supported) {
    const fw = state.manifest.chips[key];
    if (!fw) continue;
    const opt = document.createElement('option');
    opt.value = key;
    opt.textContent = chipDisplayName(key);
    sel.appendChild(opt);
  }
  for (const key of state.manifest.supported) {
    if (state.manifest.chips[key]) continue;
    const opt = document.createElement('option');
    opt.value = `exp:${key}`;
    opt.disabled = true;
    opt.textContent = chipDisplayName(key) +
      (key === 'esp32c5' ? '（实验性 · 暂未开放镜像）' : '（暂无固件镜像）');
    sel.appendChild(opt);
  }
  // 手动选择保持; 自动识别模式回到占位
  sel.value = (state.chip && state.chipManual) ? state.chip : '';
}

function chipDisplayName(key) {
  return key === 'esp32' ? 'ESP32' : 'ESP32-' + key.slice(5).toUpperCase();
}

// 手动选择开发板型号 (串口识别成功前可预选; 识别成功后自动匹配仍优先)
$('chipLabel').onchange = () => {
  const v = $('chipLabel').value;
  if (v.startsWith('exp:')) { $('chipLabel').value = ''; return; }
  if (!v) {
    state.chip = null; state.chipManual = false; state.bin = null;
  } else {
    if (state.chip && state.chip !== v && state.esploader) {
      terminalAppend(`${nowTs()} [chip] 远端设备已连接, 手动切换型号可能烧错镜像 — 建议先断开再切换\n`);
    }
    state.chip = v; state.chipManual = true; state.bin = null;
    terminalAppend(`${nowTs()} [chip] 已手动指定开发板型号: ${chipDisplayName(v)}\n`);
  }
  updateChipUI();
  refreshFlashButton();
};

// 芯片别名: main() 返回 "ESP32-S3 (revision v0.2)" / "ESP32 (revision v3.1)" 等
function chipKeyFromDescription(desc) {
  const m = /ESP32-(\w+)/.exec(desc);
  if (m) {
    const key = 'esp32' + m[1].toLowerCase();
    return state.manifest.supported.includes(key) ? key : null;
  }
  if (desc.startsWith('ESP32')) return state.manifest.supported.includes('esp32') ? 'esp32' : null;
  return null;
}

// ---------- 串口连接 ----------
$('btnChoosePort').onclick = async () => {
  if (!('serial' in navigator)) {
    alert('此浏览器不支持 Web Serial。请使用 Chrome / Edge 最新版 (localhost 访问本页)。');
    return;
  }
  try {
    state.port = await navigator.serial.requestPort({});
    state.port.addEventListener('disconnect', onSerialGone);
    $('portLabel').textContent = '已授权串口 — 已选择设备 —';
    $('btnConnect').disabled = false;
  } catch { /* 用户取消 */ }
};

const onSerialGone = () => {
  setStatus(false, '未连接');
  state.port = state.transport = state.esploader = null;
  $('btnConnect').disabled = false;
  $('btnDisconnect').disabled = true;
  $('portLabel').textContent = '已授权串口 — 无已授权端口 —';
  msg('串口已断开。重新点「连接」可继续 (烧录码仍有效)', 'warn');
};

async function connect() {
  if (!state.port) return null;
  const skipReset = $('skipAutoReset').checked;
  if (skipReset) terminalAppend('[hint] 已选择跳过自动复位: 请按住 BOOT 键, 必要时再按 RESET / 重新插拔进入下载模式\n');
  $('btnConnect').disabled = true;
  try {
    setStatus(true, '连接中… (尝试进入下载模式)');
    state.transport = new Transport(state.port, true);
    state.esploader = new ESPLoader({
      transport: state.transport,
      baudrate: BAUD_FLASH,
      terminal: loaderTerminal,
      debugLogging: false,
    });
    const desc = await state.esploader.main(); // 复位进下载模式 → 读芯片 → 上传 stub
    const detected = chipKeyFromDescription(desc);
    if (detected) {
      if (state.chip && state.chip !== detected && state.chipManual) {
        terminalAppend(`${nowTs()} [chip] 检测到实际芯片 ${desc} — 与手动指定的 ${chipDisplayName(state.chip)} 不符, 已按检测值自动匹配 (防止烧错镜像)\n`);
      }
      state.chip = detected; state.chipManual = false;
    } else if (!state.chip) {
      msg(`识别到芯片 ${desc}, 但服务端没有该芯片的镜像`, 'warn');
    } else {
      terminalAppend(`${nowTs()} [chip] 无法从镜像清单匹配到 ${desc}, 使用手动指定: ${chipDisplayName(state.chip)}\n`);
    }
    updateChipUI();
    setStatus(true, '已连接 · ' + desc);
    $('btnDisconnect').disabled = false;
    return desc;
  } catch (e) {
    terminalAppend('\n[connect] 失败: ' + e.message + '\n');
    setStatus(false, '未连接');
    $('btnConnect').disabled = false;
    state.transport = state.esploader = null;
    if (!$('skipAutoReset').checked) {
      msg('连接失败? 请勾选「跳过自动复位」, 按住 BOOT 再点连接', 'warn');
    } else {
      msg('连接失败: ' + e.message, 'err');
    }
    throw e;
  }
}

$('btnConnect').onclick = () => connect().catch(() => {});

$('btnDisconnect').onclick = async () => {
  try {
    if (state.transport) await state.transport.disconnect();
    await sleep(300);
  } catch { /* ignore */ }
  $('btnConnect').disabled = false; $('btnDisconnect').disabled = true;
  setStatus(false, '未连接');
  if (!state.chipManual) { state.chip = null; updateChipUI(); }
};

async function ensureFlasherConnection() {
  if (!state.esploader) {
    // 用户直接点烧录: 先尝试连接
    await $('btnConnect').onclick();
    if (!state.esploader) return false;
  }
  return true;
}

function updateChipUI() {
  const key = state.chip;
  const sel = $('chipLabel');
  if (!key) {
    sel.value = '';
    $('fwLabel-mini').textContent = '—';
    $('fwSize').textContent = '';
    return;
  }
  sel.value = key;
  const fw = state.manifest.chips[key];
  $('fwLabel-mini').textContent = fw ? 'v' + fw.version : '该芯片暂无镜像';
  $('fwSize').textContent = fw ? `${(fw.size / 1024).toFixed(0)} KB` : '';
}

// ---------- 烧录码 ----------
$('flashCode').addEventListener('input', () => {
  $('flashCode').className = '';
  state.nonce = null; state.code = null;
  $('btnVerify').disabled = $('flashCode').value.trim().length < 6;
  refreshFlashButton(); checkRedeemHint();
});

function refreshFlashButton() {
  const ck = $('agreeTerms').checked;
  const haveNonce = !!state.nonce;
  // 型号就绪 = 已选定且该芯片有镜像 (手动预选或自动识别均可)
  const haveFw = !!(state.chip && state.manifest.chips[state.chip]);
  const noPort = !state.port;
  // 都满足才可点; 未连接时也允许点 (点了会先走连接流程)
  $('btnFlash').disabled = !(ck && haveNonce && (haveFw || noPort));
}

function checkRedeemHint() {
  if (state.code && !state.nonce) msg('校验已过期或失败, 请重新校验烧录码', 'warn');
}

$('btnVerify').onclick = async () => {
  const code = $('flashCode').value.trim().toUpperCase();
  // 非手动指定的型号随轮次重置; 手动指定的保留 (用户明确意图)
  if (!state.chipManual) state.chip = null;
  state.bin = null;
  updateChipUI();
  // verify 时可先不带芯片
  try {
    $('btnVerify').disabled = true;
    const r = await fetch('/api/codes/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    const j = await r.json();
    if (!r.ok || !j.ok) { msg(j.error || '校验失败', 'err'); $('flashCode').className = 'err'; refreshFlashButton(); return; }
    state.code = code; state.nonce = j.nonce;
    $('flashCode').className = 'ok';
    msg('✓ 校验通过 (15 分钟内有效), 可点「开始烧录」', 'ok');
    refreshFlashButton();
  } catch (e) {
    msg('校验请求失败: ' + e.message, 'err');
  } finally { $('btnVerify').disabled = false; }
};

$('agreeTerms').onchange = refreshFlashButton;

// fetch 镜像
async function loadFwBinary(key) {
  const r = await fetch(`/api/firmware/bin/${key}`);
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `镜像加载失败 (${r.status})`);
  }
  const ab = await r.arrayBuffer();
  state.bin = ab;
  state.binMd5 = state.manifest.chips[key].md5;
  state.flashVersion = state.manifest.chips[key].version;
}

// ---------- 烧录主流程 ----------
$('btnFlash').onclick = async () => {
  if (!$('agreeTerms').checked) return;
  if (!state.nonce) { msg('请先校验烧录码', 'warn'); return; }
  const nonce = state.nonce; // 本轮使用, 无论成败轮次结束都作废
  state.nonce = null;
  refreshFlashButton();

  try {
    // 1. 串口就绪 + 芯片识别 (若尚未连接就先走连接流程)
    if (!state.esploader) {
      let sock;
      setStatus(true, '连接中…');
      try { sock = await connect(); } catch (e) { throw new Error('串口连接失败: ' + e.message); }
      if (!sock) throw new Error('串口连接失败');
    }
    const chipKey = state.chip;
    if (!chipKey) throw new Error('无法识别芯片, 或服务端没有该芯片的镜像');
    const fw = state.manifest.chips[chipKey];
    if (!fw) throw new Error(`芯片 ${chipKey} 暂无镜像, 请先编译并注册固件`);

    // 2. 下载镜像
    progress(2, '下载镜像…');
    await loadFwBinary(chipKey);

    // 3. 写入 (单镜像 offset 0x0)
    $('btnFlash').disabled = true;
    progress(5, '烧录开始…');
    // binary string (latin1)
    const u8 = new Uint8Array(state.bin);
    let bstr = '';
    for (let i = 0; i < u8.length; i += 0x8000) {
      bstr += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    }

    await state.esploader.writeFlash({
      fileArray: [{ data: bstr, address: 0 }],
      flashSize: 'keep',
      flashMode: 'keep',
      flashFreq: 'keep',
      eraseAll: false,
      compress: true,
      reportProgress: (_fi, written, total) => {
        const pct = 5 + (written / total) * 88;
        const kbs = (written / 1024).toFixed(0) + ' KB';
        progress(pct, `烧录中 ${(written / total) * 100}% · ${kbs}`);
      },
      calculateMD5Hash: (image) => CryptoJS.MD5(CryptoJS.enc.Latin1.parse(image)).toString(),
    });

    // 4. 成功 → 核销 → 提示
    progress(100, '✓ 烧录成功, 设备复位运行中');
    terminalAppend('\n[flash] 烧录成功! 设备即将出热点 WiFi-xxxx (密码 00000000), 后台 http://192.168.4.1/admin.html\n');
    msg('✓ 烧录成功! 设备已复位, 烧录码已核销。连接热点 WiFi-xxxx, 密码 00000000', 'ok');
    reportRedeem(nonce, true);

    // 5. 稍后切回 115200 挂控制台读启动日志
    setTimeout(() => { startConsole().catch(() => {}); }, 1500);
  } catch (e) {
    terminalAppend('\n[flash] 失败: ' + (e.message || e) + '\n');
    progress(0, '✗ 烧录失败 (烧录码未核销, 可重试)');
    msg('✗ 烧录失败: ' + (e.message || e) + '。烧录码未核销, 请重新校验烧录码再试。', 'err');
    reportRedeem(nonce, false);
  }
};

async function reportRedeem(nonce, success) {
  if (!nonce) return;
  try {
    const r = await fetch('/api/codes/redeem', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce, chip: state.chip, md5: state.binMd5, success }),
    });
    const j = await r.json();
    if (success && j.consumed) terminalAppend('[server] ' + (j.message || '烧录码已核销') + '\n');
    else if (!success) terminalAppend('[server] ' + (j.message || '已上报失败, 码未核销') + '\n');
    if (j.error) terminalAppend('[server] ' + j.error + '\n');
  } catch (e) {
    terminalAppend('[server] 上报失败: ' + e.message + '\n');
  }
}

// ---------- 串口控制台 ----------
async function startConsole() {
  if (!state.transport || state.consoleConn) return;
  try {
    await state.transport.disconnect();
  } catch { /* ignore */ }
  await sleep(200);
  try {
    await state.transport.connect(BAUD_CONSOLE);
  } catch (e) {
    terminalAppend('[console] 无法切到控制台模式: ' + e.message + '\n');
    return;
  }
  state.consoleConn = true;
  const hintEl = $('consoleHint');
  if (hintEl) hintEl.textContent = '控制台读取中 (115200)… 文本日志 + NDJSON 遥测（{ 开头为 JSON 事件）';
  // 经典复位: DTR/RTS 令芯片重启
  try {
    await state.transport.setDTR(false);
    await state.transport.setRTS(true);
    await sleep(120);
    await state.transport.setRTS(false);
  } catch { /* ignore */ }
  try {
    const loop = state.transport.rawRead();
    const dec = new TextDecoder();
    while (state.consoleConn) {
      const { value, done } = await loop.next();
      if (done || !value) break;
      terminalAppend(typeof value === 'string' ? value : dec.decode(value, { stream: true }));
    }
  } catch { /* port closed */ }
}

$('btnResetConsole').onclick = async () => {
  if (!state.transport) return;
  state.consoleConn = false;
  await sleep(100);
  startConsole().catch(() => {});
};

$('btnClear').onclick = () => { $('console').textContent = ''; };

$('btnCopy').onclick = async () => {
  await navigator.clipboard.writeText($('console').textContent);
  $('btnCopy').textContent = '已复制';
  setTimeout(() => ($('btnCopy').textContent = '复制'), 1200);
};

// ---------- 启动 ----------
if (localStorage.getItem('theme') === 'dark') document.documentElement.classList.add('dark');
$('btnTheme').onclick = () => {
  const dark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('theme', dark ? 'dark' : 'light');
  $('btnTheme').textContent = dark ? '🌙' : '☀️';
};
if (document.documentElement.classList.contains('dark')) $('btnTheme').textContent = '🌙';
$('btnLang').onclick = () => {}; // 语言切换占位 (当前仅中文)

bootBanner();
setStatus(false, '未连接');
loadManifest();
