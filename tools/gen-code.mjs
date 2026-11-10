#!/usr/bin/env node
// 跨平台烧录码生成与管理命令行 (Windows/macOS/Linux 通用)
// 用法:
//   node tools/gen-code.mjs               # 默认生成 3 个测试码
//   node tools/gen-code.mjs 5 "批次A"     # 生成 5 个带备注的烧录码
//   node tools/gen-code.mjs --list        # 查看最近生成的烧录码
//   node tools/gen-code.mjs --stats       # 查看烧录码与刷机统计

const BASE = process.env.BASE || 'http://localhost:8787';
const TOKEN = process.env.ADMIN_TOKEN || 'local-admin-token-change-me';

const args = process.argv.slice(2);

async function main() {
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`
ESP32 烧录码管理命令行 (Node.js 跨平台)
用法:
  node tools/gen-code.mjs [数量] [备注]   # 生成测试烧录码 (默认 3 个)
  node tools/gen-code.mjs --list         # 查看最近的烧录码列表
  node tools/gen-code.mjs --stats        # 查看系统烧录与核销统计
环境变量:
  BASE=http://localhost:8787
  ADMIN_TOKEN=local-admin-token-change-me
`);
    return;
  }

  if (args.includes('--stats')) {
    try {
      const res = await fetch(`${BASE}/api/admin/stats`, {
        headers: { 'x-admin-token': TOKEN }
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        console.error('获取统计失败:', data.error || res.statusText);
        process.exit(1);
      }
      console.log('=== 烧录码与刷机统计 ===');
      console.log(`总烧录码:   ${data.stats.codes.total}`);
      console.log(`- 未使用:   ${data.stats.codes.unused}`);
      console.log(`- 校验中:   ${data.stats.codes.verified}`);
      console.log(`- 已核销:   ${data.stats.codes.redeemed}`);
      console.log(`活跃 Nonce: ${data.activeNonces}`);
      console.log(`烧录记录:   ${data.stats.flashes.total} (成功: ${data.stats.flashes.success}, 失败: ${data.stats.flashes.failed})`);
    } catch (e) {
      console.error(`无法连接到服务 ${BASE} (请先启动服务: npm start):`, e.message);
      process.exit(1);
    }
    return;
  }

  if (args.includes('--list')) {
    try {
      const res = await fetch(`${BASE}/api/admin/codes`, {
        headers: { 'x-admin-token': TOKEN }
      });
      const data = await res.json();
      if (!res.ok) {
        console.error('查询失败:', data.error || res.statusText);
        process.exit(1);
      }
      const codes = data.codes || [];
      if (!codes.length) {
        console.log('暂无烧录码');
        return;
      }
      console.log(`烧录码 (${codes.length} 条):`);
      for (const c of codes.slice(0, 30)) {
        const time = new Date(c.created_at).toLocaleString();
        console.log(`  ${c.code.padEnd(20)} [${c.status.padEnd(8)}] ${c.chip || '未绑定'} | ${time} | ${c.remark || ''}`);
      }
      if (codes.length > 30) {
        console.log(`  ... 另有 ${codes.length - 30} 条未显示`);
      }
    } catch (e) {
      console.error(`无法连接到服务 ${BASE} (请先启动服务: npm start):`, e.message);
      process.exit(1);
    }
    return;
  }

  // 默认: 生成烧录码
  const count = parseInt(args[0], 10) || 3;
  const remark = args[1] || 'local test';

  try {
    const res = await fetch(`${BASE}/api/admin/codes`, {
      method: 'POST',
      headers: {
        'x-admin-token': TOKEN,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ count, remark })
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      console.error('生成失败:', data.error || res.statusText);
      process.exit(1);
    }
    console.log(`已成功生成 ${data.codes.length} 个烧录码:`);
    for (const code of data.codes) {
      console.log(code);
    }
  } catch (e) {
    console.error(`无法连接到服务 ${BASE} (请先启动服务: npm start):`, e.message);
    process.exit(1);
  }
}

main();
