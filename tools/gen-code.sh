#!/bin/bash
# 生成本地测试烧录码: tools/gen-code.sh [数量]
# ADMIN_TOKEN 与 server 启动环境变量一致 (默认 local-admin-token-change-me)
set -euo pipefail
BASE="${BASE:-http://localhost:8787}"
TOKEN="${ADMIN_TOKEN:-local-admin-token-change-me}"
COUNT="${1:-3}"

curl -sS -X POST "$BASE/api/admin/codes" \
  -H "x-admin-token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"count\": $COUNT, \"remark\": \"local test\"}" \
| node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s); if(!j.codes){console.error("生成失败:",j);process.exit(1)} console.log(j.codes.join("\n"))})'
