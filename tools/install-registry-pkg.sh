#!/bin/bash
# 把已下载的 PlatformIO registry tarball 安装进全局包目录
# registry 打包根目录通常是 package.json(+.piopm); 直接解压到 ~/.platformio/packages/<pkgname>
# 用法: tools/install-registry-pkg.sh <tarball路径>...
set -euo pipefail
DEST=~/.platformio/packages
for TARBALL in "$@"; do
  [[ -f "$TARBALL" ]] || { echo "跳过不存在的 $TARBALL"; continue; }
  # 从包内 package.json 读 name
  NAME=$(tar -xzOf "$TARBALL" package.json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).name||"")}catch{console.log("")}})')
  [[ -n "$NAME" ]] || { echo "✗ $TARBALL 无 package.json/name"; continue; }
  echo "安装 $NAME ← $(basename $TARBALL)"
  rm -rf "$DEST/$NAME"
  mkdir -p "$DEST/$NAME"
  tar -C "$DEST/$NAME" -xzf "$TARBALL"
  # 若包内没带 .piopm, 从 package.json 生成一份
  if [[ ! -f "$DEST/$NAME/.piopm" ]]; then
    node -e '
    const fs=require("fs"), path=process.argv[1];
    const pkg=JSON.parse(fs.readFileSync(path+"/package.json"));
    const meta={type:"tool", name:pkg.name, version:pkg.version,
      spec:{owner:"platformio", id:null, name:pkg.name, requirements:pkg.version, uri:null}};
    fs.writeFileSync(path+"/.piopm", JSON.stringify(meta,null,2));
    console.log("  生成 .piopm (version="+pkg.version+")");
    ' "$DEST/$NAME"
  fi
  echo "  ✓ $NAME 安装完成"
done
export PATH="$HOME/bin:$PATH"
pio pkg list --global 2>/dev/null | sed -n '/Tools/,$p'
