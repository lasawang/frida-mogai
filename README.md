# Frida 魔改反检测工具集

自动化编译魔改 Frida，覆盖十二类检测绕过。已验证可稳定绕过知乎(com.zhihu.android)的 libflipped.so 反检测 SDK（10分钟+存活）。

## 快速开始（已验证配置）

```bash
# 1. 编译（源码已 patch，直接 ninja）
cd frida_src
PATH="$PWD/deps/toolchain-macos-arm64/bin:$PATH" ninja -C build subprojects/frida-core/server/frida-server

# 2. 部署到设备（使用 unix socket 避免端口扫描检测）
./deploy.sh all

# 3. Python 连接
import frida
device = frida.get_device_manager().add_remote_device('127.0.0.1:38502')
pid = device.spawn(['com.zhihu.android'])
session = device.attach(pid)
# 加载 hide_all3.js 后 resume
device.resume(pid)

# 4. 存活测试
python3 test_zhihu.py 300   # 测试 300 秒存活
```

## 项目结构

```
├── deploy.sh                 # 一键部署脚本（push/start/forward/verify）
├── build.sh                  # 自动化编译脚本（从零开始用）
├── test_zhihu.py             # 知乎存活测试
├── patch_binary_libs.py      # 二进制 patch GLib/GIO 静态库（线程名）
├── randomize.py              # patch 随机化引擎
├── patches_applied/          # 当前已应用的 git diff 导出
│   ├── frida-core-all.patch  # frida-core 全部源码修改
│   └── frida-gum-all.patch   # frida-gum 全部源码修改
├── frida_src/                # 已 patch 的 frida 源码树
│   ├── build/                # ninja 编译产物
│   └── deps/                 # 工具链 + SDK（含已 patch 的 .a）
├── patches/                  # 模板 patch（用于 randomize.py）
├── scripts/bypass/           # 运行时绕过脚本
└── docs/
```

## 已验证的修改清单（知乎 bypass）

### 源码修改（frida-core）

| 文件 | 修改 | 目的 |
|------|------|------|
| `server/server.vala` | DEFAULT_DIRECTORY = "org.chromium.native_lib" | agent 路径伪装 |
| `src/linux/system-linux.c` | tmp 目录 → `/data/user/0` | 真实文件系统(fd:46)避免 tmpfs 检测 |
| `lib/pipe/pipe-unix.c` | FRIDA_TEMP_PATH → `/data/user/0` | 管道路径一致 |
| `lib/agent/agent-glue.c` | 入口符号 → `lhmcxr5kdhjpn5` | 隐藏导出符号 |
| `lib/agent/frida-agent.version` | 导出符号名随机化 | 同上 |
| 多个 .vala 文件 | `frida:rpc` → `xrpc:rx` 等 | 协议特征隐藏 |

### 源码修改（frida-gum）

| 文件 | 修改 | 目的 |
|------|------|------|
| `gumscriptscheduler.c` | JS线程名 → "Binder:Idle" | 线程名检测 |
| `runtime/message-dispatcher.js` | 协议标识替换 | 内存特征 |

### 二进制 Patch（预编译 .a 库）

| 库文件 | 修改 | 目的 |
|--------|------|------|
| `libglib-2.0.a` | "gmain" → "htrim" | GLib 主循环线程名 |
| `libglib-2.0.a` | "pool-%s" → "tsk0-%s" | 线程池线程名 |
| `libgio-2.0.a` | "gdbus" → "atsvc" | D-Bus 线程名 |

### 运行时脚本（/tmp/hide_all3.js）

- hook `prctl(PR_SET_NAME)` 拦截未来线程命名
- hook `pthread_setname_np` 同上
- 延迟扫描重命名已存在的可疑线程

### 部署配置

- 传输方式: Unix domain socket (`-l unix:org.chromium.cache_lock`)
- 端口转发: `adb forward tcp:38502 localabstract:org.chromium.cache_lock`
- 无 TCP 端口暴露，避免 /proc/net/tcp 扫描

## 三种使用路线

**路线 A：日常使用**
直接用编译产出的 server，配合 bypass 脚本。覆盖 90% 场景。

**路线 B：ZygiskFrida gadget 模式（推荐）**
零进程/零端口痕迹，最隐蔽：
```bash
# 将 gadget 放入 ZygiskFrida 模块
cp build/output/hlgadget-arm64.so /path/to/zygisk-module/
# 配置 target app
vim zygisk/config.json
```

**路线 C：硬骨头 APP**
魔改 frida + ZygiskFrida + IDA patch + Stalker，组合拳。

## Patch 覆盖范围

| # | Patch | 对抗检测 |
|---|-------|---------|
| 0001 | frida:rpc 协议标识 | 内存特征 + 协议探测 |
| 0002 | D-Bus 服务名 + 进程名 | 进程层 |
| 0003 | linjector 管道名 | 内存特征 |
| 0004 | agent so 文件名 | 内存特征 + 文件系统 |
| 0005 | 导出符号名 | 内存特征 |
| 0006 | gum-js-loop 线程名 | 线程层 |
| 0007 | gmain/gdbus/pool 线程名 | 线程层 |
| 0008 | 协议响应静默关闭 | 协议主动探测 |

## 注意事项

1. **patch 0001 改了客户端也要改** — frida:rpc 是客户端和 server 的握手协议，改了 server 端客户端连不上。只在对抗 L3 协议探测时才改。
2. **每次编译用新随机串** — `randomize.py` 每次运行产出不同值，不要复用上次的编译产物。
3. **优先用 ZygiskFrida** — gadget 注入无进程无端口，比 server 模式安全得多。
4. **spawn 模式优先** — `frida -f` 在 APP 初始化前注入，早于大多数检测点。

## 依赖

- Python 3.6+
- Git
- Node.js + npm
- Meson + Ninja
- Android NDK r25+（编译 Android 目标）

## 参考项目

- [strongR-frida-android](https://github.com/hzzheyang/strongR-frida-android)
- [Florida](https://github.com/Ylarod/Florida)
- [ZygiskFrida](https://github.com/lico-n/ZygiskFrida)
- [AAAA-Project/Patchs](https://github.com/AAAA-Project/Patchs)
