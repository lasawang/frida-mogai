# Frida 反检测十二类检测对照表

## 检测分级

| 级别 | 描述 | 典型代表 |
|------|------|---------|
| L1 | 基础检测（文件/进程/端口） | 自研简单检测 |
| L2 | 内存特征 + 线程扫描 | 梆梆、爱加密基础版 |
| L3 | 协议探测 + syscall 直调 | 梆梆企业版、数字联盟 |
| L4 | 行为分析 + 完整性校验 + 时间差 | 顶象、同盾 |

---

## 1. 文件系统层检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| 扫描 /data/local/tmp/frida-server | server 改名 + 换路径 | build.sh (输出改名) |
| 扫描 /data/local/tmp/re.frida.server | patch 改 D-Bus 名 | patches/frida-core/0002 |
| 检测 frida-agent*.so 文件 | patch 改 agent 文件名 | patches/frida-core/0004 |
| 扫描 Magisk 模块目录 | 用 ZygiskFrida 不落地 | zygisk/config.json |

## 2. 进程层检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| ps 列表搜索 frida-server | prctl 改进程名 | patches/frida-core/0002 |
| /proc/pid/cmdline 读取 | patch 改 cmdline | patches/frida-core/0002 |
| /proc/pid/comm 读取 | prctl(PR_SET_NAME) | patches/frida-core/0002 |
| Java Runtime.exec("ps") | hook Runtime.exec | scripts/bypass/anti_frida.js |

## 3. 端口层检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| 扫描 27042 默认端口 | 启动时 -l 127.0.0.1:随机端口 | build.sh (使用说明) |
| connect 探测本地端口 | 用 USB transport 或 unix socket | - |
| 端口握手协议识别 | patch 协议响应 | patches/frida-core/0008 |

## 4. 内存特征检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| /proc/self/maps 搜索 "frida" | patch agent so 名 + maps hook | patches/0004 + scripts/anti_frida.js |
| 内存搜索 "frida:rpc" | patch 协议标识 | patches/frida-core/0001 |
| 内存搜索 "LIBFRIDA" | patch gum 模块名 | patches/frida-gum/0001 |
| 内存搜索 "linjector" | patch 管道名 | patches/frida-core/0003 |
| dlsym 查找 frida_agent_main | patch 导出符号 | patches/frida-core/0005 |
| 内存搜索 "GumScript" | patch gum 字符串 | patches/frida-gum/0001 |

## 5. 线程层检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| /proc/self/task/*/comm 搜索 "gum-js-loop" | patch 线程名 | patches/frida-core/0006 + frida-gum/0002 |
| 搜索 "gmain" 线程 | patch 线程名 | patches/frida-core/0007 + frida-gum/0002 |
| 搜索 "gdbus" 线程 | patch 线程名 | patches/frida-core/0007 |
| 搜索 "pool-frida" 线程 | patch 线程池名 | patches/frida-core/0007 + frida-gum/0002 |

## 6. 反调试检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| ptrace(PTRACE_TRACEME) 自占位 | hook ptrace 返回 0 | scripts/bypass/anti_debug.js |
| 读取 /proc/self/status TracerPid | hook read 篡改 | scripts/bypass/anti_debug.js |
| /proc/self/wchan 检测 | hook read | scripts/bypass/anti_debug.js |
| fork + ptrace 双进程保护 | hook fork + ptrace | scripts/bypass/anti_debug.js |
| Debug.isDebuggerConnected() | Java hook | scripts/bypass/anti_frida.js |

## 7. 模块完整性检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| .text 段 CRC 校验 | 用 Interceptor.replace 代替 attach | - (使用策略) |
| inline hook 检测（首字节比对） | 用 Stalker 或 GOT hook | - (使用策略) |
| so 文件 hash 校验 | patch APP 的校验函数 | - (需逆向定位) |

## 8. 系统调用层检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| 直接 svc #0 调用 openat 读 maps | hook svc 指令地址 | scripts/bypass/syscall_hook.js |
| svc 调用 readlinkat 读 /proc/self/fd | hook readlinkat | scripts/bypass/syscall_hook.js |
| svc 调用 faccessat 检测文件 | hook access | scripts/bypass/syscall_hook.js |
| 绕过 libc wrapper 直接 syscall | Stalker 跟踪 svc 指令 | - (需 Stalker 脚本) |

## 9. Java 层检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| Runtime.exec 执行 ps/cat maps | hook Runtime.exec | scripts/bypass/anti_frida.js |
| File.exists 检测 frida 路径 | hook File.exists | scripts/bypass/anti_frida.js |
| PackageManager 检测 root 包 | hook getPackageInfo | scripts/bypass/anti_root.js |
| Build.TAGS 检测 test-keys | 修改 Build.TAGS | scripts/bypass/anti_root.js |
| Settings.Secure 检测 ADB | hook getString | scripts/bypass/anti_root.js |

## 10. 协议主动探测（关键）

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| 连接端口发送非 frida 协议数据 | patch: 非预期协议直接断连 | patches/frida-core/0008 |
| D-Bus AUTH 握手特征识别 | patch D-Bus 服务名 | patches/frida-core/0001 + 0002 |
| 分析错误响应 "Unexpected command" | patch: 不返回错误信息 | patches/frida-core/0008 |

## 11. 时间差检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| clock_gettime 前后对比 | hook clock_gettime 压缩时间 | scripts/bypass/time_patch.js |
| gettimeofday 计时 | hook gettimeofday | scripts/bypass/time_patch.js |
| CNTVCT_EL0 寄存器读取 | 无法 hook，需 patch APP | - (需逆向) |
| 函数执行耗时异常判断 | 用 replace 代替 attach 降低开销 | - (使用策略) |

## 12. 行为/环境检测

| 检测方式 | 绕过手段 | 对应文件 |
|---------|---------|---------|
| root 环境检测 | Magisk DenyList + Shamiko | scripts/bypass/anti_root.js |
| 模拟器检测 | 使用真机 | - |
| USB 调试状态检测 | hook Settings.Secure | scripts/bypass/anti_root.js |
| Magisk 存在性检测 | Shamiko + 隐藏包名 | scripts/bypass/anti_root.js |
| SELinux 状态检测 | hook getenforce | scripts/bypass/anti_root.js |

---

## 快速排查流程

```
APP 闪退/检测到 frida？
│
├─ strings server | grep -i frida → 有结果？→ patch 没生效，重新编译
│
├─ 用 ZygiskFrida gadget 模式 → 还检测到？
│   ├─ 是 → 不是进程/端口问题，看内存/线程/协议
│   └─ 否 → 之前是进程/端口层检测
│
├─ 加载 anti_frida.js → 还检测到？
│   ├─ 是 → 不是 Java 层，看 native/syscall
│   └─ 否 → Java 层检测，脚本已覆盖
│
├─ 加载 syscall_hook.js → 还检测到？
│   ├─ 是 → 可能是 inline hook 检测或时间差
│   └─ 否 → syscall 直调检测，已覆盖
│
└─ 以上都不行 → 用 IDA 逆向定位检测函数，直接 patch
```
