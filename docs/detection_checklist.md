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

## 13. 补充检测面（2026-10，据小佳视频与 rusda 文复盘）

| 检测方式 | 原理一句话 | 本项目状态 |
|---------|-----------|-----------|
| so 尾页被切 | spawn 门控代码寄生在已有 so 尾页，改 RWX 时该页被切成独立 maps 段；**只要 server 在跑、任何 App 启动都中招**，与注不注入无关 | ❌ server 本体机制问题，脚本/patch 层无解；缓解：走路线 B（ZygiskFrida gadget），不用 server 的 spawn 门控 |
| libc.so 段数异常 | frida 跑过后 libc.so 映射段变多且出现 RWX 段，关 server、重启 App 都不恢复，重启手机才清 | ❌ 已知无解（360 加固等在用），只能降低使用频率、换机/重启恢复 |
| pagemap soft-dirty 位 | inline hook 写过代码页后 soft-dirty 位置位，**把字节还原也不清零**，用户态无法伪造 | ❌ 用户态无解；缓解：少用 inline hook，优先 GOT hook / replace / trace（见第 7 节策略），或内核层拦截 pagemap 读取 |
| soinfo 链表遍历 + CFI | 经 linker 加载的 so 登记在 soinfo 链，遍历可识别；把节点删掉又会与 CFI 元数据对不上 | ⚠️ 本项目未实现自定义 linker 加载（小佳路线）；gadget 模式下 gadget 本身仍在链上，靠改名降命中 |
| D-Bus AUTH 协议指纹 | 遍历本地端口发 AUTH 握手，frida 回 REJECT 即实锤；改名改端口无效 | ✅ 本项目默认 unix socket 传输、无 TCP 监听，此面不成立；**切勿改回 TCP 监听**（仅剩 /proc/net/tcp 关联查 server 进程一途，已由 0002 改名缓解） |
| TracerPid 注入窗口 | frida 注入瞬间 TracerPid 置位几百毫秒，检测卡启动窗口读一次就抓 | ✅ 用 spawn_run.py 的 spawn 流程（检测代码运行前 hook 已就位）+ anti_debug.js 的 status 改写；**避免晚 attach** |
| memfd 路径名 | Frida 17 的 maps 出现 `/memfd:frida-agent (deleted)` | ✅ topatch.py 产物后处理等长替换 memfd 名（16.x 走 0004 的文件名路线） |
| .rodata 类型名 | strings/内存扫 FridaScriptEngine、GumScript 等明文 | ✅ topatch.py 等长反转（rusda 式），只动 .rodata |
| GOT 表校验 | 检测方查 GOT 中关键函数地址是否仍落在原 libc 范围，GOT hook 也会现形 | ⚠️ 策略提示：GOT hook 不是免费的，关键函数少而精；被查时换 trace 或内核路线 |
| unix socket 名全量扫描 | 网传扫 /proc/net/unix 找 frida 的 IPC 名 | ✅ 澄清：普通 App 受 SELinux/权限限制读不到全量 unix 名，且本项目 socket 名已伪装（org.chromium.cache_lock）；此面主要在系统/root 视角才成立 |
| Java API 变 Native | frida-java-bridge 把被 hook 的 Java 方法改成 native 实现，查方法类型即露；另 libart 函数头被 inline hook（LDR+BR） | ⚠️ 策略提示：能用 native 层就别用 Java.perform；必须用时先按第 3 节方法论定位并掐掉检测线程 |

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
