# 常见问题排查

## 编译问题

### Q: build.sh 报错 "meson not found"
安装 meson 和 ninja：
```bash
pip3 install meson
brew install ninja  # macOS
# 或 apt install ninja-build  # Linux
```

### Q: patch apply 失败 "does not apply"
frida 版本更新后源码结构可能变化。解决方案：
1. 确认 frida 版本与 patch 匹配（当前 patch 基于 16.x）
2. 手动定位对应文件，参考 patch 内容手工修改
3. 用 `git apply --reject` 查看哪些 hunk 失败，手动合并 .rej 文件

### Q: 编译 android-arm64 报错缺少 NDK
```bash
# 设置 ANDROID_NDK_ROOT 环境变量
export ANDROID_NDK_ROOT=/path/to/android-ndk-r25c
# frida 要求 NDK r25 或更高版本
```

### Q: 编译耗时过长
首次编译约 30-60 分钟（取决于机器配置）。建议：
- 使用 16 核以上机器
- 确保 SSD 和充足内存（至少 16GB）
- 后续增量编译会快很多

---

## 运行问题

### Q: server 推送后无法启动
```bash
# 检查权限
adb shell chmod 755 /data/local/tmp/hlserver
# 检查 SELinux
adb shell getenforce
adb shell setenforce 0  # 临时关闭（需 root）
# 检查架构
adb shell file /data/local/tmp/hlserver
```

### Q: frida 客户端连不上魔改 server
魔改后 frida:rpc 协议标识已变，需要同步修改客户端的 frida-core：
- 方案一：客户端也用同一套 patch 编译 frida-tools
- 方案二：只改 server 端的非协议部分（0002-0007），保留 0001 不改

**重要**：patch 0001 (frida:rpc) 如果改了，客户端必须同步改，否则握手失败。建议只在对抗 L3 协议探测时才改 0001。

### Q: ZygiskFrida gadget 注入后 APP 闪退
1. 检查 gadget so 架构是否匹配（arm64 APP 用 arm64 gadget）
2. 检查 config.json 配置是否正确
3. 查看 logcat：`adb logcat | grep -i "gadget\|frida\|zygisk"`
4. 尝试 `"interaction": "wait"` 模式，手动 attach 排查

### Q: 加载 bypass 脚本后 APP 仍然检测到
按以下顺序排查：
1. `strings hlserver | grep -ic frida` — 确认编译产物干净
2. 检查是否用了默认端口 27042
3. 检查 /proc/self/task/*/comm 是否有残留线程名
4. 用 `frida-trace -i "open*" -i "access"` 看 APP 在访问什么路径
5. 用 `frida-trace -i "connect"` 看 APP 在探测什么端口

---

## 脚本问题

### Q: anti_debug.js 导致 APP 卡死
ptrace hook 可能影响 APP 自身的调试逻辑。尝试：
- 只 hook PTRACE_TRACEME (request == 0)，不拦截其他 ptrace 操作
- 用 spawn 模式 (`frida -f`) 在 APP 初始化前注入

### Q: ssl_pinning.js 对某些 APP 无效
可能原因：
- APP 使用了自定义 TLS 库（非系统 SSLContext）
- Flutter APP 用 BoringSSL，需要额外 hook libflutter.so
- 某些 APP 在 native 层做 pinning，需要定位具体 so

### Q: syscall_hook.js 开销太大导致 APP 卡顿
syscall hook 会拦截大量系统调用。优化方案：
- 只在检测窗口期启用（APP 启动后 5 秒内）
- 缩小 hook 范围，只拦截特定 fd 的 read
- 用 `Interceptor.replace` 代替 `Interceptor.attach`

---

## 对抗升级

### Q: 加固方更新后之前的方案失效
1. 用 `frida-trace` 重新定位检测点
2. 检查是否有新的特征串被加入检测
3. 重新运行 `randomize.py` 生成新的随机串，重新编译
4. 查看加固方是否增加了新的检测维度（参考 detection_checklist.md）

### Q: APP 使用了 CNTVCT_EL0 寄存器计时
这是 ARM64 用户态可直接读取的计时寄存器，无法通过 hook 拦截。解决方案：
- IDA 逆向定位读取 CNTVCT_EL0 的指令（`mrs x0, CNTVCT_EL0`）
- 直接 patch APP 的 so 文件，nop 掉或改为固定值
- 或者 hook 检测结果的判断逻辑，而不是计时本身

### Q: APP 使用了 seccomp 限制 syscall
seccomp 会阻止 frida 的某些操作。解决方案：
- 在 seccomp 安装前注入（spawn 模式 + 早期 hook）
- hook `prctl` 或 `seccomp` syscall，阻止 seccomp 规则安装
- 用 ZygiskFrida 在 zygote 阶段注入，早于 APP 的 seccomp 设置
