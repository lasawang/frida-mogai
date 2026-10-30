"use strict";

// anti_debug.js - 反调试绕过
// 覆盖: ptrace、TracerPid、wchan、双进程保护

(function () {
  var ptracePtr = Module.findExportByName(null, "ptrace");
  if (ptracePtr) {
    // 只短路 PTRACE_TRACEME（反调试自占位）：假装成功但不真正执行，
    // 这样 frida 的注入通道不会被 App 自己抢占。
    // 其余 ptrace 请求必须转调原函数——旧版一律返回 0 会破坏 App 自身
    // 正常的 ptrace 用法（如崩溃采集），表现为莫名卡死。
    var origPtrace = new NativeFunction(ptracePtr, "int", ["int", "int", "pointer", "pointer"]);
    Interceptor.replace(ptracePtr, new NativeCallback(function (request, pid, addr, data) {
      if (request === 0) { // PTRACE_TRACEME
        return 0;
      }
      return origPtrace(request, pid, addr, data);
    }, "int", ["int", "int", "pointer", "pointer"]));
  }

  // hook open/openat 拦截 /proc/self/status 和 /proc/self/wchan
  var openPtr = Module.findExportByName(null, "open");
  var openatPtr = Module.findExportByName(null, "openat");

  var sensitiveFiles = [
    "/proc/self/status",
    "/proc/self/wchan",
    "/proc/self/task",
  ];

  var fakeStatusFd = {};

  function isSensitivePath(path) {
    if (!path) return false;
    // 也匹配 /proc/<pid>/status、/proc/<pid>/wchan、/proc/<pid>/task/<tid>/status
    if (path.match(/\/proc\/\d+\/(task\/\d+\/)?(status|wchan)/)) return true;
    for (var i = 0; i < sensitiveFiles.length; i++) {
      if (path.indexOf(sensitiveFiles[i]) !== -1) return true;
    }
    return false;
  }

  // hook read，按 fd 类型分别篡改：
  //   status → TracerPid 改 0、State 的 t (tracing stop) 改 R (running)
  //            （进阶检测会交叉比对 State 字段，只改 TracerPid 会被识破）
  //   wchan  → ptrace_stop 改 0（旧版只标记 fd 却不改内容，等于没处理）
  // 一律等长改写并空格补齐，避免缓冲区尾部残留原字节被按长度解析出来。
  function padTo(fake, len) {
    while (fake.length < len) fake += " ";
    return fake;
  }
  var readPtr = Module.findExportByName(null, "read");
  if (readPtr) {
    Interceptor.attach(readPtr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.kind = fakeStatusFd[this.fd] || null;
      },
      onLeave: function (retval) {
        if (!this.kind || retval.toInt32() <= 0) return;
        var content = this.buf.readUtf8String(retval.toInt32());
        if (!content) return;
        if (this.kind === "status") {
          var changed = content
            .replace(/TracerPid:\s*\d+/, function (m) { return padTo("TracerPid:\t0", m.length); })
            .replace(/State:\s*t \(tracing stop\)/, function (m) { return padTo("State:\tR (running)", m.length); });
          if (changed !== content) this.buf.writeUtf8String(changed);
        } else if (this.kind === "wchan") {
          if (content.indexOf("ptrace_stop") !== -1) {
            this.buf.writeUtf8String(content.replace(/ptrace_stop/g, function (m) { return padTo("0", m.length); }));
          }
        }
      }
    });
  }

  function trackOpen(pathArg) {
    return {
      onEnter: function (args) {
        var path = args[pathArg].readUtf8String();
        if (isSensitivePath(path)) {
          this.kind = (path.indexOf("wchan") !== -1) ? "wchan" : "status";
        }
      },
      onLeave: function (retval) {
        if (this.kind && retval.toInt32() > 0) {
          fakeStatusFd[retval.toInt32()] = this.kind;
        }
      }
    };
  }

  if (openPtr) {
    Interceptor.attach(openPtr, trackOpen(0));
  }

  if (openatPtr) {
    Interceptor.attach(openatPtr, trackOpen(1));
  }

  // hook close 清理 fd 记录
  var closePtr = Module.findExportByName(null, "close");
  if (closePtr) {
    Interceptor.attach(closePtr, {
      onEnter: function (args) {
        var fd = args[0].toInt32();
        if (fakeStatusFd[fd]) {
          delete fakeStatusFd[fd];
        }
      }
    });
  }

  // 拦截 fork/clone 双进程保护
  var forkPtr = Module.findExportByName(null, "fork");
  if (forkPtr) {
    Interceptor.attach(forkPtr, {
      onLeave: function (retval) {
        // 子进程中不做处理，父进程中记录 child pid
        // 后续如果子进程 ptrace 父进程，上面的 ptrace hook 会拦截
      }
    });
  }

  // 信号类反调试：App 自发 SIGTRAP 探测——正常时信号被自己的 handler
  // 接住，被调试时先被调试器截获，以 handler 是否按预期执行来判别。
  // 对策是吞掉自发的 SIGTRAP（raise/tgkill/pthread_kill 直接假成功），
  // 让探测信号根本发不出去。注意这只针对 SIGTRAP；App 若在 release 包里
  // 有正当的 SIGTRAP 用法（极少），把 SWALLOW_SIGTRAP 改为 false 关闭。
  var SWALLOW_SIGTRAP = true;
  var SIGTRAP = 5;
  if (SWALLOW_SIGTRAP) {
    var raisePtr = Module.findExportByName(null, "raise");
    if (raisePtr) {
      var origRaise = new NativeFunction(raisePtr, "int", ["int"]);
      Interceptor.replace(raisePtr, new NativeCallback(function (sig) {
        if (sig === SIGTRAP) return 0;
        return origRaise(sig);
      }, "int", ["int"]));
    }
    var tgkillPtr = Module.findExportByName(null, "tgkill");
    if (tgkillPtr) {
      var origTgkill = new NativeFunction(tgkillPtr, "int", ["int", "int", "int"]);
      Interceptor.replace(tgkillPtr, new NativeCallback(function (tgid, tid, sig) {
        if (sig === SIGTRAP) return 0;
        return origTgkill(tgid, tid, sig);
      }, "int", ["int", "int", "int"]));
    }
  }
})();
