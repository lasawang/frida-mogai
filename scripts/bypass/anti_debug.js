"use strict";

// anti_debug.js - 反调试绕过
// 覆盖: ptrace、TracerPid、wchan、双进程保护

(function () {
  var ptracePtr = Module.findExportByName(null, "ptrace");
  if (ptracePtr) {
    Interceptor.replace(ptracePtr, new NativeCallback(function (request, pid, addr, data) {
      if (request === 0) { // PTRACE_TRACEME
        return 0;
      }
      return 0;
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
    for (var i = 0; i < sensitiveFiles.length; i++) {
      if (path.indexOf(sensitiveFiles[i]) !== -1) return true;
      // 也匹配 /proc/<pid>/status 格式
      if (path.match(/\/proc\/\d+\/status/) || path.match(/\/proc\/\d+\/wchan/)) return true;
    }
    return false;
  }

  // hook read，当读取 status 文件时篡改 TracerPid
  var readPtr = Module.findExportByName(null, "read");
  if (readPtr) {
    Interceptor.attach(readPtr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.isFake = fakeStatusFd[this.fd] || false;
      },
      onLeave: function (retval) {
        if (this.isFake && retval.toInt32() > 0) {
          var content = this.buf.readUtf8String(retval.toInt32());
          if (content && content.indexOf("TracerPid:") !== -1) {
            content = content.replace(/TracerPid:\s*\d+/, "TracerPid:\t0");
            this.buf.writeUtf8String(content);
          }
        }
      }
    });
  }

  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) {
        var path = args[0].readUtf8String();
        if (isSensitivePath(path)) {
          this.markFd = true;
        }
      },
      onLeave: function (retval) {
        if (this.markFd && retval.toInt32() > 0) {
          fakeStatusFd[retval.toInt32()] = true;
        }
      }
    });
  }

  if (openatPtr) {
    Interceptor.attach(openatPtr, {
      onEnter: function (args) {
        var path = args[1].readUtf8String();
        if (isSensitivePath(path)) {
          this.markFd = true;
        }
      },
      onLeave: function (retval) {
        if (this.markFd && retval.toInt32() > 0) {
          fakeStatusFd[retval.toInt32()] = true;
        }
      }
    });
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
})();
