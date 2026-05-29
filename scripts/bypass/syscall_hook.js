"use strict";

// syscall_hook.js - 系统调用层 hook
// 直接 hook svc #0 指令或 libc wrapper，拦截 openat/readlinkat/stat 等关键 syscall

(function () {
  var SYSCALL_OPENAT = 56;       // __NR_openat (arm64)
  var SYSCALL_READLINKAT = 78;   // __NR_readlinkat (arm64)
  var SYSCALL_FACCESSAT = 48;    // __NR_faccessat (arm64)

  var fridaKeywords = [
    "frida", "gadget", "gum-js", "linjector",
    "27042", "re.frida.server", "LIBFRIDA"
  ];

  function containsFridaKeyword(str) {
    if (!str) return false;
    var lower = str.toLowerCase();
    for (var i = 0; i < fridaKeywords.length; i++) {
      if (lower.indexOf(fridaKeywords[i]) !== -1) return true;
    }
    return false;
  }

  // hook openat - 最常用的文件访问 syscall
  var openatPtr = Module.findExportByName("libc.so", "openat");
  if (openatPtr) {
    Interceptor.attach(openatPtr, {
      onEnter: function (args) {
        var path = args[1].readUtf8String();
        if (containsFridaKeyword(path)) {
          this.fakePath = Memory.allocUtf8String("/dev/null");
          args[1] = this.fakePath;
        }
      }
    });
  }

  // hook readlinkat - 用于读取 /proc/self/exe、/proc/self/fd/N
  var readlinkatPtr = Module.findExportByName("libc.so", "readlinkat");
  if (readlinkatPtr) {
    Interceptor.attach(readlinkatPtr, {
      onEnter: function (args) {
        this.buf = args[2];
        this.bufsiz = args[3].toInt32();
        var path = args[1].readUtf8String();
        if (path && path.indexOf("/proc/") !== -1) {
          this.checkResult = true;
        }
      },
      onLeave: function (retval) {
        if (this.checkResult && retval.toInt32() > 0) {
          try {
            var result = this.buf.readUtf8String(retval.toInt32());
            if (containsFridaKeyword(result)) {
              // 替换为无害路径
              var fake = "/system/lib64/libc.so";
              this.buf.writeUtf8String(fake);
              retval.replace(ptr(fake.length));
            }
          } catch (e) {}
        }
      }
    });
  }

  // hook access/faccessat - 检测文件是否存在
  var accessPtr = Module.findExportByName("libc.so", "access");
  if (accessPtr) {
    Interceptor.attach(accessPtr, {
      onEnter: function (args) {
        var path = args[0].readUtf8String();
        if (containsFridaKeyword(path)) {
          this.block = true;
        }
      },
      onLeave: function (retval) {
        if (this.block) {
          retval.replace(ptr(-1));
        }
      }
    });
  }

  // hook stat/lstat - 文件状态检测
  var statPtr = Module.findExportByName("libc.so", "stat");
  var lstatPtr = Module.findExportByName("libc.so", "lstat");

  function hookStat(funcPtr) {
    if (!funcPtr) return;
    Interceptor.attach(funcPtr, {
      onEnter: function (args) {
        var path = args[0].readUtf8String();
        if (containsFridaKeyword(path)) {
          this.block = true;
        }
      },
      onLeave: function (retval) {
        if (this.block) {
          retval.replace(ptr(-1));
        }
      }
    });
  }

  hookStat(statPtr);
  hookStat(lstatPtr);

  // 扫描 .text 段中的 svc #0 指令（ARM64: 0xD4000001）
  // 用于定位直接 syscall 调用点
  function findSvcInstructions(moduleName) {
    var mod = Process.findModuleByName(moduleName);
    if (!mod) return [];

    var results = [];
    var SVC_OPCODE = 0x01000000 | (0 << 5); // svc #0 = D4000001
    var base = mod.base;
    var size = mod.size;

    Memory.scan(base, size, "01 00 00 D4", {
      onMatch: function (address, size) {
        results.push(address);
      },
      onComplete: function () {}
    });

    return results;
  }

  // 导出扫描函数供外部调用
  if (typeof globalThis !== "undefined") {
    globalThis.findSvcInstructions = findSvcInstructions;
  }
})();
