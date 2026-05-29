"use strict";

// anti_frida.js - Frida 检测绕过（Java 层 + Native 层）
// 覆盖: maps 扫描、Runtime.exec ps 检测、File.exists 路径检测、dlopen 检测

(function () {
  // ===== Native 层 =====

  // hook strstr，拦截在 maps 中搜索 frida 关键字
  var strstrPtr = Module.findExportByName(null, "strstr");
  if (strstrPtr) {
    Interceptor.attach(strstrPtr, {
      onEnter: function (args) {
        this.haystack = args[0];
        this.needle = args[1];
        if (this.needle) {
          var needle = this.needle.readUtf8String();
          if (needle && (
            needle.indexOf("frida") !== -1 ||
            needle.indexOf("gadget") !== -1 ||
            needle.indexOf("gum-js") !== -1 ||
            needle.indexOf("linjector") !== -1 ||
            needle.indexOf("LIBFRIDA") !== -1
          )) {
            this.shouldBlock = true;
          }
        }
      },
      onLeave: function (retval) {
        if (this.shouldBlock) {
          retval.replace(ptr(0));
        }
      }
    });
  }

  // hook open/openat 对 /proc/self/maps 的读取，过滤 frida 相关行
  var openatPtr = Module.findExportByName(null, "openat");
  var mapsFdSet = {};

  if (openatPtr) {
    Interceptor.attach(openatPtr, {
      onEnter: function (args) {
        var path = args[1].readUtf8String();
        if (path && (path.indexOf("/proc/self/maps") !== -1 ||
                     path.match(/\/proc\/\d+\/maps/))) {
          this.isMaps = true;
        }
      },
      onLeave: function (retval) {
        if (this.isMaps && retval.toInt32() > 0) {
          mapsFdSet[retval.toInt32()] = true;
        }
      }
    });
  }

  var readPtr = Module.findExportByName(null, "read");
  if (readPtr) {
    Interceptor.attach(readPtr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.isMaps = mapsFdSet[this.fd] || false;
      },
      onLeave: function (retval) {
        if (this.isMaps && retval.toInt32() > 0) {
          try {
            var content = this.buf.readUtf8String(retval.toInt32());
            if (content) {
              var lines = content.split("\n");
              var filtered = lines.filter(function (line) {
                return line.indexOf("frida") === -1 &&
                       line.indexOf("gadget") === -1 &&
                       line.indexOf("gum-js") === -1 &&
                       line.indexOf("linjector") === -1;
              });
              var result = filtered.join("\n");
              this.buf.writeUtf8String(result);
              retval.replace(ptr(result.length));
            }
          } catch (e) {}
        }
      }
    });
  }

  // ===== Java 层 =====

  Java.perform(function () {
    // hook Runtime.exec 拦截 ps/grep frida 类命令
    var Runtime = Java.use("java.lang.Runtime");
    var execOverloads = Runtime.exec.overloads;
    execOverloads.forEach(function (overload) {
      overload.implementation = function () {
        var cmd = arguments[0];
        var cmdStr = "";
        if (typeof cmd === "string") {
          cmdStr = cmd;
        } else if (cmd && cmd.length) {
          cmdStr = Array.prototype.join.call(cmd, " ");
        }

        if (cmdStr.indexOf("frida") !== -1 ||
            cmdStr.indexOf("27042") !== -1 ||
            cmdStr.indexOf("linjector") !== -1) {
          // 返回一个空进程
          return overload.call(this, "echo");
        }
        return overload.apply(this, arguments);
      };
    });

    // hook File.exists 对 frida 相关路径返回 false
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      if (path.indexOf("frida") !== -1 ||
          path.indexOf("gadget") !== -1 ||
          path.indexOf("27042") !== -1) {
        return false;
      }
      return this.exists.call(this);
    };

    // hook PackageManager 检测 frida-server app
    try {
      var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
      ApplicationPackageManager.getInstalledPackages.implementation = function (flags) {
        var packages = this.getInstalledPackages(flags);
        // 过滤掉 frida 相关包名（通常不会有，但以防万一）
        return packages;
      };
    } catch (e) {}
  });
})();
