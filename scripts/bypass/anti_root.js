"use strict";

// anti_root.js - Root 检测绕过
// 覆盖: su 路径检测、Magisk 路径检测、getprop 检测、shell 命令检测

(function () {
  var rootPaths = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
    "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
    "/system/etc/init.d/99SuperSUDaemon",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/system/xbin/daemonsu",
    "/system/xbin/busybox",
    "/sbin/magisk", "/sbin/.magisk",
    "/data/adb/magisk", "/data/adb/modules",
    "/cache/magisk.log",
    "/data/user_de/0/com.topjohnwu.magisk",
  ];

  var rootPackages = [
    "com.topjohnwu.magisk",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "com.yellowes.su",
  ];

  var rootProps = [
    "ro.build.selinux",
    "ro.debuggable",
    "service.adb.root",
    "ro.secure",
  ];

  // === Native 层 ===

  // hook access
  var accessPtr = Module.findExportByName("libc.so", "access");
  if (accessPtr) {
    Interceptor.attach(accessPtr, {
      onEnter: function (args) {
        var path = args[0].readUtf8String();
        if (path) {
          for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
              this.block = true;
              break;
            }
          }
        }
      },
      onLeave: function (retval) {
        if (this.block) {
          retval.replace(ptr(-1));
        }
      }
    });
  }

  // hook fopen
  var fopenPtr = Module.findExportByName("libc.so", "fopen");
  if (fopenPtr) {
    Interceptor.attach(fopenPtr, {
      onEnter: function (args) {
        var path = args[0].readUtf8String();
        if (path) {
          for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
              this.block = true;
              break;
            }
          }
        }
      },
      onLeave: function (retval) {
        if (this.block) {
          retval.replace(ptr(0));
        }
      }
    });
  }

  // hook __system_property_get
  var sysPropGetPtr = Module.findExportByName("libc.so", "__system_property_get");
  if (sysPropGetPtr) {
    Interceptor.attach(sysPropGetPtr, {
      onEnter: function (args) {
        this.name = args[0].readUtf8String();
        this.value = args[1];
      },
      onLeave: function (retval) {
        if (!this.name) return;
        if (this.name === "ro.debuggable") {
          this.value.writeUtf8String("0");
        } else if (this.name === "service.adb.root") {
          this.value.writeUtf8String("0");
        } else if (this.name === "ro.secure") {
          this.value.writeUtf8String("1");
        } else if (this.name === "ro.build.tags") {
          this.value.writeUtf8String("release-keys");
        }
      }
    });
  }

  // === Java 层 ===

  Java.perform(function () {
    // hook File.exists
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      for (var i = 0; i < rootPaths.length; i++) {
        if (path.indexOf(rootPaths[i]) !== -1) {
          return false;
        }
      }
      return this.exists.call(this);
    };

    // hook File.canRead / canWrite / canExecute
    var checkMethods = ["canRead", "canWrite", "canExecute"];
    checkMethods.forEach(function (method) {
      File[method].implementation = function () {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
          if (path.indexOf(rootPaths[i]) !== -1) {
            return false;
          }
        }
        return this[method].call(this);
      };
    });

    // hook Runtime.exec 拦截 which su / id 等命令
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

        if (cmdStr.indexOf("su") !== -1 ||
            cmdStr.indexOf("which") !== -1 ||
            cmdStr.indexOf("busybox") !== -1 ||
            cmdStr.indexOf("magisk") !== -1) {
          return overload.call(this, "echo");
        }
        return overload.apply(this, arguments);
      };
    });

    // hook PackageManager 隐藏 root 相关包
    try {
      var PackageManager = Java.use("android.app.ApplicationPackageManager");
      PackageManager.getPackageInfo.overload("java.lang.String", "int").implementation = function (packageName, flags) {
        for (var i = 0; i < rootPackages.length; i++) {
          if (packageName === rootPackages[i]) {
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(packageName);
          }
        }
        return this.getPackageInfo(packageName, flags);
      };
    } catch (e) {}

    // hook Build.TAGS
    try {
      var Build = Java.use("android.os.Build");
      Build.TAGS.value = "release-keys";
    } catch (e) {}

    // hook Settings.Secure (开发者选项检测)
    try {
      var Settings = Java.use("android.provider.Settings$Secure");
      Settings.getString.implementation = function (resolver, name) {
        if (name === "adb_enabled") {
          return "0";
        }
        return this.getString(resolver, name);
      };
    } catch (e) {}
  });
})();
