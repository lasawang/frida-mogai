"use strict";

// loader.js - 脚本加载器
// 按需加载 bypass 脚本，支持选择性启用

(function () {
  var SCRIPTS = {
    anti_debug: "bypass/anti_debug.js",
    anti_frida: "bypass/anti_frida.js",
    anti_root: "bypass/anti_root.js",
    ssl_pinning: "bypass/ssl_pinning.js",
    syscall_hook: "bypass/syscall_hook.js",
    time_patch: "bypass/time_patch.js",
  };

  // 默认全部加载的配置
  var DEFAULT_CONFIG = {
    anti_debug: true,
    anti_frida: true,
    anti_root: true,
    ssl_pinning: true,
    syscall_hook: false,  // syscall hook 开销较大，按需开启
    time_patch: false,    // 时间 patch 需要配合具体场景
  };

  function loadScript(name) {
    if (!SCRIPTS[name]) {
      console.log("[Loader] Unknown script: " + name);
      return false;
    }
    try {
      var scriptPath = SCRIPTS[name];
      console.log("[Loader] Loading: " + name + " (" + scriptPath + ")");
      // 在 frida CLI 中使用时，脚本已经被合并加载
      // 此 loader 主要用于文档和配置管理
      return true;
    } catch (e) {
      console.log("[Loader] Failed to load " + name + ": " + e.message);
      return false;
    }
  }

  function loadAll(config) {
    config = config || DEFAULT_CONFIG;
    var loaded = [];
    var skipped = [];

    Object.keys(config).forEach(function (name) {
      if (config[name]) {
        if (loadScript(name)) {
          loaded.push(name);
        }
      } else {
        skipped.push(name);
      }
    });

    console.log("[Loader] Loaded: " + loaded.join(", "));
    if (skipped.length > 0) {
      console.log("[Loader] Skipped: " + skipped.join(", "));
    }
  }

  // 导出接口
  if (typeof globalThis !== "undefined") {
    globalThis.BypassLoader = {
      loadScript: loadScript,
      loadAll: loadAll,
      scripts: SCRIPTS,
      defaultConfig: DEFAULT_CONFIG,
    };
  }

  // 使用说明:
  // 方式一：合并加载（推荐）
  //   frida -U -f com.target.app -l anti_debug.js -l anti_frida.js -l ssl_pinning.js
  //
  // 方式二：使用 frida-compile 打包
  //   frida-compile loader.js -o bundle.js
  //   frida -U -f com.target.app -l bundle.js
  //
  // 方式三：在 Python 脚本中按需加载
  //   script = session.create_script(open("anti_debug.js").read() + open("ssl_pinning.js").read())
})();
