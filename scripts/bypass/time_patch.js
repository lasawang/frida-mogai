"use strict";

// time_patch.js - 时间差检测绕过
// hook clock_gettime/gettimeofday，压缩被测函数执行期间的时间差

(function () {
  var CLOCK_REALTIME = 0;
  var CLOCK_MONOTONIC = 1;
  var CLOCK_BOOTTIME = 7;

  // 时间偏移累积量（纳秒）
  var timeOffsetNs = 0;
  // 是否处于"被监控"状态
  var monitoring = false;
  // 每次 hook 调用增加的最大时间（模拟正常执行开销）
  var MAX_HOOK_OVERHEAD_NS = 500; // 500ns，正常函数调用级别

  // hook clock_gettime
  var clockGettimePtr = Module.findExportByName("libc.so", "clock_gettime");
  if (clockGettimePtr) {
    Interceptor.attach(clockGettimePtr, {
      onEnter: function (args) {
        this.clockId = args[0].toInt32();
        this.tp = args[1];
      },
      onLeave: function (retval) {
        if (retval.toInt32() !== 0) return;
        if (this.clockId === CLOCK_REALTIME ||
            this.clockId === CLOCK_MONOTONIC ||
            this.clockId === CLOCK_BOOTTIME) {
          if (timeOffsetNs > 0) {
            // 读取当前 timespec
            var sec = this.tp.readS64();
            var nsec = this.tp.add(8).readS64();

            // 减去累积偏移
            var totalNs = sec * 1000000000 + nsec - timeOffsetNs;
            if (totalNs < 0) totalNs = 0;

            var newSec = Math.floor(totalNs / 1000000000);
            var newNsec = totalNs % 1000000000;

            this.tp.writeS64(newSec);
            this.tp.add(8).writeS64(newNsec);
          }
        }
      }
    });
  }

  // hook gettimeofday
  var gettimeofdayPtr = Module.findExportByName("libc.so", "gettimeofday");
  if (gettimeofdayPtr) {
    Interceptor.attach(gettimeofdayPtr, {
      onEnter: function (args) {
        this.tv = args[0];
      },
      onLeave: function (retval) {
        if (retval.toInt32() !== 0) return;
        if (timeOffsetNs > 0 && this.tv && !this.tv.isNull()) {
          var sec = this.tv.readS64();
          var usec = this.tv.add(8).readS64();

          var totalUs = sec * 1000000 + usec - Math.floor(timeOffsetNs / 1000);
          if (totalUs < 0) totalUs = 0;

          var newSec = Math.floor(totalUs / 1000000);
          var newUsec = totalUs % 1000000;

          this.tv.writeS64(newSec);
          this.tv.add(8).writeS64(newUsec);
        }
      }
    });
  }

  // 提供接口：在 hook 关键函数前后调用，累积时间偏移
  // 用法：在 Interceptor.attach 的 onEnter 中调用 startTiming()
  //       在 onLeave 中调用 stopTiming(elapsedNs)
  //       其中 elapsedNs 是 hook 逻辑实际消耗的时间

  function addOffset(ns) {
    if (ns > MAX_HOOK_OVERHEAD_NS) {
      timeOffsetNs += (ns - MAX_HOOK_OVERHEAD_NS);
    }
  }

  function resetOffset() {
    timeOffsetNs = 0;
  }

  function getOffset() {
    return timeOffsetNs;
  }

  // 导出接口
  if (typeof globalThis !== "undefined") {
    globalThis.TimePatch = {
      addOffset: addOffset,
      resetOffset: resetOffset,
      getOffset: getOffset,
    };
  }
})();
