#!/usr/bin/env python3
"""知乎反检测存活测试"""
import frida
import time
import sys

REMOTE = '127.0.0.1:38502'
TARGET = 'com.zhihu.android'
HIDE_SCRIPT = '/tmp/hide_all3.js'
DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 60

device = frida.get_device_manager().add_remote_device(REMOTE)
print(f'[*] Connected to {REMOTE}')

pid = device.spawn([TARGET])
print(f'[*] Spawned {TARGET} PID: {pid}')

session = device.attach(pid)

with open(HIDE_SCRIPT) as f:
    code = f.read()

code += '''
Java.perform(function() {
    var Activity = Java.use('android.app.Activity');
    Activity.onResume.implementation = function() {
        console.log('onResume: ' + this.getClass().getName());
        this.onResume();
    };
});
'''

script = session.create_script(code)
script.on('message', lambda msg, _: print(f'  [{msg["type"]}] {msg.get("payload","")}'))
script.load()
device.resume(pid)
print(f'[*] Resumed. Testing {DURATION}s survival...')

start = time.time()
while True:
    time.sleep(5)
    elapsed = int(time.time() - start)
    try:
        alive = any(p.pid == pid for p in device.enumerate_processes())
        if not alive:
            print(f'[!] DEAD after {elapsed}s')
            sys.exit(1)
        print(f'  {elapsed}s alive')
    except Exception as e:
        print(f'[!] DEAD after {elapsed}s - {e}')
        sys.exit(1)
    if elapsed >= DURATION:
        print(f'[+] SUCCESS: survived {DURATION}s')
        sys.exit(0)
