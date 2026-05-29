#!/bin/bash
# 魔改 Frida 一键部署脚本
# 用法: ./deploy.sh [push|start|forward|all]
set -e

FRIDA_SRC="/Volumes/Shared/ai_reverse/frida_mogai/frida_src"
SERVER_BIN="$FRIDA_SRC/build/subprojects/frida-core/server/frida-server"
REMOTE_TMP="/data/local/tmp/hluda-tmp"
REMOTE_BIN="/dev/hluda"
SOCKET_NAME="org.chromium.cache_lock"
LOCAL_PORT=38502

push() {
    echo "[*] Pushing frida-server to device..."
    adb push "$SERVER_BIN" "$REMOTE_TMP"
}

start() {
    echo "[*] Killing old instance..."
    adb shell "su -c 'killall hluda 2>/dev/null; sleep 1'"
    echo "[*] Deploying and starting..."
    adb shell "su -c 'cp $REMOTE_TMP $REMOTE_BIN && chmod 755 $REMOTE_BIN && rm -rf /data/user/0/org.chromium.native_lib && $REMOTE_BIN -l unix:$SOCKET_NAME &'"
    sleep 2
    PID=$(adb shell "su -c 'pidof hluda'")
    echo "[+] Server running at PID: $PID"
}

forward() {
    echo "[*] Setting up port forward..."
    adb forward tcp:$LOCAL_PORT localabstract:$SOCKET_NAME
    echo "[+] Forward: localhost:$LOCAL_PORT -> @$SOCKET_NAME"
}

verify() {
    echo "[*] Verifying connection..."
    python3 -c "
import frida
d = frida.get_device_manager().add_remote_device('127.0.0.1:$LOCAL_PORT')
procs = d.enumerate_processes()
print(f'[+] Connected! {len(procs)} processes')
"
}

case "${1:-all}" in
    push)    push ;;
    start)   start ;;
    forward) forward ;;
    verify)  verify ;;
    all)     push; start; forward; verify ;;
    *)       echo "Usage: $0 [push|start|forward|verify|all]"; exit 1 ;;
esac
