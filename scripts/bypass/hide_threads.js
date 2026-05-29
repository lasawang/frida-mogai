const openSys = new NativeFunction(Module.getExportByName('libc.so', 'open'), 'int', ['pointer', 'int']);
const writeSys = new NativeFunction(Module.getExportByName('libc.so', 'write'), 'long', ['int', 'pointer', 'long']);
const closeSys = new NativeFunction(Module.getExportByName('libc.so', 'close'), 'int', ['int']);
const readSys = new NativeFunction(Module.getExportByName('libc.so', 'read'), 'long', ['int', 'pointer', 'long']);

const rename_map = {
    'gmain': 'HeapTrim',
    'gdbus': 'AsyncTask #1',
    'pool-frida': 'AsyncTask #2',
    'gc-svc3': 'Binder:Idle',
};

function getThreadName(tid) {
    const commPath = Memory.allocUtf8String('/proc/self/task/' + tid + '/comm');
    const fd = openSys(commPath, 0);
    if (fd < 0) return null;
    const buf = Memory.alloc(64);
    const n = readSys(fd, buf, 63);
    closeSys(fd);
    if (n <= 0) return null;
    return buf.readCString().trim();
}

function renameThread(tid, newName) {
    const commPath = Memory.allocUtf8String('/proc/self/task/' + tid + '/comm');
    const wfd = openSys(commPath, 1);
    if (wfd >= 0) {
        const nameBuf = Memory.allocUtf8String(newName);
        writeSys(wfd, nameBuf, newName.length);
        closeSys(wfd);
        return true;
    }
    return false;
}

function doRename() {
    let renamed = 0;
    Process.enumerateThreads().forEach(t => {
        const name = getThreadName(t.id);
        if (name === null) return;
        for (const [pattern, replacement] of Object.entries(rename_map)) {
            if (name === pattern || name.startsWith(pattern)) {
                if (renameThread(t.id, replacement)) {
                    console.log('OK: ' + name + ' -> ' + replacement);
                    renamed++;
                }
                break;
            }
        }
    });
    return renamed;
}

// Hook prctl to intercept PR_SET_NAME (15)
const PR_SET_NAME = 15;
Interceptor.attach(Module.getExportByName('libc.so', 'prctl'), {
    onEnter: function(args) {
        if (args[0].toInt32() === PR_SET_NAME) {
            const name = args[1].readCString();
            for (const [pattern, replacement] of Object.entries(rename_map)) {
                if (name === pattern || name.startsWith(pattern)) {
                    args[1].writeUtf8String(replacement);
                    break;
                }
            }
        }
    }
});

// Hook pthread_setname_np too
Interceptor.attach(Module.getExportByName('libc.so', 'pthread_setname_np'), {
    onEnter: function(args) {
        const name = args[1].readCString();
        for (const [pattern, replacement] of Object.entries(rename_map)) {
            if (name === pattern || name.startsWith(pattern)) {
                args[1].writeUtf8String(replacement);
                break;
            }
        }
    }
});

// Delayed rename attempts
setTimeout(() => { 
    const n = doRename();
    console.log('Delayed rename (200ms): ' + n);
}, 200);
setTimeout(() => { 
    const n = doRename();
    console.log('Delayed rename (500ms): ' + n);
}, 500);
setTimeout(() => { 
    const n = doRename();
    console.log('Delayed rename (1000ms): ' + n);
}, 1000);

console.log('Hooks installed');
