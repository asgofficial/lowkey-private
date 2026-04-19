const { app, BrowserWindow, session } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let mainWindow;
let pythonProcess;

// Must be registered at top level BEFORE app.whenReady(), so the handler
// is attached before any early HTTPS request fires.
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
    // Allow mitmproxy's self-signed cert for HTTPS interception
    event.preventDefault();
    callback(true);
});

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false,
            // Required: UI is a file:// page that fetches http://127.0.0.1:5000
            webSecurity: false
        }
    });

    mainWindow.loadFile('index.html');

    // Uncomment to open DevTools for debugging:
    // mainWindow.webContents.openDevTools();
}

app.whenReady().then(async () => {
    console.log('[LowKeyPrivate] Starting mitmproxy engine...');

    pythonProcess = spawn('mitmdump', ['-s', 'engine.py', '--listen-port', '8080', '--ssl-insecure'], {
        cwd: __dirname
    });

    pythonProcess.stdout.on('data', (data) => {
        console.log(`[Engine] ${data.toString().trim()}`);
    });

    pythonProcess.stderr.on('data', (data) => {
        // mitmproxy writes normal startup logs to stderr — not just errors
        const msg = data.toString().trim();
        if (msg) console.log(`[Engine] ${msg}`);
    });

    pythonProcess.on('error', (err) => {
        console.error(`[Engine] Failed to start mitmdump: ${err.message}`);
        console.error('[Engine] Make sure mitmproxy is installed: pip install mitmproxy');
    });

    pythonProcess.on('exit', (code) => {
        if (code !== 0 && code !== null) {
            console.error(`[Engine] mitmdump exited with code ${code}`);
        }
    });

    // '<local>' bypasses ALL loopback addresses (localhost, 127.0.0.1, ::1)
    // so the UI's fetch() calls to FastAPI at :5000 never go through mitmproxy.
    try {
        await session.defaultSession.setProxy({
            proxyRules: 'http=127.0.0.1:8080;https=127.0.0.1:8080',
            proxyBypassRules: '<local>'
        });
        console.log('[LowKeyPrivate] Proxy rules applied — port 8080');
    } catch (err) {
        console.error('[LowKeyPrivate] Failed to set proxy:', err);
    }

    createWindow();

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
});

app.on('will-quit', () => {
    console.log('[LowKeyPrivate] Shutting down engine...');
    if (pythonProcess) {
        pythonProcess.kill();
    }
});
