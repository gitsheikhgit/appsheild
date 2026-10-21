import Cocoa
import WebKit

// ==============================================================================
// AppShield Fleet Manager: Native macOS Cocoa Application
// Version: 1.2.0
// ==============================================================================

class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, NSWindowDelegate {
    var window: NSWindow!
    var webView: WKWebView!
    var backendProcess: Process?
    let targetPort = 8080
    var retryCount = 0

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenuBar()
        startBackendServerIfNeeded()
        createNativeWindow()
        loadDashboardWithRetry()
    }

    func setupMenuBar() {
        let mainMenu = NSMenu()
        
        // 1. App Menu
        let appMenuItem = NSMenuItem()
        let appMenu = NSMenu(title: "AppShield")
        appMenu.addItem(withTitle: "About AppShield Fleet Manager", action: #selector(showAbout), keyEquivalent: "")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Hide AppShield", action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        let hideOthersItem = NSMenuItem(title: "Hide Others", action: #selector(NSApplication.hideOtherApplications(_:)), keyEquivalent: "h")
        hideOthersItem.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(hideOthersItem)
        appMenu.addItem(withTitle: "Show All", action: #selector(NSApplication.unhideAllApplications(_:)), keyEquivalent: "")
        appMenu.addItem(NSMenuItem.separator())
        appMenu.addItem(withTitle: "Quit AppShield", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        appMenuItem.submenu = appMenu
        mainMenu.addItem(appMenuItem)

        // 2. Edit Menu (Crucial for Cmd+C, Cmd+V, Cmd+A inside WKWebView)
        let editMenuItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        editMenu.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(withTitle: "Cut", action: Selector(("cut:")), keyEquivalent: "x")
        editMenu.addItem(withTitle: "Copy", action: Selector(("copy:")), keyEquivalent: "c")
        editMenu.addItem(withTitle: "Paste", action: Selector(("paste:")), keyEquivalent: "v")
        editMenu.addItem(withTitle: "Select All", action: Selector(("selectAll:")), keyEquivalent: "a")
        editMenuItem.submenu = editMenu
        mainMenu.addItem(editMenuItem)

        // 3. View Menu
        let viewMenuItem = NSMenuItem()
        let viewMenu = NSMenu(title: "View")
        viewMenu.addItem(withTitle: "Reload Dashboard", action: #selector(reloadWebView), keyEquivalent: "r")
        let fullscreenItem = NSMenuItem(title: "Toggle Full Screen", action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f")
        fullscreenItem.keyEquivalentModifierMask = [.command, .control]
        viewMenu.addItem(fullscreenItem)
        viewMenuItem.submenu = viewMenu
        mainMenu.addItem(viewMenuItem)

        // 4. Window Menu
        let windowMenuItem = NSMenuItem()
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(withTitle: "Minimize", action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        windowMenu.addItem(withTitle: "Zoom", action: #selector(NSWindow.performZoom(_:)), keyEquivalent: "")
        windowMenuItem.submenu = windowMenu
        mainMenu.addItem(windowMenuItem)

        NSApp.mainMenu = mainMenu
    }

    func createNativeWindow() {
        let screenRect = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let width: CGFloat = min(1380, screenRect.width - 60)
        let height: CGFloat = min(880, screenRect.height - 60)
        let rect = NSRect(x: (screenRect.width - width) / 2, y: (screenRect.height - height) / 2, width: width, height: height)

        window = NSWindow(
            contentRect: rect,
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )

        window.title = "AppShield Fleet Manager — Tamper-Resistant Windows Security"
        window.titlebarAppearsTransparent = true
        window.backgroundColor = NSColor(red: 17/255.0, green: 17/255.0, blue: 27/255.0, alpha: 1.0)
        window.minSize = NSSize(width: 980, height: 640)
        window.center()
        window.delegate = self

        // Configure WKWebView
        let config = WKWebViewConfiguration()
        config.preferences.setValue(true, forKey: "developerExtrasEnabled")
        
        webView = WKWebView(frame: window.contentView!.bounds, configuration: config)
        webView.autoresizingMask = [.width, .height]
        webView.navigationDelegate = self
        webView.setValue(false, forKey: "drawsBackground") // Prevents white flash before CSS loads

        window.contentView?.addSubview(webView)
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func startBackendServerIfNeeded() {
        // Find project AppShield.Admin folder relative to app bundle or current dir
        let bundlePath = Bundle.main.bundlePath
        let possibleDirs = [
            (bundlePath as NSString).deletingLastPathComponent + "/AppShield.Admin",
            (bundlePath as NSString).deletingLastPathComponent,
            FileManager.default.currentDirectoryPath + "/AppShield.Admin",
            FileManager.default.currentDirectoryPath
        ]

        var adminDir = possibleDirs[0]
        for dir in possibleDirs {
            if FileManager.default.fileExists(atPath: dir + "/main.py") {
                adminDir = dir
                break
            }
        }

        // Check if port 8080 or pid file is running
        let pidFile = adminDir + "/.server.pid"
        if FileManager.default.fileExists(atPath: pidFile),
           let pidStr = try? String(contentsOfFile: pidFile, encoding: .utf8),
           let pid = Int32(pidStr.trimmingCharacters(in: .whitespacesAndNewlines)) {
            if kill(pid, 0) == 0 {
                return // Server already running!
            }
        }

        // Spawn python3 uvicorn in background
        let process = Process()
        let venvPython = adminDir + "/.venv/bin/python3"
        if FileManager.default.fileExists(atPath: venvPython) {
            process.executableURL = URL(fileURLWithPath: venvPython)
        } else {
            process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        }

        process.currentDirectoryURL = URL(fileURLWithPath: adminDir)
        process.arguments = ["-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "\(targetPort)"]
        
        do {
            try process.run()
            self.backendProcess = process
            try? "\(process.processIdentifier)".write(toFile: pidFile, atomically: true, encoding: .utf8)
        } catch {
            print("[AppShield Native] Could not launch backend: \(error)")
        }
    }

    func loadDashboardWithRetry() {
        guard let url = URL(string: "http://127.0.0.1:\(targetPort)") else { return }
        webView.load(URLRequest(url: url))
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        // If server is still starting up, retry up to 10 times (10 x 0.5s = 5s)
        if retryCount < 10 {
            retryCount += 1
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.loadDashboardWithRetry()
            }
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        retryCount = 0
    }

    @objc func reloadWebView() {
        webView.reload()
    }

    @objc func showAbout() {
        let alert = NSAlert()
        alert.messageText = "AppShield Fleet Manager"
        alert.informativeText = "Version 1.2.0 (macOS Native Client)\n\nTamper-Resistant Windows Endpoint Protection & Parental Shield.\nBuilt with Apple WebKit & Cocoa."
        alert.alertStyle = .informational
        alert.runModal()
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        NSApp.terminate(nil)
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let proc = backendProcess, proc.isRunning {
            proc.terminate()
        }
    }
}

// ==============================================================================
// Main Entrypoint
// ==============================================================================
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
