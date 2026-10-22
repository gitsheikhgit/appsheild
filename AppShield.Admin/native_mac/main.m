#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <signal.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>

// ==============================================================================
// AppShield Fleet Manager: Native macOS Cocoa Desktop Application
// Version: 1.2.0
// ==============================================================================

@interface AppDelegate : NSObject <NSApplicationDelegate, WKNavigationDelegate, NSWindowDelegate>
@property (strong, nonatomic) NSWindow *window;
@property (strong, nonatomic) WKWebView *webView;
@property (strong, nonatomic) NSTask *backendTask;
@property (assign, nonatomic) NSInteger targetPort;
@property (assign, nonatomic) NSInteger retryCount;
@end

@implementation AppDelegate

- (instancetype)init {
    self = [super init];
    if (self) {
        _targetPort = 8085;
        _retryCount = 0;
    }
    return self;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    [self setupMenuBar];
    [self startOrConnectBackend];
    [self createNativeWindow];
    [self loadDashboardWithRetry];
}

- (void)setupMenuBar {
    NSMenu *mainMenu = [[NSMenu alloc] init];

    // 1. App Menu
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"AppShield"];
    [appMenu addItemWithTitle:@"About AppShield Fleet Manager" action:@selector(showAbout:) keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"Hide AppShield" action:@selector(hide:) keyEquivalent:@"h"];
    NSMenuItem *hideOthers = [[NSMenuItem alloc] initWithTitle:@"Hide Others" action:@selector(hideOtherApplications:) keyEquivalent:@"h"];
    [hideOthers setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagOption)];
    [appMenu addItem:hideOthers];
    [appMenu addItemWithTitle:@"Show All" action:@selector(unhideAllApplications:) keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"Quit AppShield" action:@selector(terminate:) keyEquivalent:@"q"];
    [appMenuItem setSubmenu:appMenu];
    [mainMenu addItem:appMenuItem];

    // 2. Edit Menu (Crucial for Cmd+C, Cmd+V, Cmd+A inside WKWebView)
    NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"Edit"];
    [editMenu addItemWithTitle:@"Undo" action:NSSelectorFromString(@"undo:") keyEquivalent:@"z"];
    [editMenu addItemWithTitle:@"Redo" action:NSSelectorFromString(@"redo:") keyEquivalent:@"Z"];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItemWithTitle:@"Cut" action:NSSelectorFromString(@"cut:") keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"Copy" action:NSSelectorFromString(@"copy:") keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"Paste" action:NSSelectorFromString(@"paste:") keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"Select All" action:NSSelectorFromString(@"selectAll:") keyEquivalent:@"a"];
    [editMenuItem setSubmenu:editMenu];
    [mainMenu addItem:editMenuItem];

    // 3. View Menu
    NSMenuItem *viewMenuItem = [[NSMenuItem alloc] init];
    NSMenu *viewMenu = [[NSMenu alloc] initWithTitle:@"View"];
    [viewMenu addItemWithTitle:@"Reload Dashboard" action:@selector(reloadWebView:) keyEquivalent:@"r"];
    NSMenuItem *fullscreenItem = [[NSMenuItem alloc] initWithTitle:@"Toggle Full Screen" action:@selector(toggleFullScreen:) keyEquivalent:@"f"];
    [fullscreenItem setKeyEquivalentModifierMask:(NSEventModifierFlagCommand | NSEventModifierFlagControl)];
    [viewMenu addItem:fullscreenItem];
    [viewMenuItem setSubmenu:viewMenu];
    [mainMenu addItem:viewMenuItem];

    // 4. Window Menu
    NSMenuItem *windowMenuItem = [[NSMenuItem alloc] init];
    NSMenu *windowMenu = [[NSMenu alloc] initWithTitle:@"Window"];
    [windowMenu addItemWithTitle:@"Minimize" action:@selector(performMiniaturize:) keyEquivalent:@"m"];
    [windowMenu addItemWithTitle:@"Zoom" action:@selector(performZoom:) keyEquivalent:@""];
    [windowMenuItem setSubmenu:windowMenu];
    [mainMenu addItem:windowMenuItem];

    [NSApp setMainMenu:mainMenu];
}

- (void)createNativeWindow {
    NSScreen *screen = [NSScreen mainScreen];
    NSRect screenRect = screen ? [screen visibleFrame] : NSMakeRect(0, 0, 1440, 900);
    CGFloat width = MIN(1380, screenRect.size.width - 60);
    CGFloat height = MIN(880, screenRect.size.height - 60);
    NSRect rect = NSMakeRect((screenRect.size.width - width) / 2, (screenRect.size.height - height) / 2, width, height);

    self.window = [[NSWindow alloc] initWithContentRect:rect
                                              styleMask:(NSWindowStyleMaskTitled |
                                                         NSWindowStyleMaskClosable |
                                                         NSWindowStyleMaskMiniaturizable |
                                                         NSWindowStyleMaskResizable |
                                                         NSWindowStyleMaskFullSizeContentView)
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];

    [self.window setTitle:@"AppShield Fleet Manager — Tamper-Resistant Windows Security"];
    [self.window setTitlebarAppearsTransparent:YES];
    [self.window setMovableByWindowBackground:YES];
    [self.window setBackgroundColor:[NSColor colorWithCalibratedRed:17.0/255.0 green:17.0/255.0 blue:27.0/255.0 alpha:1.0]];
    [self.window setMinSize:NSMakeSize(980, 640)];
    [self.window center];
    [self.window setDelegate:self];

    // Configure WKWebView
    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    [[config preferences] setValue:@YES forKey:@"developerExtrasEnabled"];

    self.webView = [[WKWebView alloc] initWithFrame:[[self.window contentView] bounds] configuration:config];
    [self.webView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [self.webView setNavigationDelegate:self];
    [self.webView setValue:@NO forKey:@"drawsBackground"];

    [[self.window contentView] addSubview:self.webView];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (BOOL)isAppShieldListeningOnPort:(NSInteger)port {
    NSString *urlString = [NSString stringWithFormat:@"http://127.0.0.1:%ld/api/fleet", (long)port];
    NSURL *url = [NSURL URLWithString:urlString];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    [req setTimeoutInterval:0.8];

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __block BOOL isAppShield = NO;

    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data && !error) {
            NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            if ([str containsString:@"success"] || [str containsString:@"data"]) {
                isAppShield = YES;
            }
        }
        dispatch_semaphore_signal(sema);
    }] resume];

    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)));
    return isAppShield;
}

- (void)startOrConnectBackend {
    // 1. Check if AppShield is already active on 8085 or 54125
    if ([self isAppShieldListeningOnPort:8085]) {
        self.targetPort = 8085;
        NSLog(@"[AppShield Native] Connected to existing AppShield backend on port 8085");
        return;
    }
    if ([self isAppShieldListeningOnPort:54125]) {
        self.targetPort = 54125;
        NSLog(@"[AppShield Native] Connected to existing AppShield backend on port 54125");
        return;
    }

    self.targetPort = 8085;

    // 2. Locate AppShield.Admin directory
    NSString *resourcePath = [[NSBundle mainBundle] resourcePath];
    NSString *bundleAdmin = [resourcePath stringByAppendingPathComponent:@"AppShield.Admin"];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];

    NSArray<NSString *> *searchDirs = @[
        bundleAdmin,
        [[bundlePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"AppShield.Admin"],
        [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:@"AppShield.Admin"],
        [NSHomeDirectory() stringByAppendingPathComponent:@"Applications/AppShield.Admin"],
        [NSHomeDirectory() stringByAppendingPathComponent:@"AppShield.Admin"]
    ];

    NSString *adminDir = nil;
    for (NSString *dir in searchDirs) {
        NSString *mainPy = [dir stringByAppendingPathComponent:@"main.py"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:mainPy]) {
            adminDir = dir;
            break;
        }
    }

    if (!adminDir) {
        NSLog(@"[AppShield Native] Error: Could not locate AppShield.Admin directory");
        return;
    }

    // 3. Locate or Auto-Bootstrap Python virtual environment on a new Mac
    NSString *venvPython = [adminDir stringByAppendingPathComponent:@".venv/bin/python3"];
    NSString *venvUvicorn = [adminDir stringByAppendingPathComponent:@".venv/bin/uvicorn"];

    if (![[NSFileManager defaultManager] fileExistsAtPath:venvUvicorn]) {
        NSLog(@"[AppShield Native] First-run on new Mac: Bootstrapping Python virtual environment in background...");
        @try {
            NSTask *venvTask = [[NSTask alloc] init];
            [venvTask setExecutableURL:[NSURL fileURLWithPath:@"/usr/bin/python3"]];
            [venvTask setCurrentDirectoryURL:[NSURL fileURLWithPath:adminDir]];
            [venvTask setArguments:@[@"-m", @"venv", @".venv"]];
            [venvTask launch];
            [venvTask waitUntilExit];

            NSString *pipPath = [adminDir stringByAppendingPathComponent:@".venv/bin/pip"];
            if ([[NSFileManager defaultManager] fileExistsAtPath:pipPath]) {
                NSTask *pipTask = [[NSTask alloc] init];
                [pipTask setExecutableURL:[NSURL fileURLWithPath:pipPath]];
                [pipTask setCurrentDirectoryURL:[NSURL fileURLWithPath:adminDir]];
                [pipTask setArguments:@[@"install", @"-r", @"requirements.txt", @"--quiet"]];
                [pipTask launch];
                [pipTask waitUntilExit];
            }
        } @catch (NSException *e) {
            NSLog(@"[AppShield Native] Bootstrap note: %@", e);
        }
    }

    NSArray<NSString *> *pythonCandidates = @[
        venvPython,
        @"/opt/homebrew/bin/python3",
        @"/usr/local/bin/python3",
        @"/usr/bin/python3"
    ];

    NSString *pythonExec = nil;
    for (NSString *py in pythonCandidates) {
        if ([[NSFileManager defaultManager] isExecutableFileAtPath:py]) {
            pythonExec = py;
            break;
        }
    }

    if (!pythonExec) pythonExec = @"/usr/bin/python3";

    self.backendTask = [[NSTask alloc] init];
    [self.backendTask setExecutableURL:[NSURL fileURLWithPath:pythonExec]];
    [self.backendTask setCurrentDirectoryURL:[NSURL fileURLWithPath:adminDir]];
    [self.backendTask setArguments:@[
        @"-m", @"uvicorn", @"main:app",
        @"--host", @"0.0.0.0",
        @"--port", [NSString stringWithFormat:@"%ld", (long)self.targetPort]
    ]];

    NSError *err = nil;
    if ([self.backendTask launchAndReturnError:&err]) {
        NSLog(@"[AppShield Native] Launched AppShield backend on port %ld (PID: %d)", (long)self.targetPort, [self.backendTask processIdentifier]);
    } else {
        NSLog(@"[AppShield Native] Failed to launch backend: %@", err);
    }
}

- (void)loadDashboardWithRetry {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%ld", (long)self.targetPort]];
    NSURLRequest *request = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:30.0];
    [self.webView loadRequest:request];
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    if (self.retryCount < 25) {
        self.retryCount++;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [self loadDashboardWithRetry];
        });
    }
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    self.retryCount = 0;
}

- (void)reloadWebView:(id)sender {
    [self loadDashboardWithRetry];
}

- (void)showAbout:(id)sender {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"AppShield Fleet Manager"];
    [alert setInformativeText:@"Version 1.2.0 (macOS Native Client)\n\nTamper-Resistant Windows Endpoint Protection & Parental Shield.\nBuilt with Apple Cocoa & WebKit."];
    [alert setAlertStyle:NSAlertStyleInformational];
    [alert runModal];
}

- (BOOL)windowShouldClose:(NSWindow *)sender {
    [NSApp terminate:nil];
    return YES;
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    if (self.backendTask && [self.backendTask isRunning]) {
        [self.backendTask terminate];
    }
}

@end

// ==============================================================================
// Main Entrypoint
// ==============================================================================
int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        [app setDelegate:delegate];
        [app run];
    }
    return 0;
}
