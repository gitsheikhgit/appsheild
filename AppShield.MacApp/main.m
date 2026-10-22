#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <unistd.h>

// ==============================================================================
// AppShield for macOS: Native Cocoa Application & Graphical Setup Engine
// Version: 1.2.0
// ==============================================================================

@interface AppDelegate : NSObject <NSApplicationDelegate, WKNavigationDelegate, WKScriptMessageHandler, NSWindowDelegate>
@property (strong, nonatomic) NSWindow *window;
@property (strong, nonatomic) WKWebView *webView;
@property (copy, nonatomic) NSString *currentServerUrl;
@property (assign, nonatomic) BOOL isShowingDashboard;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // 1. Read default or stored server URL
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    self.currentServerUrl = [defaults stringForKey:@"AppShieldServerUrl"];
    if (!self.currentServerUrl || [self.currentServerUrl length] == 0) {
        self.currentServerUrl = @"http://192.168.0.101:8000";
    }

    [self setupMenuBar];
    [self createNativeWindow];
    [self loadSetupHtml];
}

- (void)setupMenuBar {
    NSMenu *mainMenu = [[NSMenu alloc] init];

    // 1. App Menu
    NSMenuItem *appMenuItem = [[NSMenuItem alloc] init];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"AppShield"];
    [appMenu addItemWithTitle:@"About AppShield" action:@selector(showAbout:) keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"Shield Configuration..." action:@selector(showSetupFromMenu:) keyEquivalent:@","];
    [appMenu addItemWithTitle:@"Open Central Dashboard" action:@selector(openDashboardFromMenu:) keyEquivalent:@"d"];
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

    // 2. Edit Menu (Cmd+C, Cmd+V, Cmd+A)
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
    [viewMenu addItemWithTitle:@"Reload Screen" action:@selector(reloadWebView:) keyEquivalent:@"r"];
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
    CGFloat width = MIN(1180, screenRect.size.width - 60);
    CGFloat height = MIN(760, screenRect.size.height - 60);
    NSRect rect = NSMakeRect((screenRect.size.width - width) / 2, (screenRect.size.height - height) / 2, width, height);

    self.window = [[NSWindow alloc] initWithContentRect:rect
                                              styleMask:(NSWindowStyleMaskTitled |
                                                         NSWindowStyleMaskClosable |
                                                         NSWindowStyleMaskMiniaturizable |
                                                         NSWindowStyleMaskResizable |
                                                         NSWindowStyleMaskFullSizeContentView)
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];

    [self.window setTitle:@"AppShield for macOS — Parental Control & Endpoint Shield"];
    [self.window setTitlebarAppearsTransparent:YES];
    [self.window setMovableByWindowBackground:YES];
    [self.window setBackgroundColor:[NSColor colorWithCalibratedRed:12.0/255.0 green:14.0/255.0 blue:20.0/255.0 alpha:1.0]];
    [self.window setMinSize:NSMakeSize(900, 600)];
    [self.window center];
    [self.window setDelegate:self];

    // Configure WKWebView with script message handler
    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    [[config preferences] setValue:@YES forKey:@"developerExtrasEnabled"];
    WKUserContentController *userContent = [[WKUserContentController alloc] init];
    [userContent addScriptMessageHandler:self name:@"nativeAgent"];
    config.userContentController = userContent;

    self.webView = [[WKWebView alloc] initWithFrame:[[self.window contentView] bounds] configuration:config];
    [self.webView setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];
    [self.webView setNavigationDelegate:self];
    [self.webView setValue:@NO forKey:@"drawsBackground"];

    [[self.window contentView] addSubview:self.webView];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)loadSetupHtml {
    self.isShowingDashboard = NO;
    NSString *resourcePath = [[NSBundle mainBundle] resourcePath];
    NSString *htmlPath = [resourcePath stringByAppendingPathComponent:@"static/setup.html"];

    if (![[NSFileManager defaultManager] fileExistsAtPath:htmlPath]) {
        // Fallback search in working directory
        htmlPath = [@"./AppShield.MacApp/static/setup.html" stringByStandardizingPath];
    }

    if ([[NSFileManager defaultManager] fileExistsAtPath:htmlPath]) {
        NSURL *fileUrl = [NSURL fileURLWithPath:htmlPath];
        [self.webView loadFileURL:fileUrl allowingReadAccessToURL:[fileUrl URLByDeletingLastPathComponent]];
    } else {
        NSString *fallbackHtml = @"<html><body style='background:#111;color:#fff;font-family:sans-serif;padding:40px;'>"
                                 @"<h2>AppShield Setup Error</h2><p>Could not locate setup.html resource.</p></body></html>";
        [self.webView loadHTMLString:fallbackHtml baseURL:nil];
    }
}

// -----------------------------------------------------------------------------
// Bridge: JavaScript <-> Native Objective-C Handling
// -----------------------------------------------------------------------------
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![message.name isEqualToString:@"nativeAgent"]) return;

    NSDictionary *body = message.body;
    if (![body isKindOfClass:[NSDictionary class]]) return;

    NSString *action = body[@"action"];

    if ([action isEqualToString:@"getAgentStatus"]) {
        [self handleGetStatus];
    } else if ([action isEqualToString:@"saveServerUrl"]) {
        NSString *newUrl = body[@"serverUrl"];
        if (newUrl && [newUrl length] > 0) {
            self.currentServerUrl = newUrl;
            [[NSUserDefaults standardUserDefaults] setObject:newUrl forKey:@"AppShieldServerUrl"];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }
    } else if ([action isEqualToString:@"installAgent"]) {
        NSString *url = body[@"serverUrl"] ?: self.currentServerUrl;
        [self executeInstallAgent:url];
    } else if ([action isEqualToString:@"uninstallAgent"]) {
        [self executeUninstallAgent];
    } else if ([action isEqualToString:@"loadDashboard"]) {
        NSString *url = body[@"serverUrl"] ?: self.currentServerUrl;
        [self loadDashboardUrl:url];
    } else if ([action isEqualToString:@"syncRules"]) {
        [self executeSyncRules];
    }
}

- (void)handleGetStatus {
    BOOL isInstalled = NO;
    NSString *deviceId = @"mac_detecting";

    // 1. Check if launchd daemon is installed
    NSString *plist = @"/Library/LaunchDaemons/com.appshield.macagent.plist";
    if ([[NSFileManager defaultManager] fileExistsAtPath:plist]) {
        isInstalled = YES;
    }

    // 2. Read config if present
    NSString *cfgPath = @"/Library/Application Support/AppShield/agent_config.json";
    if ([[NSFileManager defaultManager] fileExistsAtPath:cfgPath]) {
        NSData *data = [NSData dataWithContentsOfFile:cfgPath];
        if (data) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json[@"device_id"]) deviceId = json[@"device_id"];
            if (json[@"server_url"]) self.currentServerUrl = json[@"server_url"];
        }
    }

    NSString *js = [NSString stringWithFormat:@"window.updateAgentState && window.updateAgentState({ isInstalled: %@, serverUrl: '%@', deviceId: '%@' });",
                    isInstalled ? @"true" : @"false", self.currentServerUrl, deviceId];
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.webView evaluateJavaScript:js completionHandler:nil];
    });
}

- (void)executeInstallAgent:(NSString *)serverUrl {
    self.currentServerUrl = serverUrl;
    [[NSUserDefaults standardUserDefaults] setObject:serverUrl forKey:@"AppShieldServerUrl"];
    [[NSUserDefaults standardUserDefaults] synchronize];

    NSString *resourcePath = [[NSBundle mainBundle] resourcePath];
    NSString *installScript = [resourcePath stringByAppendingPathComponent:@"install-mac-agent.sh"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:installScript]) {
        installScript = [@"./install-mac-agent.sh" stringByStandardizingPath];
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Standard macOS authorization prompt: do shell script ... with administrator privileges
        NSString *scriptText = [NSString stringWithFormat:
            @"do shell script \"bash '%@' '%@'\" with administrator privileges",
            installScript, serverUrl];

        NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:scriptText];
        NSDictionary *errorInfo = nil;
        NSAppleEventDescriptor *result = [appleScript executeAndReturnError:&errorInfo];

        dispatch_async(dispatch_get_main_queue(), ^{
            if (errorInfo) {
                NSLog(@"[AppShield] Authorization canceled or failed: %@", errorInfo);
                [self handleGetStatus];
            } else {
                NSLog(@"[AppShield] Agent installed successfully!");
                [self handleGetStatus];
            }
        });
    });
}

- (void)executeUninstallAgent {
    NSString *resourcePath = [[NSBundle mainBundle] resourcePath];
    NSString *uninstallScript = [resourcePath stringByAppendingPathComponent:@"uninstall-mac-agent.sh"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:uninstallScript]) {
        uninstallScript = [@"./uninstall-mac-agent.sh" stringByStandardizingPath];
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *scriptText = [NSString stringWithFormat:
            @"do shell script \"bash '%@'\" with administrator privileges",
            uninstallScript];

        NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:scriptText];
        NSDictionary *errorInfo = nil;
        [appleScript executeAndReturnError:&errorInfo];

        dispatch_async(dispatch_get_main_queue(), ^{
            [self handleGetStatus];
        });
    });
}

- (void)executeSyncRules {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        system("pkill -HUP -f agent.py 2>/dev/null || true");
    });
}

- (void)loadDashboardUrl:(NSString *)urlStr {
    self.isShowingDashboard = YES;
    NSURL *url = [NSURL URLWithString:urlStr];
    if (url) {
        NSURLRequest *req = [NSURLRequest requestWithURL:url];
        [self.webView loadRequest:req];
    }
}

// -----------------------------------------------------------------------------
// Menu Actions
// -----------------------------------------------------------------------------
- (void)showSetupFromMenu:(id)sender {
    [self loadSetupHtml];
}

- (void)openDashboardFromMenu:(id)sender {
    [self loadDashboardUrl:self.currentServerUrl];
}

- (void)reloadWebView:(id)sender {
    [self.webView reload];
}

- (void)showAbout:(id)sender {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"AppShield for macOS v1.2.0"];
    [alert setInformativeText:@"Commercial Multi-Platform Parental Shield & Tamper-Resistant Security.\n\nConnected to Proxmox LXC Hub:\nhttp://192.168.0.101:8000"];
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        [app setDelegate:delegate];
        [app run];
    }
    return 0;
}
