#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <unistd.h>

// ==============================================================================
// AppShield for macOS: Native Cocoa Application & Graphical Setup Engine
// Version: 1.3.2
// ==============================================================================

@interface AppDelegate : NSObject <NSApplicationDelegate, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler, NSWindowDelegate>
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
                                                         NSWindowStyleMaskResizable)
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];

    [self.window setTitle:@"AppShield for macOS — Parental Control & Endpoint Shield"];
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
    [self.webView setUIDelegate:self];
    [self.webView setValue:@NO forKey:@"drawsBackground"];

    [[self.window contentView] addSubview:self.webView];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

// Support JavaScript alert() and confirm() inside WebKit
- (void)webView:(WKWebView *)webView runJavaScriptAlertPanelWithMessage:(NSString *)message initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(void))completionHandler {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"AppShield"];
    [alert setInformativeText:message];
    [alert addButtonWithTitle:@"OK"];
    [alert runModal];
    completionHandler();
}

- (void)webView:(WKWebView *)webView runJavaScriptConfirmPanelWithMessage:(NSString *)message initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(BOOL result))completionHandler {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"AppShield Confirmation"];
    [alert setInformativeText:message];
    [alert addButtonWithTitle:@"Yes"];
    [alert addButtonWithTitle:@"Cancel"];
    NSModalResponse resp = [alert runModal];
    completionHandler(resp == NSAlertFirstButtonReturn);
}

- (void)webView:(WKWebView *)webView runJavaScriptTextInputPanelWithPrompt:(NSString *)prompt defaultText:(NSString *)defaultText initiatedByFrame:(WKFrameInfo *)frame completionHandler:(void (^)(NSString * _Nullable result))completionHandler {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"AppShield Input"];
    [alert setInformativeText:prompt];
    [alert addButtonWithTitle:@"Confirm"];
    [alert addButtonWithTitle:@"Cancel"];

    NSTextField *input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
    [input setStringValue:defaultText ?: @""];
    [alert setAccessoryView:input];
    [[alert window] setInitialFirstResponder:input];

    NSModalResponse resp = [alert runModal];
    if (resp == NSAlertFirstButtonReturn) {
        completionHandler([input stringValue]);
    } else {
        completionHandler(nil);
    }
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
        NSString *newUrl = body[@"serverUrl"] ?: body[@"url"];
        if (newUrl && [newUrl length] > 0) {
            self.currentServerUrl = newUrl;
            [[NSUserDefaults standardUserDefaults] setObject:newUrl forKey:@"AppShieldServerUrl"];
            [[NSUserDefaults standardUserDefaults] synchronize];

            // 1. Update settings.json in /Library/Application Support/AppShield
            NSString *settingsPath = @"/Library/Application Support/AppShield/settings.json";
            NSMutableDictionary *settingsDict = [NSMutableDictionary dictionary];
            if ([[NSFileManager defaultManager] fileExistsAtPath:settingsPath]) {
                NSData *data = [NSData dataWithContentsOfFile:settingsPath];
                if (data) {
                    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if (json) [settingsDict addEntriesFromDictionary:json];
                }
            }
            BOOL isStandalone = [newUrl isEqualToString:@"standalone"] || [newUrl length] == 0;
            settingsDict[@"server_url"] = newUrl;
            settingsDict[@"standalone_mode"] = @(isStandalone);

            if (!settingsDict[@"device_id"]) {
                settingsDict[@"device_id"] = [NSString stringWithFormat:@"mac_%@", [self getHardwareUUIDPrefix]];
            }
            if (!settingsDict[@"name"]) {
                settingsDict[@"name"] = [NSHost currentHost].localizedName ?: @"Mac";
            }
            if (!settingsDict[@"psk"] || [settingsDict[@"psk"] length] == 0) {
                NSMutableString *psk = [NSMutableString stringWithCapacity:32];
                for (int i = 0; i < 32; i++) {
                    [psk appendFormat:@"%x", arc4random_uniform(16)];
                }
                settingsDict[@"psk"] = psk;
            }

            NSData *outData = [NSJSONSerialization dataWithJSONObject:settingsDict options:NSJSONWritingPrettyPrinted error:nil];
            if (outData) {
                if (![outData writeToFile:settingsPath atomically:YES]) {
                    NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:@"settings_update.json"];
                    [outData writeToFile:tmp atomically:YES];
                    NSString *cmd = [NSString stringWithFormat:@"cp -f '%@' '%@' 2>/dev/null", tmp, settingsPath];
                    system([cmd UTF8String]);
                }
            }

            // 2. Restart daemon so it reconnects to server immediately
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                system("pkill -9 -f agent.py 2>/dev/null || true");
            });

            // 3. Directly register with Central Server and transmit PSK
            if (!isStandalone) {
                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                    NSString *regUrlStr = [NSString stringWithFormat:@"%@/api/devices/register", [newUrl stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]]];
                    NSURL *regUrl = [NSURL URLWithString:regUrlStr];
                    if (regUrl) {
                        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:regUrl];
                        req.HTTPMethod = @"POST";
                        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
                        NSDictionary *payload = @{
                            @"id": settingsDict[@"device_id"] ?: @"mac_000000000000",
                            @"name": settingsDict[@"name"] ?: @"Mac",
                            @"os": @"macOS",
                            @"lan_ip": @"127.0.0.1",
                            @"tailscale_ip": settingsDict[@"tailscale_ip"] ?: @"",
                            @"agent_version": @"1.3.2",
                            @"psk": settingsDict[@"psk"] ?: @""
                        };
                        req.HTTPBody = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
                        [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                            if (!e) {
                                NSLog(@"[AppShield] Client auto-registered with server successfully.");
                            }
                        }] resume];
                    }
                });
            }

            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(500 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
                [self handleGetStatus];
            });
        }
    } else if ([action isEqualToString:@"openInBrowser"] || [action isEqualToString:@"loadDashboard"]) {
        NSString *urlStr = body[@"serverUrl"] ?: body[@"url"] ?: self.currentServerUrl;
        if (urlStr && [urlStr hasPrefix:@"http"]) {
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:urlStr]];
        }
    } else if ([action isEqualToString:@"installAgent"]) {
        NSString *url = body[@"serverUrl"] ?: self.currentServerUrl;
        [self executeInstallAgent:url];
    } else if ([action isEqualToString:@"uninstallAgent"]) {
        [self executeUninstallAgent];
    } else if ([action isEqualToString:@"unregisterDevice"]) {
        NSString *devId = body[@"deviceId"];
        NSString *serverUrl = body[@"serverUrl"] ?: self.currentServerUrl;
        if (serverUrl && [serverUrl hasPrefix:@"http"] && devId && [devId length] > 0) {
            NSString *cleanUrl = [serverUrl stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
            NSString *unregUrlStr = [NSString stringWithFormat:@"%@/api/fleet/%@", cleanUrl, devId];
            NSURL *url = [NSURL URLWithString:unregUrlStr];
            if (url) {
                NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
                req.HTTPMethod = @"DELETE";
                [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
            }
        }
    } else if ([action isEqualToString:@"syncRules"]) {
        [self executeSyncRules];
    } else if ([action isEqualToString:@"applyDns"]) {
        NSDictionary *dnsSettings = body[@"dns"] ?: body[@"settings"];
        if (dnsSettings) {
            [self executeApplyDns:dnsSettings];
        }
    } else if ([action isEqualToString:@"saveFeatures"]) {
        NSDictionary *features = body[@"features"];
        if (features) {
            NSError *err = nil;
            NSData *jsonData = [NSJSONSerialization dataWithJSONObject:features options:NSJSONWritingPrettyPrinted error:&err];
            if (jsonData) {
                NSString *featPath = @"/Library/Application Support/AppShield/features.json";
                if (![jsonData writeToFile:featPath atomically:YES]) {
                    // Fallback using temp file if needed
                    NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:@"features_update.json"];
                    [jsonData writeToFile:tmp atomically:YES];
                    NSString *cmd = [NSString stringWithFormat:@"cp -f '%@' '%@' 2>/dev/null", tmp, featPath];
                    system([cmd UTF8String]);
                }
                NSLog(@"[AppShield] Saved features.json successfully.");
            }
        }
    } else if ([action isEqualToString:@"terminateProcess"]) {
        NSNumber *pidNum = body[@"pid"];
        NSString *procName = body[@"processName"];
        if (pidNum && [pidNum intValue] > 0) {
            kill([pidNum intValue], SIGKILL);
        } else if (procName && procName.length > 0) {
            NSString *cmd = [NSString stringWithFormat:@"pkill -9 -f '%@' 2>/dev/null", procName];
            system([cmd UTF8String]);
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(300 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
            [self handleGetStatus];
        });
    } else if ([action isEqualToString:@"refreshRunningApps"]) {
        NSArray *running = [self getRunningApps];
        NSData *d = [NSJSONSerialization dataWithJSONObject:running options:0 error:nil];
        NSString *json = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"[]";
        NSString *js = [NSString stringWithFormat:@"window.updateRunningApps && window.updateRunningApps(%@);", json];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.webView evaluateJavaScript:js completionHandler:nil];
        });
    } else if ([action isEqualToString:@"refreshInstalledApps"]) {
        NSArray *installed = [self getInstalledApps];
        NSData *d = [NSJSONSerialization dataWithJSONObject:installed options:0 error:nil];
        NSString *json = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"[]";
        NSString *js = [NSString stringWithFormat:@"window.updateInstalledApps && window.updateInstalledApps(%@);", json];
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.webView evaluateJavaScript:js completionHandler:nil];
        });
    } else if ([action isEqualToString:@"quitApp"]) {
        [NSApp terminate:nil];
    } else if ([action isEqualToString:@"openInstalledApp"]) {
        NSString *appPath = @"/Applications/AppShield.app";
        if ([[NSFileManager defaultManager] fileExistsAtPath:appPath]) {
            [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:appPath]];
        }
        [NSApp terminate:nil];
    }
}

- (NSArray *)getLocalMacUsers {
    NSMutableArray *users = [NSMutableArray array];
    
    // 1. Get admin group members
    NSMutableSet *adminUsers = [NSMutableSet set];
    NSTask *adminTask = [[NSTask alloc] init];
    adminTask.launchPath = @"/usr/bin/dscl";
    adminTask.arguments = @[@".", @"-read", @"/Groups/admin", @"GroupMembership"];
    NSPipe *adminPipe = [NSPipe pipe];
    adminTask.standardOutput = adminPipe;
    @try {
        [adminTask launch];
        [adminTask waitUntilExit];
        NSData *data = [adminPipe.fileHandleForReading readDataToEndOfFile];
        NSString *outStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSArray *parts = [outStr componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        for (NSString *p in parts) {
            if ([p length] > 0 && ![p isEqualToString:@"GroupMembership:"]) {
                [adminUsers addObject:p];
            }
        }
    } @catch (NSException *e) {}
    
    // 2. Read features.json to check existing managed_users list
    NSMutableArray *managedUsernames = [NSMutableArray array];
    NSString *featuresPath = @"/Library/Application Support/AppShield/features.json";
    if ([[NSFileManager defaultManager] fileExistsAtPath:featuresPath]) {
        NSData *fData = [NSData dataWithContentsOfFile:featuresPath];
        if (fData) {
            NSDictionary *fJson = [NSJSONSerialization JSONObjectWithData:fData options:0 error:nil];
            if (fJson && [fJson[@"managed_users"] isKindOfClass:[NSArray class]]) {
                [managedUsernames addObjectsFromArray:fJson[@"managed_users"]];
            }
        }
    }
    
    // 3. Enumerate all local accounts with UID >= 501
    NSTask *userTask = [[NSTask alloc] init];
    userTask.launchPath = @"/usr/bin/dscl";
    userTask.arguments = @[@".", @"-list", @"/Users", @"UniqueID"];
    NSPipe *userPipe = [NSPipe pipe];
    userTask.standardOutput = userPipe;
    @try {
        [userTask launch];
        [userTask waitUntilExit];
        NSData *data = [userPipe.fileHandleForReading readDataToEndOfFile];
        NSString *outStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSArray *lines = [outStr componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            NSArray *parts = [line componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSMutableArray *nonEmpty = [NSMutableArray array];
            for (NSString *p in parts) {
                if ([p length] > 0) [nonEmpty addObject:p];
            }
            if (nonEmpty.count >= 2) {
                NSString *username = nonEmpty[0];
                int uid = [nonEmpty[1] intValue];
                if (uid >= 501 && ![username hasPrefix:@"_"] && ![username isEqualToString:@"daemon"] && ![username isEqualToString:@"nobody"]) {
                    BOOL isAdmin = [adminUsers containsObject:username];
                    
                    // Determine if managed:
                    // If features.json already specified managed_users, check presence.
                    // Otherwise default: standard child accounts are managed, admins are exempt.
                    BOOL isManaged = NO;
                    if (managedUsernames.count > 0) {
                        isManaged = [managedUsernames containsObject:username];
                    } else {
                        isManaged = !isAdmin;
                    }
                    
                    // Get real name
                    NSString *realName = username;
                    NSTask *nameTask = [[NSTask alloc] init];
                    nameTask.launchPath = @"/usr/bin/dscl";
                    nameTask.arguments = @[@".", @"-read", [NSString stringWithFormat:@"/Users/%@", username], @"RealName"];
                    NSPipe *namePipe = [NSPipe pipe];
                    nameTask.standardOutput = namePipe;
                    @try {
                        [nameTask launch];
                        [nameTask waitUntilExit];
                        NSData *nd = [namePipe.fileHandleForReading readDataToEndOfFile];
                        NSString *ns = [[NSString alloc] initWithData:nd encoding:NSUTF8StringEncoding];
                        for (NSString *nl in [ns componentsSeparatedByString:@"\n"]) {
                            NSString *trimmed = [nl stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                            if (![trimmed containsString:@"RealName:"] && trimmed.length > 0) {
                                realName = trimmed;
                                break;
                            }
                        }
                    } @catch (NSException *e) {}
                    
                    [users addObject:@{
                        @"username": username,
                        @"fullName": realName,
                        @"isAdmin": @(isAdmin),
                        @"isManaged": @(isManaged),
                        @"uid": @(uid)
                    }];
                }
            }
        }
    } @catch (NSException *e) {}
    
    return users;
}

- (NSString *)base64IconForPath:(NSString *)path {
    if (!path || [path length] == 0) return @"";
    static NSMutableDictionary *iconCache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        iconCache = [[NSMutableDictionary alloc] init];
    });
    
    @synchronized (iconCache) {
        NSString *cached = iconCache[path];
        if (cached) return cached;
    }
    
    @try {
        NSImage *icon = nil;
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            icon = [[NSWorkspace sharedWorkspace] iconForFile:path];
        }
        if (!icon) return @"";
        
        NSSize targetSize = NSMakeSize(48, 48);
        NSImage *resized = [[NSImage alloc] initWithSize:targetSize];
        [resized lockFocus];
        [[NSGraphicsContext currentContext] setImageInterpolation:NSImageInterpolationHigh];
        [icon drawInRect:NSMakeRect(0, 0, targetSize.width, targetSize.height)
                fromRect:NSZeroRect
               operation:NSCompositingOperationCopy
                fraction:1.0];
        [resized unlockFocus];
        
        NSData *tiff = [resized TIFFRepresentation];
        if (!tiff) return @"";
        NSBitmapImageRep *rep = [NSBitmapImageRep imageRepWithData:tiff];
        if (!rep) return @"";
        
        NSDictionary *props = @{ NSImageCompressionFactor: @0.75 };
        NSData *pngData = [rep representationUsingType:NSBitmapImageFileTypePNG properties:props];
        if (!pngData) return @"";
        
        NSString *b64 = [pngData base64EncodedStringWithOptions:0];
        NSString *uri = [NSString stringWithFormat:@"data:image/png;base64,%@", b64];
        
        // Also cache to shared directory so agent.py can send it in telemetry
        NSString *cacheDir = @"/Library/Application Support/AppShield/icons";
        [[NSFileManager defaultManager] createDirectoryAtPath:cacheDir withIntermediateDirectories:YES attributes:nil error:nil];
        NSString *safeName = [[path lastPathComponent] stringByDeletingPathExtension];
        NSString *filePath = [cacheDir stringByAppendingPathComponent:[NSString stringWithFormat:@"%@.png", safeName]];
        [pngData writeToFile:filePath atomically:YES];
        
        @synchronized (iconCache) {
            iconCache[path] = uri;
        }
        return uri;
    } @catch (NSException *e) {
        return @"";
    }
}

- (NSArray *)getInstalledApps {
    NSMutableArray *apps = [NSMutableArray array];
    NSArray *dirs = @[@"/Applications", @"/System/Applications", @"/System/Applications/Utilities", @"/Applications/Utilities"];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableSet *seen = [NSMutableSet set];
    
    for (NSString *dir in dirs) {
        NSArray *items = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *item in items) {
            if ([item hasSuffix:@".app"]) {
                NSString *cleanName = [item stringByDeletingPathExtension];
                if ([seen containsObject:cleanName]) continue;
                [seen addObject:cleanName];
                
                NSString *appPath = [dir stringByAppendingPathComponent:item];
                NSString *infoPlist = [appPath stringByAppendingPathComponent:@"Contents/Info.plist"];
                NSString *bundleId = @"";
                NSString *version = @"1.0";
                NSString *displayName = cleanName;
                if ([fm fileExistsAtPath:infoPlist]) {
                    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:infoPlist];
                    if (dict) {
                        bundleId = dict[@"CFBundleIdentifier"] ?: @"";
                        version = dict[@"CFBundleShortVersionString"] ?: dict[@"CFBundleVersion"] ?: @"1.0";
                        displayName = dict[@"CFBundleDisplayName"] ?: dict[@"CFBundleName"] ?: cleanName;
                    }
                }
                
                NSString *category = @"Other";
                NSString *lower = [displayName lowercaseString];
                if ([lower containsString:@"game"] || [lower containsString:@"roblox"] || [lower containsString:@"steam"] || 
                    [lower containsString:@"minecraft"] || [lower containsString:@"epic"] || [lower containsString:@"riot"] ||
                    [lower containsString:@"battle.net"] || [lower containsString:@"fortnite"] || [lower containsString:@"chess"]) {
                    category = @"Games";
                } else if ([lower containsString:@"discord"] || [lower containsString:@"slack"] || [lower containsString:@"telegram"] ||
                           [lower containsString:@"whatsapp"] || [lower containsString:@"messages"] || [lower containsString:@"zoom"] || [lower containsString:@"facetime"]) {
                    category = @"Social & Chat";
                } else if ([lower containsString:@"chrome"] || [lower containsString:@"safari"] || [lower containsString:@"firefox"] ||
                           [lower containsString:@"edge"] || [lower containsString:@"brave"] || [lower containsString:@"arc"] || [lower containsString:@"opera"]) {
                    category = @"Browsers";
                } else if ([lower containsString:@"youtube"] || [lower containsString:@"netflix"] || [lower containsString:@"spotify"] ||
                           [lower containsString:@"music"] || [lower containsString:@"tv"] || [lower containsString:@"vlc"] || [lower containsString:@"quicktime"]) {
                    category = @"Media";
                }
                
                NSString *icon = [self base64IconForPath:appPath];
                
                [apps addObject:@{
                    @"name": displayName,
                    @"exe": cleanName,
                    @"bundleId": bundleId,
                    @"version": version,
                    @"path": appPath,
                    @"category": category,
                    @"icon": icon ?: @""
                }];
            }
        }
    }
    [apps sortUsingComparator:^NSComparisonResult(NSDictionary *a, NSDictionary *b) {
        return [a[@"name"] localizedCaseInsensitiveCompare:b[@"name"]];
    }];
    return apps;
}

- (NSArray *)getRunningApps {
    NSMutableArray *list = [NSMutableArray array];
    NSWorkspace *ws = [NSWorkspace sharedWorkspace];
    
    // Get map of PID to username using ps
    NSMutableDictionary *pidUserMap = [NSMutableDictionary dictionary];
    NSTask *psTask = [[NSTask alloc] init];
    psTask.launchPath = @"/bin/ps";
    psTask.arguments = @[@"-A", @"-o", @"pid=,user="];
    NSPipe *pipe = [NSPipe pipe];
    psTask.standardOutput = pipe;
    @try {
        [psTask launch];
        [psTask waitUntilExit];
        NSData *d = [pipe.fileHandleForReading readDataToEndOfFile];
        NSString *outStr = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        NSArray *lines = [outStr componentsSeparatedByString:@"\n"];
        for (NSString *line in lines) {
            NSString *trimmed = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSArray *parts = [trimmed componentsSeparatedByCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
            NSMutableArray *nonEmpty = [NSMutableArray array];
            for (NSString *p in parts) {
                if (p.length > 0) [nonEmpty addObject:p];
            }
            if (nonEmpty.count >= 2) {
                pidUserMap[nonEmpty[0]] = nonEmpty[1];
            }
        }
    } @catch (NSException *e) {}

    for (NSRunningApplication *app in ws.runningApplications) {
        if (app.activationPolicy == NSApplicationActivationPolicyRegular) {
            NSString *name = app.localizedName ?: @"";
            if (name.length == 0 || [name isEqualToString:@"AppShield"]) continue;
            
            NSString *pidStr = [NSString stringWithFormat:@"%d", app.processIdentifier];
            NSString *user = pidUserMap[pidStr] ?: @"unknown";
            NSString *appPath = [app.bundleURL path] ?: @"";
            NSString *icon = [self base64IconForPath:appPath];
            
            [list addObject:@{
                @"pid": @(app.processIdentifier),
                @"name": name,
                @"bundleId": app.bundleIdentifier ?: @"",
                @"user": user,
                @"path": appPath,
                @"icon": icon ?: @""
            }];
        }
    }
    return list;
}

- (NSString *)getHardwareUUIDPrefix {
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/usr/sbin/ioreg";
    task.arguments = @[@"-rd1", @"-c", @"IOPlatformExpertDevice"];
    NSPipe *pipe = [NSPipe pipe];
    task.standardOutput = pipe;
    @try {
        [task launch];
        NSData *data = [[pipe fileHandleForReading] readDataToEndOfFile];
        [task waitUntilExit];
        NSString *outStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        for (NSString *line in [outStr componentsSeparatedByString:@"\n"]) {
            if ([line containsString:@"IOPlatformUUID"]) {
                NSArray *parts = [line componentsSeparatedByString:@"="];
                if (parts.count >= 2) {
                    NSString *raw = [[[[parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] stringByReplacingOccurrencesOfString:@"\"" withString:@""] stringByReplacingOccurrencesOfString:@"-" withString:@""] lowercaseString];
                    if (raw.length >= 12) {
                        return [raw substringToIndex:12];
                    }
                }
            }
        }
    } @catch (NSException *e) {}
    return [[[NSUUID UUID].UUIDString stringByReplacingOccurrencesOfString:@"-" withString:@""].lowercaseString substringToIndex:12];
}

- (void)handleGetStatus {
    BOOL isInstalled = NO;
    NSString *deviceId = [NSString stringWithFormat:@"mac_%@", [self getHardwareUUIDPrefix]];

    // 1. Check if launchd daemon AND /Applications/AppShield.app are installed
    NSString *plist = @"/Library/LaunchDaemons/com.appshield.macagent.plist";
    NSString *appInApps = @"/Applications/AppShield.app";
    if ([[NSFileManager defaultManager] fileExistsAtPath:plist] &&
        [[NSFileManager defaultManager] fileExistsAtPath:appInApps]) {
        isInstalled = YES;
    }

    // 2. Read config if present (check settings.json first, fallback to agent_config.json)
    NSString *settingsPath = @"/Library/Application Support/AppShield/settings.json";
    NSString *cfgPath = @"/Library/Application Support/AppShield/agent_config.json";
    NSString *activePath = [[NSFileManager defaultManager] fileExistsAtPath:settingsPath] ? settingsPath : cfgPath;
    if ([[NSFileManager defaultManager] fileExistsAtPath:activePath]) {
        NSData *data = [NSData dataWithContentsOfFile:activePath];
        if (data) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (json[@"device_id"]) deviceId = json[@"device_id"];
            if (json[@"server_url"]) self.currentServerUrl = json[@"server_url"];
        }
    }

    // 3. Read features.json
    NSDictionary *featuresDict = @{};
    NSString *featuresPath = @"/Library/Application Support/AppShield/features.json";
    if ([[NSFileManager defaultManager] fileExistsAtPath:featuresPath]) {
        NSData *fData = [NSData dataWithContentsOfFile:featuresPath];
        if (fData) {
            NSDictionary *fJson = [NSJSONSerialization JSONObjectWithData:fData options:0 error:nil];
            if (fJson) featuresDict = fJson;
        }
    }

    NSArray *users = [self getLocalMacUsers];
    NSString *deviceName = [NSHost currentHost].localizedName ?: @"Mac";

    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    BOOL isFromApplications = [bundlePath hasPrefix:@"/Applications"];

    NSData *usersData = [NSJSONSerialization dataWithJSONObject:users options:0 error:nil];
    NSString *usersJson = usersData ? [[NSString alloc] initWithData:usersData encoding:NSUTF8StringEncoding] : @"[]";

    NSData *featData = [NSJSONSerialization dataWithJSONObject:featuresDict options:0 error:nil];
    NSString *featJson = featData ? [[NSString alloc] initWithData:featData encoding:NSUTF8StringEncoding] : @"{}";

    NSDictionary *dnsDict = featuresDict[@"dns_filter"] ?: @{};
    NSData *dnsData = [NSJSONSerialization dataWithJSONObject:dnsDict options:0 error:nil];
    NSString *dnsJson = dnsData ? [[NSString alloc] initWithData:dnsData encoding:NSUTF8StringEncoding] : @"{}";

    NSArray *installedApps = [self getInstalledApps];
    NSArray *runningApps = [self getRunningApps];

    NSData *instData = [NSJSONSerialization dataWithJSONObject:installedApps options:0 error:nil];
    NSString *instJson = instData ? [[NSString alloc] initWithData:instData encoding:NSUTF8StringEncoding] : @"[]";

    NSData *runData = [NSJSONSerialization dataWithJSONObject:runningApps options:0 error:nil];
    NSString *runJson = runData ? [[NSString alloc] initWithData:runData encoding:NSUTF8StringEncoding] : @"[]";

    NSString *js = [NSString stringWithFormat:
        @"window.updateAgentState && window.updateAgentState({"
        @"  isInstalled: %@,"
        @"  isFromApplications: %@,"
        @"  serverUrl: '%@',"
        @"  deviceId: '%@',"
        @"  deviceName: '%@',"
        @"  users: %@,"
        @"  features: %@,"
        @"  dns: %@,"
        @"  installedApps: %@,"
        @"  runningApps: %@"
        @"});",
        isInstalled ? @"true" : @"false",
        isFromApplications ? @"true" : @"false",
        self.currentServerUrl ?: @"standalone",
        deviceId,
        [deviceName stringByReplacingOccurrencesOfString:@"'" withString:@"\\'"],
        usersJson,
        featJson,
        dnsJson,
        instJson,
        runJson];

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
        NSString *cmd = [NSString stringWithFormat:@"bash '%@' '%@'", installScript, serverUrl];
        NSString *escapedCmd = [cmd stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
        escapedCmd = [escapedCmd stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
        NSString *scriptText = [NSString stringWithFormat:
            @"do shell script \"%@\" with administrator privileges",
            escapedCmd];

        NSTask *task = [[NSTask alloc] init];
        task.launchPath = @"/usr/bin/osascript";
        task.arguments = @[@"-e", scriptText];
        @try {
            [task launch];
            [task waitUntilExit];
            NSLog(@"[AppShield] Install task exited with code: %d", task.terminationStatus);
        } @catch (NSException *e) {
            NSLog(@"[AppShield] Install task exception: %@", e);
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self loadSetupHtml];
            [self handleGetStatus];
        });
    });
}

- (void)executeUninstallAgent {
    // 1. Immediately notify Central Server to purge this computer from the fleet
    NSString *settingsPath = @"/Library/Application Support/AppShield/settings.json";
    if (![[NSFileManager defaultManager] fileExistsAtPath:settingsPath]) {
        settingsPath = @"/Library/Application Support/AppShield/agent_config.json";
    }
    NSString *devId = nil;
    NSString *srvUrl = self.currentServerUrl;
    if ([[NSFileManager defaultManager] fileExistsAtPath:settingsPath]) {
        NSData *data = [NSData dataWithContentsOfFile:settingsPath];
        if (data) {
            NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if (dict) {
                if (dict[@"device_id"]) devId = dict[@"device_id"];
                if (dict[@"server_url"] && [dict[@"server_url"] hasPrefix:@"http"]) {
                    srvUrl = dict[@"server_url"];
                }
            }
        }
    }
    if (!devId || devId.length == 0) {
        devId = [NSString stringWithFormat:@"mac_%@", [self getHardwareUUIDPrefix]];
    }
    if (!srvUrl || [srvUrl isEqualToString:@"standalone"] || ![srvUrl hasPrefix:@"http"]) {
        srvUrl = @"http://192.168.0.101:8000";
    }
    if (devId && devId.length > 0) {
        NSString *cleanUrl = [srvUrl stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        
        // 1. Unregister via POST
        NSURL *postUrl = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/devices/unregister", cleanUrl]];
        if (postUrl) {
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:postUrl];
            req.HTTPMethod = @"POST";
            req.timeoutInterval = 3.0;
            [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            NSDictionary *payload = @{@"device_id": devId, @"reason": @"uninstalled"};
            req.HTTPBody = [NSJSONSerialization dataWithJSONObject:payload options:0 error:nil];
            [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                dispatch_semaphore_signal(sema);
            }] resume];
            dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 1500 * NSEC_PER_MSEC));
        }

        // 2. Unregister via DELETE
        NSURL *delUrl = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/fleet/%@", cleanUrl, devId]];
        if (delUrl) {
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:delUrl];
            req.HTTPMethod = @"DELETE";
            req.timeoutInterval = 3.0;
            [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                dispatch_semaphore_signal(sema);
            }] resume];
            dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 1500 * NSEC_PER_MSEC));
        }

        // 3. Unregister via POST delete
        NSURL *postDelUrl = [NSURL URLWithString:[NSString stringWithFormat:@"%@/api/fleet/%@/delete", cleanUrl, devId]];
        if (postDelUrl) {
            NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:postDelUrl];
            req.HTTPMethod = @"POST";
            req.timeoutInterval = 3.0;
            [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
                dispatch_semaphore_signal(sema);
            }] resume];
            dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 1500 * NSEC_PER_MSEC));
        }
    }

    NSString *resourcePath = [[NSBundle mainBundle] resourcePath];
    NSString *uninstallScript = [resourcePath stringByAppendingPathComponent:@"uninstall-mac-agent.sh"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:uninstallScript]) {
        uninstallScript = @"/Library/Application Support/AppShield/uninstall-mac-agent.sh";
    }
    if (![[NSFileManager defaultManager] fileExistsAtPath:uninstallScript]) {
        uninstallScript = [@"./uninstall-mac-agent.sh" stringByStandardizingPath];
    }

    NSString *execCmd;
    if ([[NSFileManager defaultManager] fileExistsAtPath:uninstallScript]) {
        execCmd = [NSString stringWithFormat:@"bash '%@' '%@' '%@'", uninstallScript, srvUrl, devId ?: @""];
    } else {
        execCmd = @"launchctl bootout system/com.appshield.macagent 2>/dev/null || launchctl unload /Library/LaunchDaemons/com.appshield.macagent.plist 2>/dev/null || true; rm -f /Library/LaunchDaemons/com.appshield.macagent.plist; pkill -9 -f 'AppShield/agent/agent.py' 2>/dev/null || true; rm -rf '/Library/Application Support/AppShield' /var/log/appshield-agent.log /Applications/AppShield.app";
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *escapedCmd = [execCmd stringByReplacingOccurrencesOfString:@"\\" withString:@"\\\\"];
        escapedCmd = [escapedCmd stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
        NSString *scriptText = [NSString stringWithFormat:
            @"do shell script \"%@\" with administrator privileges",
            escapedCmd];

        NSTask *task = [[NSTask alloc] init];
        task.launchPath = @"/usr/bin/osascript";
        task.arguments = @[@"-e", scriptText];
        @try {
            [task launch];
            [task waitUntilExit];
            NSLog(@"[AppShield] Uninstall task exited with status: %d", task.terminationStatus);
        } @catch (NSException *e) {
            NSLog(@"[AppShield] Error running uninstall task: %@", e);
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self loadSetupHtml];
            [self handleGetStatus];
        });
    });
}

- (void)executeApplyDns:(NSDictionary *)dnsSettings {
    if (!dnsSettings) return;

    // 1. Update features.json
    NSString *featuresPath = @"/Library/Application Support/AppShield/features.json";
    NSMutableDictionary *featuresDict = [NSMutableDictionary dictionary];
    if ([[NSFileManager defaultManager] fileExistsAtPath:featuresPath]) {
        NSData *fData = [NSData dataWithContentsOfFile:featuresPath];
        if (fData) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:fData options:0 error:nil];
            if (json) [featuresDict addEntriesFromDictionary:json];
        }
    }
    featuresDict[@"dns_filter"] = dnsSettings;

    NSData *outData = [NSJSONSerialization dataWithJSONObject:featuresDict options:NSJSONWritingPrettyPrinted error:nil];
    if (outData) {
        if (![outData writeToFile:featuresPath atomically:YES]) {
            NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:@"features_dns.json"];
            [outData writeToFile:tmp atomically:YES];
            NSString *cmd = [NSString stringWithFormat:@"cp -f '%@' '%@' 2>/dev/null", tmp, featuresPath];
            system([cmd UTF8String]);
        }
    }

    // 2. Direct system execution via networksetup
    NSString *primaryDns = dnsSettings[@"primary_dns"] ?: @"";
    NSString *secondaryDns = dnsSettings[@"secondary_dns"] ?: @"";
    NSString *primaryIpv6 = dnsSettings[@"primary_ipv6"] ?: @"";
    NSString *secondaryIpv6 = dnsSettings[@"secondary_ipv6"] ?: @"";
    BOOL isEnabled = [dnsSettings[@"is_enabled"] boolValue];

    NSMutableArray *dnsArgs = [NSMutableArray array];
    if (isEnabled) {
        for (NSString *addr in @[primaryDns, secondaryDns, primaryIpv6, secondaryIpv6]) {
            NSString *trimmed = [addr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (trimmed.length > 0 && ![trimmed isEqualToString:@"N/A"] && ![dnsArgs containsObject:trimmed]) {
                [dnsArgs addObject:trimmed];
            }
        }
    }

    NSString *dnsStr = (dnsArgs.count > 0) ? [dnsArgs componentsJoinedByString:@" "] : @"empty";

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        // Build shell script for setting DNS on all network services
        NSMutableString *cmd = [NSMutableString string];
        [cmd appendString:@"networksetup -listallnetworkservices 2>/dev/null | grep -v '^\\*' | while read -r s; do "];
        [cmd appendFormat:@"if [ -n \"$s\" ] && ! echo \"$s\" | grep -q 'asterisk'; then networksetup -setdnsservers \"$s\" %@ 2>/dev/null || true; fi; done; ", dnsStr];
        [cmd appendString:@"dscacheutil -flushcache 2>/dev/null || true; killall -HUP mDNSResponder 2>/dev/null || true"];

        // If background daemon is running, poke it to sync DNS
        system("pkill -HUP -f agent.py 2>/dev/null || true");

        // Try direct execution; if permissions required, trigger osascript with admin privileges
        int res = system([cmd UTF8String]);
        if (res != 0) {
            NSString *escaped = [cmd stringByReplacingOccurrencesOfString:@"\"" withString:@"\\\""];
            NSString *asCmd = [NSString stringWithFormat:@"do shell script \"%@\" with administrator privileges", escaped];
            NSTask *task = [[NSTask alloc] init];
            task.launchPath = @"/usr/bin/osascript";
            task.arguments = @[@"-e", asCmd];
            @try {
                [task launch];
                [task waitUntilExit];
            } @catch (NSException *e) {}
        }

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
    if (urlStr && [urlStr hasPrefix:@"http"]) {
        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:urlStr]];
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
    [alert setMessageText:@"AppShield for macOS v1.3.2"];
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
