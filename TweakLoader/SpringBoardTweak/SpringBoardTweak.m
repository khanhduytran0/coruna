@import UIKit;
@import UniformTypeIdentifiers;
#import "SpringBoardTweak.h"
#include <objc/runtime.h>
#include <objc/message.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <spawn.h>
#include <dlfcn.h>

#pragma mark - Status Bar Clock Tweak

static NSString *g_timeFormat = nil;
static NSString *g_dateFormat = nil;

static NSString *getTimeFormat(void) {
    return g_timeFormat ?: @"HH:mm";
}

static NSString *getDateFormat(void) {
    return g_dateFormat ?: @"E dd/MM/yyyy";
}

static void (*orig_applyStyleAttributes)(id self, SEL _cmd, id arg1);
static void (*orig_setText)(id self, SEL _cmd, NSString *text);

static void hook_applyStyleAttributes(id self, SEL _cmd, id arg1) {
    UILabel *label = (UILabel *)self;
    if (!(label.text != nil && [label.text containsString:@":"])) {
        orig_applyStyleAttributes(self, _cmd, arg1);
    }
}

static void hook_setText(id self, SEL _cmd, NSString *text) {
    if ([text containsString:@":"]) {
        UILabel *label = (UILabel *)self;
        @autoreleasepool {
            NSMutableAttributedString *finalString = [[NSMutableAttributedString alloc] init];

            NSString *timeFmt = getTimeFormat();
            NSString *dateFmt = getDateFormat();

            NSDateFormatter *formatter1 = [[NSDateFormatter alloc] init];
            [formatter1 setDateFormat:timeFmt];
            UIFont *font1 = [UIFont systemFontOfSize:15.0 weight:UIFontWeightSemibold];
            NSAttributedString *attrString1 = [[NSAttributedString alloc] initWithString:[formatter1 stringFromDate:[NSDate date]]
                                                                              attributes:@{NSFontAttributeName: font1}];

            [finalString appendAttributedString:attrString1];

            if (dateFmt.length > 0) {
                NSLocale *currentLocale = [NSLocale autoupdatingCurrentLocale];
                NSDateFormatter *formatter2 = [[NSDateFormatter alloc] init];
                [formatter2 setDateFormat:dateFmt];
                [formatter2 setLocale:currentLocale];
                UIFont *font2 = [UIFont systemFontOfSize:8.0 weight:UIFontWeightRegular];
                NSAttributedString *attrString2 = [[NSAttributedString alloc] initWithString:[formatter2 stringFromDate:[NSDate date]]
                                                                                  attributes:@{NSFontAttributeName: font2}];

                [finalString appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n"]];
                [finalString appendAttributedString:attrString2];
                label.numberOfLines = 2;
            } else {
                label.numberOfLines = 1;
            }

            label.textAlignment = NSTextAlignmentCenter;
            label.attributedText = finalString;
        }
    } else {
        orig_setText(self, _cmd, text);
    }
}

static void hookStatusBarClass(Class cls) {
    if (!cls) return;

    Method m1 = class_getInstanceMethod(cls, @selector(applyStyleAttributes:));
    if (m1) {
        orig_applyStyleAttributes = (void *)method_getImplementation(m1);
        method_setImplementation(m1, (IMP)hook_applyStyleAttributes);
    }

    Method m2 = class_getInstanceMethod(cls, @selector(setText:));
    if (m2) {
        orig_setText = (void *)method_getImplementation(m2);
        method_setImplementation(m2, (IMP)hook_setText);
    }
}

static void initStatusBarTweak(void) {
    // iOS 17+: STUIStatusBarStringView (StatusBarUI framework)
    Class cls17 = objc_getClass("STUIStatusBarStringView");
    // iOS 16: _UIStatusBarStringView (UIKit private)
    Class cls16 = objc_getClass("_UIStatusBarStringView");

    if (cls17) hookStatusBarClass(cls17);
    if (cls16) hookStatusBarClass(cls16);
}

#pragma mark - Dock Transparency

static void (*orig_setBackgroundAlpha)(id self, SEL _cmd, double alpha);
static void hook_setBackgroundAlpha(id self, SEL _cmd, double alpha) {
    orig_setBackgroundAlpha(self, _cmd, 0.0);
}

static void (*orig_setBackgroundView)(id self, SEL _cmd, id view);
static void hook_setBackgroundView(id self, SEL _cmd, id view) {
    orig_setBackgroundView(self, _cmd, view);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(view, sel_registerName("setHidden:"), YES);
}

static void initDockTransparency(void) {
    Class dockView = objc_getClass("SBDockView");
    if (dockView) {
        Method m = class_getInstanceMethod(dockView, @selector(setBackgroundAlpha:));
        if (m) {
            orig_setBackgroundAlpha = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_setBackgroundAlpha);
        }
    }
    Class platterView = objc_getClass("SBFloatingDockPlatterView");
    if (platterView) {
        Method m = class_getInstanceMethod(platterView, @selector(setBackgroundView:));
        if (m) {
            orig_setBackgroundView = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_setBackgroundView);
        }
    }
}

#pragma mark - Hide Icon Labels

static void (*orig_applyIconLabelAlpha)(id self, SEL _cmd, double alpha);
static void hook_applyIconLabelAlpha(id self, SEL _cmd, double alpha) {
    orig_applyIconLabelAlpha(self, _cmd, 0.0);
}

static void initHideIconLabels(void) {
    Class iconView = objc_getClass("SBIconView");
    if (!iconView) return;
    Method m = class_getInstanceMethod(iconView, @selector(_applyIconLabelAlpha:));
    if (m) {
        orig_applyIconLabelAlpha = (void *)method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_applyIconLabelAlpha);
    }
}

#pragma mark - Status Bar gesture

@implementation SpringBoard(Hook)
+ (SpringBoard *)sharedApplication {
    return (id)UIApplication.sharedApplication;
}
- (void)initStatusBarGesture {
    [self.statusBarForEmbeddedDisplay addGestureRecognizer:[[UILongPressGestureRecognizer alloc]
                                                            initWithTarget:self action:@selector(statusBarLongPressed:)
    ]];
}

- (void)showInjectedAlert {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Coruna"
        message:@"SpringBoard is pwned. Long-press on the status bar to activate this menu." preferredStyle:UIAlertControllerStyleAlert];

    [alert addAction:[UIAlertAction actionWithTitle:@"Install TrollStore helper to Tips"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *hp = @"/tmp/PersistenceHelper_Embedded";
        if ([[NSFileManager defaultManager] fileExistsAtPath:hp]) {
            showAlert(@"Ready", @"PersistenceHelper is at /tmp/.\nNow open Tips app - it will launch PersistenceHelper instead!");
        } else {
            showAlert(@"Downloading...", @"PersistenceHelper is being downloaded. Wait a moment and try again.");
        }
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Status Bar Settings"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        [self showStatusBarSettings];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Action Button: Flashlight"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        showAlert(@"Action Button", @"Single click: Toggle flashlight\nDouble click: Magic ✨\nLong press: Original action (Siri, Shortcut, etc.)\n\niPhone 15 Pro+ only (iOS 17)");
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Load .dylib tweak"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        UIDocumentPickerViewController *documentPickerVC = [[UIDocumentPickerViewController alloc]
                initForOpeningContentTypes:@[[UTType typeWithFilenameExtension:@"dylib" conformingToType:UTTypeData]]
                asCopy:NO];
        documentPickerVC.allowsMultipleSelection = YES;
        documentPickerVC.delegate = (id<UIDocumentPickerDelegate>)self;
        [SpringBoard.viewControllerToPresent presentViewController:documentPickerVC animated:YES completion:nil];
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Activate FLEX"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        Class flexManagerClass = NSClassFromString(@"FLEXManager");
        if (flexManagerClass) {
            id sharedManager = [flexManagerClass valueForKey:@"sharedManager"];
            [sharedManager performSelector:@selector(showExplorer)];
        } else {
            showAlert(@"Error", @"FLEXManager not found. Please load libFLEX.dylib first");
        }
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Respring (will remove inject)"
        style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        exit(0);
    }]];

    [alert addAction:[UIAlertAction actionWithTitle:@"Cancel"
        style:UIAlertActionStyleCancel handler:nil]];

    [SpringBoard.viewControllerToPresent presentViewController:alert animated:YES completion:nil];
}
- (void)showStatusBarSettings {
    UIAlertController *settings = [UIAlertController alertControllerWithTitle:@"Status Bar Settings"
        message:@"Set time and date format.\nExamples:\n  Time: HH:mm  HH:mm:ss  h:mm a\n  Date: E dd/MM/yyyy  EE d/M/yy\n\nLeave date empty to show time only."
        preferredStyle:UIAlertControllerStyleAlert];

    [settings addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"Time format (e.g. HH:mm)";
        tf.text = getTimeFormat();
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];

    [settings addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"Date format (e.g. E dd/MM/yyyy)";
        tf.text = getDateFormat();
        tf.clearButtonMode = UITextFieldViewModeWhileEditing;
    }];

    [settings addAction:[UIAlertAction actionWithTitle:@"Apply" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        NSString *timeFmt = settings.textFields[0].text;
        NSString *dateFmt = settings.textFields[1].text;

        if (timeFmt.length == 0) timeFmt = @"HH:mm";

        // Validate formats by trying them
        NSDateFormatter *testFmt = [[NSDateFormatter alloc] init];
        [testFmt setDateFormat:timeFmt];
        NSString *testResult = [testFmt stringFromDate:[NSDate date]];
        if (!testResult || testResult.length == 0) {
            showAlert(@"Error", [NSString stringWithFormat:@"Invalid time format: %@", timeFmt]);
            return;
        }
        if (dateFmt.length > 0) {
            [testFmt setDateFormat:dateFmt];
            testResult = [testFmt stringFromDate:[NSDate date]];
            if (!testResult || testResult.length == 0) {
                showAlert(@"Error", [NSString stringWithFormat:@"Invalid date format: %@", dateFmt]);
                return;
            }
        }

        g_timeFormat = [timeFmt copy];
        g_dateFormat = [dateFmt copy];

        initStatusBarTweak();
        showAlert(@"Applied", [NSString stringWithFormat:@"Time: %@\nDate: %@\nLock and unlock for changes to take effect.",
            g_timeFormat, g_dateFormat.length > 0 ? g_dateFormat : @"(none)"]);
    }]];

    [settings addAction:[UIAlertAction actionWithTitle:@"Default" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        g_timeFormat = nil;
        g_dateFormat = nil;
        initStatusBarTweak();
        showAlert(@"Reset", @"Status bar reset to default (HH:mm / E dd/MM/yyyy).\nLock and unlock for changes to take effect.");
    }]];

    [settings addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];

    [SpringBoard.viewControllerToPresent presentViewController:settings animated:YES completion:nil];
}

// Document picker delegate
- (void)documentPicker:(UIDocumentPickerViewController *)controller didPickDocumentsAtURLs:(NSArray<NSURL *> *)urls {
    if (urls.count <= 0) return;
    NSString *log = @"";
    for (NSURL *url in urls) {
        NSString *path = url.path;
        log = [log stringByAppendingFormat:@"Load %@:", path.lastPathComponent];
        //if (![[NSFileManager defaultManager] fileExistsAtPath:path]) return;
        void *handle = dlopen(path.UTF8String, RTLD_NOW);
        if (handle) {
            log = [log stringByAppendingString:@" Success!\n"];
        } else {
            log = [log stringByAppendingFormat:@" Failed: %s\n", dlerror()];
        }
    }
    showAlert(@"Result", log);
}

- (void)statusBarLongPressed:(UILongPressGestureRecognizer *)gesture {
    if (gesture.state == UIGestureRecognizerStateBegan) {
        [self showInjectedAlert];
    }
}

+ (UIViewController *)viewControllerToPresent {
    UIViewController *root = UIApplication.sharedApplication.keyWindow.rootViewController;
    while (root.presentedViewController) root = root.presentedViewController;
    return root;
}
@end

#pragma mark - Action Button Tweak (iOS 17 - SBRingerHardwareButton)

static BOOL g_actionLongPressActive = NO;
static id g_lastDownEvent = nil;
static NSInteger g_clickCount = 0;
static NSTimeInterval g_firstClickTime = 0;
static dispatch_source_t g_clickTimer = nil;

static const NSTimeInterval kDoubleClickInterval = 0.22;
static const NSTimeInterval kSingleClickTimeout = 0.52;

static IMP orig_configureButtonArbiter = NULL;
static IMP orig_actionButtonDown = NULL;
static IMP orig_actionButtonUp = NULL;
static IMP orig_actionButtonLongPress = NULL;

static void toggleFlashlight(void) {
    Class cls = objc_getClass("SBUIFlashlightController");
    if (!cls) return;
    id controller = ((id (*)(id, SEL))objc_msgSend)((id)cls, sel_registerName("sharedInstance"));
    if (!controller) return;
    NSUInteger level = ((NSUInteger (*)(id, SEL))objc_msgSend)(controller, sel_registerName("level"));
    ((void (*)(id, SEL, NSUInteger))objc_msgSend)(controller, sel_registerName("setLevel:"), level > 0 ? 0 : 1);
}

static void openDoubleClickURL(void) {
    NSURL *url = [NSURL URLWithString:@"https://www.youtube.com/watch?v=dQw4w9WgXcQ"];
    ((void (*)(id, SEL, id, id, id))objc_msgSend)(
        [UIApplication sharedApplication],
        sel_registerName("openURL:options:completionHandler:"),
        url, @{}, nil);
}

static void cancelClickTimer(void) {
    if (g_clickTimer) {
        dispatch_source_cancel(g_clickTimer);
        g_clickTimer = nil;
    }
}

static void hook_configureButtonArbiter(id self, SEL _cmd) {
    ((void (*)(id, SEL))orig_configureButtonArbiter)(self, _cmd);
    // Disable multi-click detection so buttonUp fires immediately
    Ivar arbiterIvar = class_getInstanceVariable(object_getClass(self), "_buttonArbiter");
    if (!arbiterIvar) return;
    id arbiter = object_getIvar(self, arbiterIvar);
    if (!arbiter) return;
    SEL setMaxSel = sel_registerName("setMaximumRepeatedPressCount:");
    if ([arbiter respondsToSelector:setMaxSel]) {
        ((void (*)(id, SEL, unsigned long long))objc_msgSend)(arbiter, setMaxSel, 0);
    }
}

static void hook_actionButtonDown(id self, SEL _cmd, id event) {
    g_lastDownEvent = event;
    // Suppress original — we handle action on button up
}

static void hook_actionButtonUp(id self, SEL _cmd, id event) {
    if (g_actionLongPressActive) {
        g_actionLongPressActive = NO;
        ((void (*)(id, SEL, id))orig_actionButtonUp)(self, _cmd, event);
        return;
    }

    NSTimeInterval now = [[NSProcessInfo processInfo] systemUptime];
    g_clickCount++;

    if (g_clickCount == 1) {
        g_firstClickTime = now;
        cancelClickTimer();
        // Wait for possible second click
        g_clickTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
        dispatch_source_set_timer(g_clickTimer,
            dispatch_time(DISPATCH_TIME_NOW, (int64_t)(kSingleClickTimeout * NSEC_PER_SEC)), DISPATCH_TIME_FOREVER, 0);
        dispatch_source_set_event_handler(g_clickTimer, ^{
            cancelClickTimer();
            g_clickCount = 0;
            toggleFlashlight();
        });
        dispatch_resume(g_clickTimer);
    } else if (g_clickCount >= 2) {
        NSTimeInterval interval = now - g_firstClickTime;
        cancelClickTimer();
        g_clickCount = 0;
        if (interval <= kDoubleClickInterval) {
            openDoubleClickURL();
        } else {
            // Too slow for double click — treat as single click
            toggleFlashlight();
        }
    }
}

static void hook_actionButtonLongPress(id self, SEL _cmd, id event) {
    g_actionLongPressActive = YES;
    cancelClickTimer();
    g_clickCount = 0;
    // Pass through to original long press (Siri, Shortcut, etc.)
    ((void (*)(id, SEL, id))orig_actionButtonDown)(self, _cmd, g_lastDownEvent);
    ((void (*)(id, SEL, id))orig_actionButtonLongPress)(self, _cmd, event);
}

static void initActionButtonTweak(void) {
    Class cls = objc_getClass("SBRingerHardwareButton");
    if (!cls) return;

    Method m;

    m = class_getInstanceMethod(cls, @selector(_configureButtonArbiter));
    if (m) {
        orig_configureButtonArbiter = method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_configureButtonArbiter);
    }

    m = class_getInstanceMethod(cls, @selector(performActionsForButtonDown:));
    if (m) {
        orig_actionButtonDown = method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_actionButtonDown);
    }

    m = class_getInstanceMethod(cls, @selector(performActionsForButtonUp:));
    if (m) {
        orig_actionButtonUp = method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_actionButtonUp);
    }

    m = class_getInstanceMethod(cls, @selector(performActionsForButtonLongPress:));
    if (m) {
        orig_actionButtonLongPress = method_getImplementation(m);
        method_setImplementation(m, (IMP)hook_actionButtonLongPress);
    }
}

#pragma mark - FrontBoard Trust Bypass (AppSync-like)

static IMP orig_trustStateForApplication = NULL;
static NSUInteger hook_trustStateForApplication(id self, SEL _cmd, id application) {
    return 8; // Always trusted (iOS 14+)
}

static void initFrontBoardBypass(void) {
    Class cls = objc_getClass("FBSSignatureValidationService");
    if (cls) {
        Method m = class_getInstanceMethod(cls, @selector(trustStateForApplication:));
        if (m) {
            orig_trustStateForApplication = method_getImplementation(m);
            method_setImplementation(m, (IMP)hook_trustStateForApplication);
        }
    }
}

#pragma mark - RBSLaunchContext Hook (Tips -> PersistenceHelper)

@interface RBSLaunchContext : NSObject
@property (nonatomic, copy, readonly) NSString *bundleIdentifier;
@end
@implementation RBSLaunchContext(Hook)
- (NSString *)_overrideExecutablePath {
    if([self.bundleIdentifier isEqualToString:@"com.apple.tips"]) {
        return @"/tmp/PersistenceHelper_Embedded";
    }
    return nil;
}
@end

#pragma mark - Helpers

void showAlert(NSString *title, NSString *message) {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title message:message preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [SpringBoard.viewControllerToPresent presentViewController:a animated:YES completion:nil];
}

static NSData *downloadFile(NSString *urlString) {
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:urlString]
                                             cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                         timeoutInterval:60];
    __block NSData *downloadedData = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            downloadedData = data;
            dispatch_semaphore_signal(sem);
        }];
    [task resume];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return downloadedData;
}

#pragma mark - Constructor

__attribute__((constructor)) static void init() {
    initFrontBoardBypass();
    initStatusBarTweak();
    initActionButtonTweak();
    initDockTransparency();
    initHideIconLabels();
    [SpringBoard.sharedApplication initStatusBarGesture];

    // Auto-download PersistenceHelper to /tmp if not present
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSString *helperPath = @"/tmp/PersistenceHelper_Embedded";
        if (![[NSFileManager defaultManager] fileExistsAtPath:helperPath]) {
            NSString *url = @"https://github.com/opa334/TrollStore/releases/download/2.1/PersistenceHelper_Embedded";
            NSData *data = downloadFile(url);
            if (data && data.length > 0) {
                [data writeToFile:helperPath atomically:YES];
                chmod(helperPath.UTF8String, 0755);
            }
        }
    });

    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *flag = @"/tmp/.coruna_welcomed";
        if (![[NSFileManager defaultManager] fileExistsAtPath:flag]) {
            [@"" writeToFile:flag atomically:YES encoding:NSUTF8StringEncoding error:nil];
            UIAlertController *welcome = [UIAlertController alertControllerWithTitle:@"Welcome to Coruna"
                message:@"Your device has been jailbroken!\n\n"
                         "Features enabled:\n"
                         "  \u2022 Custom status bar (time + date)\n"
                         "  \u2022 Action button \u2192 Flashlight\n"
                         "  \u2022 Transparent dock\n"
                         "  \u2022 Hidden icon labels\n"
                         "  \u2022 TrollStore helper\n\n"
                         "Long-press the status bar for settings."
                preferredStyle:UIAlertControllerStyleAlert];
            [welcome addAction:[UIAlertAction actionWithTitle:@"Let's go!" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
                [SpringBoard.sharedApplication showInjectedAlert];
            }]];
            [SpringBoard.viewControllerToPresent presentViewController:welcome animated:YES completion:nil];
        } else {
            [SpringBoard.sharedApplication showInjectedAlert];
        }
    });
}
