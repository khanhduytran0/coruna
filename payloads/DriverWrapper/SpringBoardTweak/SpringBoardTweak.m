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

            NSDateFormatter *formatter1 = [[NSDateFormatter alloc] init];
            [formatter1 setDateFormat:@"HH:mm"];
            UIFont *font1 = [UIFont systemFontOfSize:15.0 weight:UIFontWeightSemibold];
            NSAttributedString *attrString1 = [[NSAttributedString alloc] initWithString:[formatter1 stringFromDate:[NSDate date]]
                                                                              attributes:@{NSFontAttributeName: font1}];

            NSLocale *currentLocale = [NSLocale autoupdatingCurrentLocale];
            NSDateFormatter *formatter2 = [[NSDateFormatter alloc] init];
            [formatter2 setDateFormat:@"E dd/MM/yyyy"];
            [formatter2 setLocale:currentLocale];
            UIFont *font2 = [UIFont systemFontOfSize:8.0 weight:UIFontWeightRegular];
            NSAttributedString *attrString2 = [[NSAttributedString alloc] initWithString:[formatter2 stringFromDate:[NSDate date]]
                                                                              attributes:@{NSFontAttributeName: font2}];

            [finalString appendAttributedString:attrString1];
            [finalString appendAttributedString:[[NSAttributedString alloc] initWithString:@"\n"]];
            [finalString appendAttributedString:attrString2];

            label.textAlignment = NSTextAlignmentCenter;
            label.numberOfLines = 2;
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

    [alert addAction:[UIAlertAction actionWithTitle:@"Enable Status Bar Tweak"
        style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        initStatusBarTweak();
        showAlert(@"Done", @"Status bar tweak enabled!\nLock and unlock your device for it to take effect.");
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
    // Auto-enable status bar tweak on load (works on both iOS 16 and 17)
    initStatusBarTweak();
    // Add long press gesture to status bar
    [SpringBoard.sharedApplication initStatusBarGesture];
    
    // Auto-download PersistenceHelper to /tmp if not present
    NSString *helperPath = @"/tmp/PersistenceHelper_Embedded";
    if (![[NSFileManager defaultManager] fileExistsAtPath:helperPath]) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSString *url = @"https://github.com/opa334/TrollStore/releases/download/2.1/PersistenceHelper_Embedded";
            NSData *data = downloadFile(url);
            if (data && data.length > 0) {
                [data writeToFile:helperPath atomically:YES];
                chmod(helperPath.UTF8String, 0755);
            }
        });
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        // Show alert on load
        [SpringBoard.sharedApplication showInjectedAlert];
    });
}
