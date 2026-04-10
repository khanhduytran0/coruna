@import UIKit;

static void showAlert(NSString *title, NSString *message);

@interface SpringBoard : UIApplication
+ (SpringBoard *)sharedApplication;
- (UIView *)statusBarForEmbeddedDisplay;
@end
