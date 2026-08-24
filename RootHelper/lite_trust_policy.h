#import <Foundation/Foundation.h>

#ifdef TROLLSTORE_LITE

NS_ASSUME_NONNULL_BEGIN

NSArray<NSString *> *TSLitePreservedTrustIdentitiesForApp(NSString *appPath,
                                                          NSArray<NSString *> *launchExecutablePaths);

NS_ASSUME_NONNULL_END

#endif
