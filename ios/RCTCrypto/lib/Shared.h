#import <Foundation/Foundation.h>

@interface Shared : NSObject
+ (NSString *) toHex: (NSData *)nsdata;
+ (NSData *) fromHex: (NSString *)string;
+ (NSString *)base64FromBase64URL:(NSString *)base64URL;
+ (NSString *)calculateFileChecksum:(NSString *)filePath;
+ (NSString *)getRandomValues: (NSUInteger)length;
@end
