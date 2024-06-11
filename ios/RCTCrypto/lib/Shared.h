#import <Foundation/Foundation.h>

@interface Shared : NSObject
+ (NSString *) toHex: (NSData *)nsdata;
+ (NSData *) fromHex: (NSString *)string;
+ (NSString *)base64FromBase64URL:(NSString *)base64URL;
+ (NSString *)normalizeFilePath:(NSString *)filePath;
+ (NSString *)restoreFilePathSchemeIfNeeded:(NSString *)filePath originalPath:(NSString *)originalPath;
@end
