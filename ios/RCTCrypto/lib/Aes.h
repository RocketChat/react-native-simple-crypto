#import <Foundation/Foundation.h>

@interface Aes : NSObject
+ (NSString *) encrypt: (NSString *)clearText64  key: (NSString *)key iv: (NSString *)iv;
+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv;
+ (NSData *) AES128CBC: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv;
@end
