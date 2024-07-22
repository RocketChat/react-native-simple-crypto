#import <Foundation/Foundation.h>

@interface Aes : NSObject

// Encrypt and decrypt methods for base64-encoded string data
+ (NSString *)encrypt:(NSString *)clearText64 key:(NSString *)key iv:(NSString *)iv;
+ (NSString *)decrypt:(NSString *)cipherText key:(NSString *)key iv:(NSString *)iv;

// Core AES CBC encryption/decryption method
+ (NSData *)AES128CBC:(NSString *)operation data:(NSData *)data key:(NSString *)key iv:(NSString *)iv;

// File encryption and decryption methods
+ (NSString *)encryptFile:(NSString *)filePath key:(NSString *)key iv:(NSString *)iv;
+ (NSString *)decryptFile:(NSString *)filePath key:(NSString *)key iv:(NSString *)iv;

@end
