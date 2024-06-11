#import "RCTAes.h"
#import "Aes.h"

@implementation RCTAes

RCT_EXPORT_MODULE()

RCT_EXPORT_METHOD(encrypt:(NSString *)dataBase64 key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *base64 = [Aes encrypt:dataBase64 key:key iv:iv];
    if (base64 == nil) {
        reject(@"encrypt_fail", @"Encrypt error", error);
    } else {
        resolve(base64);
    }
}

RCT_EXPORT_METHOD(decrypt:(NSString *)base64 key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [Aes decrypt:base64 key:key iv:iv];
    if (data == nil) {
        reject(@"decrypt_fail", @"Decrypt failed", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(encryptFile:(NSString *)filePath key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *encryptedFilePath = [Aes encryptFile:filePath key:key iv:iv];
    if (encryptedFilePath == nil) {
        reject(@"encrypt_file_fail", @"File encryption failed", nil);
    } else {
        resolve(encryptedFilePath);
    }
}

RCT_EXPORT_METHOD(decryptFile:(NSString *)filePath key:(NSString *)key iv:(NSString *)iv
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *decryptedFilePath = [Aes decryptFile:filePath key:key iv:iv];
    if (decryptedFilePath == nil) {
        reject(@"decrypt_file_fail", @"File decryption failed", nil);
    } else {
        resolve(decryptedFilePath);
    }
}

@end
