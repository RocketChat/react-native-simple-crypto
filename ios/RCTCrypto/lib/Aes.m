#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "Shared.h"
#import "Aes.h"

@implementation Aes

+ (NSData *) AES128CBC: (NSString *)operation data: (NSData *)data key: (NSString *)key iv: (NSString *)iv {
    // Convert hex string to hex data.
    NSData *keyData = [Shared fromHex:key];
    NSData *ivData = [Shared fromHex:iv];
    size_t numBytes = 0;
    NSMutableData *buffer = [[NSMutableData alloc] initWithLength:[data length] + kCCBlockSizeAES128];

    CCCryptorStatus cryptStatus = CCCrypt(
                                          [operation isEqualToString:@"encrypt"] ? kCCEncrypt : kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          keyData.length,
                                          ivData.bytes,
                                          data.bytes, data.length,
                                          buffer.mutableBytes,
                                          buffer.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
        [buffer setLength:numBytes];
        return buffer;
    }
    NSLog(@"AES error, %d", cryptStatus);
    return nil;
}

+ (NSString *) encrypt: (NSString *)clearText64 key: (NSString *)key iv: (NSString *)iv {
    NSData* clearData = [[NSData alloc] initWithBase64EncodedString:clearText64 options:0];
    NSData *result = [self AES128CBC:@"encrypt" data:clearData key:key iv:iv];
    return [result base64EncodedStringWithOptions:0];
}

+ (NSString *) decrypt: (NSString *)cipherText key: (NSString *)key iv: (NSString *)iv {
    NSData *result = [self AES128CBC:@"decrypt" data:[[NSData alloc] initWithBase64EncodedString:cipherText options:0] key:key iv:iv];
    return [result base64EncodedStringWithOptions:0];
}

+ (NSString *)processFile:(NSString *)filePath
                operation:(CCOperation)operation
                     key:(NSString *)keyBase64URL
                      iv:(NSString *)ivBase64 {
    NSString *keyBase64 = [Shared base64FromBase64URL:keyBase64URL];
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyBase64 options:0];
    NSData *ivData = [[NSData alloc] initWithBase64EncodedString:ivBase64 options:0];

    NSString *normalizedFilePath = [filePath stringByReplacingOccurrencesOfString:@"file://" withString:@""];
    NSString *outputFileName = [@"processed_" stringByAppendingString:[normalizedFilePath lastPathComponent]];
    NSString *outputFilePath = [[normalizedFilePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:outputFileName];
    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:normalizedFilePath];
    NSOutputStream *outputStream = [NSOutputStream outputStreamToFileAtPath:outputFilePath append:NO];
    [inputStream open];
    [outputStream open];

    size_t bufferSize = 4096;
    uint8_t buffer[bufferSize];
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = CCCryptorCreateWithMode(operation, kCCModeCTR, kCCAlgorithmAES, ccNoPadding, ivData.bytes, keyData.bytes, keyData.length, NULL, 0, 0, kCCModeOptionCTR_BE, &cryptor);
    if (status != kCCSuccess) {
        NSLog(@"Failed to create cryptor: %d", status);
        [inputStream close];
        [outputStream close];
        return nil;
    }

    while ([inputStream hasBytesAvailable]) {
        NSInteger bytesRead = [inputStream read:buffer maxLength:sizeof(buffer)];
        if (bytesRead > 0) {
            size_t dataOutMoved;
            status = CCCryptorUpdate(cryptor, buffer, bytesRead, buffer, bufferSize, &dataOutMoved);
            if (status == kCCSuccess) {
                [outputStream write:buffer maxLength:dataOutMoved];
            } else {
                NSLog(@"Cryptor update failed: %d", status);
                return nil;
                break;
            }
        } else if (bytesRead < 0) {
            NSLog(@"Input stream read error");
            status = kCCDecodeError;
            return nil;
            break;
        }
    }

    if (status == kCCSuccess) {
        size_t finalBytesOut;
        status = CCCryptorFinal(cryptor, buffer, bufferSize, &finalBytesOut);
        if (status == kCCSuccess) {
            [outputStream write:buffer maxLength:finalBytesOut];
        } else {
            NSLog(@"Cryptor final failed: %d", status);
            return nil;
        }
    }

    CCCryptorRelease(cryptor);
    [inputStream close];
    [outputStream close];

    if (status == kCCSuccess) {
        NSURL *originalFileURL = [NSURL fileURLWithPath:normalizedFilePath];
        NSURL *outputFileURL = [NSURL fileURLWithPath:outputFilePath];
        NSError *error = nil;
        [[NSFileManager defaultManager] replaceItemAtURL:originalFileURL
                                          withItemAtURL:outputFileURL
                                         backupItemName:nil
                                                options:NSFileManagerItemReplacementUsingNewMetadataOnly
                                       resultingItemURL:nil
                                                  error:&error];
        if (error) {
            NSLog(@"Failed to replace original file: %@", error);
            return nil;
        }
        return [NSString stringWithFormat:@"file://%@", normalizedFilePath];
    } else {
        // Clean up temp file in case of failure
        [[NSFileManager defaultManager] removeItemAtPath:outputFilePath error:nil];
        return nil;
    }
}

+ (NSString *)encryptFile:(NSString *)filePath key:(NSString *)key iv:(NSString *)iv {
    return [self processFile:filePath operation:kCCEncrypt key:key iv:iv];
}

+ (NSString *)decryptFile:(NSString *)filePath key:(NSString *)key iv:(NSString *)iv {
    return [self processFile:filePath operation:kCCDecrypt key:key iv:iv];
}

@end
