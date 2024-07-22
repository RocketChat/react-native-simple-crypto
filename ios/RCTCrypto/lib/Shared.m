#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonKeyDerivation.h>

#import "Shared.h"

@implementation Shared

+ (NSString *) toHex:(NSData *)nsdata {
    // Copied from: https://riptutorial.com/ios/example/18979/converting-nsdata-to-hex-string
    const unsigned char *bytes = (const unsigned char *)nsdata.bytes;
    NSMutableString *hex = [NSMutableString new];
    for (NSInteger i = 0; i < nsdata.length; i++) {
        [hex appendFormat:@"%02x", bytes[i]];
    }
    return [hex copy];
}

+ (NSData *) fromHex: (NSString *)string {
    NSMutableData *data = [[NSMutableData alloc] init];
    unsigned char whole_byte;
    char byte_chars[3] = {'\0','\0','\0'};
    for (int i = 0; i < ([string length] / 2); i++) {
        byte_chars[0] = [string characterAtIndex:i*2];
        byte_chars[1] = [string characterAtIndex:i*2+1];
        whole_byte = strtol(byte_chars, NULL, 16);
        [data appendBytes:&whole_byte length:1];
    }
    return data;
}

+ (NSString *)base64FromBase64URL:(NSString *)base64URL {
    NSMutableString *base64 = [NSMutableString stringWithString:base64URL];
    [base64 replaceOccurrencesOfString:@"-" withString:@"+" options:NSLiteralSearch range:NSMakeRange(0, base64.length)];
    [base64 replaceOccurrencesOfString:@"_" withString:@"/" options:NSLiteralSearch range:NSMakeRange(0, base64.length)];
    
    // Pad with '=' to ensure the base64 string length is a multiple of 4
    while (base64.length % 4 != 0) {
        [base64 appendString:@"="];
    }
    return base64;
}

+ (NSString *)calculateFileChecksum:(NSString *)filePath {
    NSString *normalizedFilePath = [filePath stringByReplacingOccurrencesOfString:@"file://" withString:@""];
    NSInputStream *inputStream = [NSInputStream inputStreamWithFileAtPath:normalizedFilePath];
    [inputStream open];

    if (!inputStream) {
        NSLog(@"Failed to open file: %@", filePath);
        return nil;
    }

    CC_SHA256_CTX sha256;
    CC_SHA256_Init(&sha256);

    uint8_t buffer[4096];
    NSInteger bytesRead = 0;

    while ((bytesRead = [inputStream read:buffer maxLength:sizeof(buffer)]) > 0) {
        CC_SHA256_Update(&sha256, buffer, (CC_LONG)bytesRead);
    }

    [inputStream close];

    if (bytesRead < 0) {
        NSLog(@"File read error: %@", filePath);
        return nil;
    }

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &sha256);

    NSMutableString *checksum = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [checksum appendFormat:@"%02x", hash[i]];
    }

    return checksum;
}

+ (NSString *)getRandomValues:(NSUInteger)length {
    static const char alphanumericChars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    NSMutableData *randomData = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault, length, randomData.mutableBytes);
    if (result != 0) {
        return nil;
    }
    
    NSMutableString *randomString = [NSMutableString stringWithCapacity:length];
    const unsigned char *dataBytes = (const unsigned char *)randomData.bytes;
    
    for (NSUInteger i = 0; i < length; i++) {
        [randomString appendFormat:@"%c", alphanumericChars[dataBytes[i] % (sizeof(alphanumericChars) - 1)]];
    }
    
    return [randomString copy];
}

@end
