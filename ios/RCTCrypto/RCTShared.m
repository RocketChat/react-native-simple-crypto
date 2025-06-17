#import "RCTShared.h"
#import "Shared.h"

@implementation RCTShared

RCT_EXPORT_MODULE()
 
RCT_EXPORT_METHOD(calculateFileChecksum:(NSString *)filePath resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    NSError *error = nil;
    NSString *data = [Shared calculateFileChecksum:filePath];
    if (data == nil) {
        reject(@"shared_checksum_fail", @"Checksum error", error);
    } else {
        resolve(data);
    }
}

RCT_EXPORT_METHOD(getRandomValues:(NSUInteger)length resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    NSString *randomString = [Shared getRandomValues:length];
    if (randomString == nil) {
        reject(@"shared_random_fail", @"Random value generation error", nil);
    } else {
        resolve(randomString);
    }
}

@end
