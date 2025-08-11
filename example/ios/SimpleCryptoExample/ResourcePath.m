//
//  ResourcePath.m
//  SimpleCryptoExample
//
//  Created by Diego Mello on 17/06/25.
//

#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(ResourcePath, NSObject)
RCT_EXTERN_METHOD(getResourcePath:(NSString *)resourceName
                  ext:(NSString *)ext
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)
@end
