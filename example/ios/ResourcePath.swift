import Foundation
import React

@objc(ResourcePath)
class ResourcePath: NSObject {
  @objc
  static func requiresMainQueueSetup() -> Bool {
    return false
  }

  @objc
  func getResourcePath(_ resourceName: String, ext: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
    if let path = Bundle.main.path(forResource: resourceName, ofType: ext) {
      resolve(path)
    } else {
      reject("not_found", "Resource not found", nil)
    }
  }
} 