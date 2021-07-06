//
//  RCTRsaUtils.swift
//  RCTCrypto
//
//  Created by Djorkaeff Alexandre Vilela Pereira on 8/18/20.
//  Copyright © 2020 pedrouid. All rights reserved.
//

import Foundation

public extension String {
    
    func base64URLDecode() -> Data? {
        var str = self
        str = str.padding(toLength: ((str.count + 3) / 4) * 4, withPad: "=", startingAt: 0)
        str = str.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        return Data(base64Encoded: str)
    }
}

extension Data {
    
    func base64URLEncode() -> String {
        let d = self
        let str = d.base64EncodedString()
        return str.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

@objc(RCTRsaUtils)
public class RCTRsaUtils: NSObject {
    
    @objc
    func importKey(_ jwk: NSDictionary, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        if let key = importKey(jwk: jwk) {
            resolve(key)
        } else {
            let error = NSError(domain: "", code: 200, userInfo: nil)
            reject("E_IMPORTING", "Impossible to import given key", error)
        }
    }
    
    public func importKey(jwk: NSDictionary) -> String? {
        let rsakey = RSA_new()
        defer { RSA_free(rsakey) }
        var isPublic = true
        var new_n, new_e, new_d, new_p, new_q, new_dp, new_dq, new_qi: OpaquePointer?

        if let n = jwk["n"] as? String {
            new_n = try? base64URLToBignum(n)
        }
        if let e = jwk["e"] as? String {
            new_e = try? base64URLToBignum(e)
        }
        if let d = jwk["d"] as? String {
            new_d = try? base64URLToBignum(d)
            isPublic = false
        }
        if let p = jwk["p"] as? String {
            new_p = try? base64URLToBignum(p)
        }
        if let q = jwk["q"] as? String {
            new_q = try? base64URLToBignum(q)
        }
        if let dq = jwk["dq"] as? String {
            new_dq = try? base64URLToBignum(dq)
        }
        if let dp = jwk["dp"] as? String {
            new_dp = try? base64URLToBignum(dp)
        }
        if let qi = jwk["qi"] as? String {
            new_qi = try? base64URLToBignum(qi)
        }
        
        RSA_set0_key(rsakey, new_n, new_e, new_d)
        RSA_set0_factors(rsakey, new_p, new_q)
        RSA_set0_crt_params(rsakey, new_dp, new_dq, new_qi)
        
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }
        
        var retval: Int32
        if isPublic {
            retval = PEM_write_bio_RSAPublicKey(bio, rsakey)
        } else {
            retval = PEM_write_bio_RSAPrivateKey(bio, rsakey, nil, nil, 0, nil, nil)
        }
        let publicKeyLen = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        
        guard retval == 1, publicKeyLen > 0 else {
            return nil
        }
        
        let publicKey: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(publicKeyLen))
        BIO_read(bio, publicKey, Int32(publicKeyLen))
        
        if let publicKey = publicKey {
            let pk = Data(bytes: publicKey, count: Int(publicKeyLen))
            return String(data: pk, encoding: .utf8)
        }
        
        return nil
    }
    
    @objc
    func exportKey(_ pkcs1: NSString, resolver resolve: RCTPromiseResolveBlock, rejecter reject: RCTPromiseRejectBlock) -> Void {
        let jwk = exportKey(pkcs1: pkcs1)
        resolve(jwk)
    }
    
    public func exportKey(pkcs1: NSString) -> [String: Any] {
        let bio = BIO_new_mem_buf(pkcs1.utf8String, Int32(pkcs1.length))
        defer { BIO_free(bio) }
        
        let isPublic = pkcs1.contains("PUBLIC")
        let reader = isPublic ? PEM_read_bio_RSAPublicKey : PEM_read_bio_RSAPrivateKey
        let rsaKey = reader(bio, nil, nil, nil)
        
        var jwk = [
            "alg": "RSA-OAEP-256",
            "ext": true,
            "key_ops": [isPublic ? "encrypt" : "decrypt"],
            "kty": "RSA"
        ] as [String : Any]
        
        if let d = RSA_get0_d(rsaKey) {
            jwk["d"] = bigNumToBase64(d)
        }
        if let e = RSA_get0_e(rsaKey) {
            jwk["e"] = bigNumToBase64(e)
        }
        if let n = RSA_get0_n(rsaKey) {
            jwk["n"] = bigNumToBase64(n)
        }
        if let p = RSA_get0_p(rsaKey) {
            jwk["p"] = bigNumToBase64(p)
        }
        if let q = RSA_get0_q(rsaKey) {
            jwk["q"] = bigNumToBase64(q)
        }
        if let dp = RSA_get0_dmp1(rsaKey) {
            jwk["dp"] = bigNumToBase64(dp)
        }
        if let dq = RSA_get0_dmq1(rsaKey) {
            jwk["dq"] = bigNumToBase64(dq)
        }
        if let qi = RSA_get0_iqmp(rsaKey) {
            jwk["qi"] = bigNumToBase64(qi)
        }
        
        return jwk
    }
    
    private func bigNumToBase64(_ bn: OpaquePointer) -> String {
        var bytes = [UInt8](repeating: 0, count: Int(BN_num_bits(bn) + 7) / 8)
        BN_bn2bin(bn, &bytes)
        return Data(bytes: bytes, count: bytes.count).base64URLEncode()
    }
    
    private func base64URLToBignum(_ str: String) throws -> OpaquePointer {
        guard let data = str.base64URLDecode() else {
            throw NSError(domain: "", code: 200, userInfo: nil)
        }
        let array = [UInt8](data)
        return array.withUnsafeBufferPointer { p in
            let bn: OpaquePointer = OpaquePointer.make(optional: BN_bin2bn(p.baseAddress, Int32(p.count), nil))!
            return bn
        }
    }
}


extension OpaquePointer {
    init(_ ptr: OpaquePointer) {
        self = ptr
    }

    static func make(optional ptr: OpaquePointer?) -> OpaquePointer? {
        return ptr.map(OpaquePointer.init)
    }

    static func make(optional ptr: UnsafeMutableRawPointer?) -> OpaquePointer? {
        return ptr.map(OpaquePointer.init)
    }

    static func make<Pointee>(optional ptr: UnsafeMutablePointer<Pointee>?) -> OpaquePointer? {
        return ptr.map(OpaquePointer.init)
    }
}
