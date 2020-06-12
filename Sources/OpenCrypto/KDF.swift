//
//  KDF.swift
//
//
//  Created by Craz1k0ek on 12/06/2020.
//

import Foundation

/// Cryptographic key derivation.
///
/// https://en.wikipedia.org/wiki/Key_derivation_function
public enum KDF {
    
    /// Derives a symmetric encryption key from the secret using HKDF key derivation.
    /// - Parameters:
    ///   - hashFunction: The hash function to use for key derivation.
    ///   - ikm: The input key material.
    ///   - salt: The salt to use for key derivation.
    ///   - info: The shared information to use for key derivation.
    ///   - outputByteCount: The length in bytes of resulting symmetric key.
    /// - Returns: The derived symmetric key.
    ///
    /// https://en.wikipedia.org/wiki/HKDF
    public static func hkdf<H>(using hashFunction: H, secret ikm: Data, salt: Data? = nil, sharedInfo: Data = Data(), outputByteCount: Int) -> SymmetricKey where H: HashFunction {
        let salt = salt == nil ? Data(repeating: 0, count: H.Digest.byteCount) : salt!
        
        // Generate the PRK (extract).
        let pseudoRandomKey = HMAC<H>.authenticationCode(for: ikm, using: SymmetricKey(data: salt))
        
        // Prepare the OKM.
        var mixin = Data()
        var outputKeyMaterial = Data()
        
        // Perform the derivation (expand).
        for iteration in 0 ..< Int(ceil(Double(outputByteCount) / Double(H.Digest.byteCount))) {
            var preMixin = Data()
            preMixin.append(mixin)
            preMixin.append(sharedInfo)
            preMixin.append(Data([1 + UInt8(iteration)]))
            
            mixin = Data(HMAC<H>.authenticationCode(for: preMixin, using: SymmetricKey(data: pseudoRandomKey)))
            
            outputKeyMaterial += mixin
        }
        
        return SymmetricKey(data: outputKeyMaterial[0 ..< outputByteCount])
    }
    
}
