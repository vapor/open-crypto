//
//  HMAC.swift
//  Crypto
//
//  Created by Joannis Orlandos on 04/08/2016.
//
//

/// Used to authenticate messages using the `Hash` algorithm
public class HMAC<Variant: Hash> {
    /// Authenticates a message using the provided `Hash` algorithm
    /// 
    /// - parameter message: The message to authenticate
    /// - parameter key: The key to authenticate with
    ///
    /// - returns: The authenticated message
    public static func authenticate(_ message: [UInt8], withKey key: [UInt8]) -> [UInt8] {
        var key = key
        
        // If it's too long, hash it first
        if key.count > Variant.blockSize {
            key = Variant.hash(key)
        }
        
        // Add padding
        if key.count < Variant.blockSize {
            key = key + [UInt8](repeating: 0, count: Variant.blockSize - key.count)
        }
        
        // XOR the information
        var outerPadding = [UInt8](repeating: 0x5c, count: Variant.blockSize)
        var innerPadding = [UInt8](repeating: 0x36, count: Variant.blockSize)
        
        for (index, _) in key.enumerated() {
            outerPadding[index] = key[index] ^ outerPadding[index]
        }
        
        for (index, _) in key.enumerated() {
            innerPadding[index] = key[index] ^ innerPadding[index]
        }
        
        // Hash the information
        let innerPaddingHash = Variant.hash(innerPadding + message)
        let outerPaddingHash = Variant.hash(outerPadding + innerPaddingHash)
        
        return outerPaddingHash
    }
}
