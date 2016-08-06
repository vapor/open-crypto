import Core
import Essentials

/// Used to authenticate messages using the `Hash` algorithm
public class HMAC<Variant: Hash> {
    public let variant: Variant
    public init(_ variant: Variant) {
        self.variant = variant
    }
    /// Authenticates a message using the provided `Hash` algorithm
    /// 
    /// - parameter message: The message to authenticate
    /// - parameter key: The key to authenticate with
    ///
    /// - returns: The authenticated message
    public func authenticate(_ message: Bytes, key: Bytes) throws -> Bytes {
        var key = key
        
        // If it's too long, hash it first
        if key.count > Variant.blockSize {
            key = try variant.hash(key)
        }
        
        // Add padding
        if key.count < Variant.blockSize {
            key = key + Bytes(repeating: 0, count: Variant.blockSize - key.count)
        }
        
        // XOR the information
        var outerPadding = Bytes(repeating: 0x5c, count: Variant.blockSize)
        var innerPadding = Bytes(repeating: 0x36, count: Variant.blockSize)
        
        for (index, _) in key.enumerated() {
            outerPadding[index] = key[index] ^ outerPadding[index]
        }
        
        for (index, _) in key.enumerated() {
            innerPadding[index] = key[index] ^ innerPadding[index]
        }
        
        // Hash the information
        let innerPaddingHash = try variant.hash(innerPadding + message)
        let outerPaddingHash = try variant.hash(outerPadding + innerPaddingHash)
        
        return outerPaddingHash
    }
}
