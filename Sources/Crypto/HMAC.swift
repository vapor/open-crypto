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
        if key.count > Variant.chunkSize {
            key = Variant.hash(key)
        }
        
        // Add padding
        if key.count < Variant.chunkSize {
            key = key + [UInt8](repeating: 0, count: Variant.chunkSize - key.count)
        }
        
        // XOR the information
        var outerPadding = [UInt8](repeating: 0x5c, count: Variant.chunkSize)
        var innerPadding = [UInt8](repeating: 0x36, count: Variant.chunkSize)
        
        for i in 0..<key.count {
            outerPadding[i] = key[i] ^ outerPadding[i]
        }
        
        for i in 0..<key.count {
            innerPadding[i] = key[i] ^ innerPadding[i]
        }
        
        // Hash the information
        let innerPaddingHash: [UInt8] = Variant.hash(innerPadding + message)
        let outerPaddingHash: [UInt8] = Variant.hash(outerPadding + innerPaddingHash)
        
        return outerPaddingHash
    }
}
