import Foundation

public protocol Hash: class {
    /// The amount of processed bytes per chunk
    static var chunkSize: Int { get }
    
    /// The amount of bytes returned in the hash
    static var digestSize: Int { get }
    
    /// If `true`, treat the bitlength in the padding at littleEndian, bigEndian otherwise
    static var littleEndian: Bool { get }
    
    /// The current length of hashes bytes in bits
    var totalLength: UInt64 { get set }
    
    /// The resulting hash
    var hash: Data { get }
    
    /// The amount of bytes currently inside the `remainder` pointer
    var containedRemainder: Int { get set }
    
    /// A buffer that keeps track of any bytes that cannot be processed until the chunk is full
    var remainder: UnsafeMutablePointer<UInt8> { get }
    
    /// Updates the hash using exactly one `chunkSize` of bytes referenced by a pointer
    func update(pointer: UnsafePointer<UInt8>)
    
    /// Resets the hash's context to it's original state (reusing the context class)
    func reset()
    
    init()
}

extension Hash {
    fileprivate var lastChunkSize: Int {
        return Self.chunkSize &- 8
    }
    
    public static func hash(_ buffer: UnsafeBufferPointer<UInt8>) -> Data {
        let hash = Self()
        hash.finalize(buffer)
        return hash.hash
    }
    
    public static func hash<S: Sequence>(_ sequence: S) -> Data where S.Element == UInt8 {
        return Array(sequence).withUnsafeBufferPointer { buffer in
            return hash(buffer)
        }
    }
    
    public func finalize(_ buffer: UnsafeBufferPointer<UInt8>) {
        let totalRemaining = containedRemainder + buffer.count + 1
        totalLength = totalLength &+ (UInt64(buffer.count) &* 8)
        
        // Append zeroes
        var zeroes = lastChunkSize &- (totalRemaining % Self.chunkSize)
        
        if zeroes > lastChunkSize {
            // Append another chunk of zeroes if we have more than 448 bits
            zeroes = (Self.chunkSize &+ (lastChunkSize &- zeroes)) &+ zeroes
        }
        
        if zeroes < 0 {
            zeroes =  (8 &+ zeroes) + lastChunkSize
        }
        
        var length = [UInt8](repeating: 0, count: 8)
        
        // Append UInt64 length in bits
        _ = length.withUnsafeMutableBytes { length in
            memcpy(length.baseAddress!, &totalLength, 8)
        }
        
        if !Self.littleEndian {
            length.reverse()
        }
        
        let lastBlocks = Array(buffer) + [0x80] + Data(repeating: 0, count: zeroes) + length
        var offset = 0
        
        lastBlocks.withUnsafeBufferPointer { buffer in
            let pointer = buffer.baseAddress!
            
            while offset < buffer.count {
                defer { offset = offset &+ Self.chunkSize }
                self.update(pointer: pointer.advanced(by: offset))
            }
        }
    }
    
    public func finalize<S: Sequence>(_ sequence: S) where S.Element == UInt8 {
        return Array(sequence).withUnsafeBufferPointer { buffer in
            self.finalize(buffer)
        }
    }
    
    public func update(_ buffer: UnsafeBufferPointer<UInt8>) {
        totalLength = totalLength &+ UInt64(buffer.count)
        
        var buffer = buffer
        
        if containedRemainder > 0 {
            let needed = Self.chunkSize &- containedRemainder
            
            guard let bufferPointer = buffer.baseAddress else {
                assertionFailure("Invalid buffer provided")
                return
            }
            
            if buffer.count >= needed {
                memcpy(remainder.advanced(by: containedRemainder), bufferPointer, needed)
                
                buffer = UnsafeBufferPointer(start: bufferPointer.advanced(by: needed), count: buffer.count &- needed)
            } else {
                memcpy(remainder.advanced(by: containedRemainder), bufferPointer, buffer.count)
                return
            }
        }
        
        guard var bufferPointer = buffer.baseAddress else {
            assertionFailure("Invalid buffer provided")
            return
        }
        
        var bufferSize = buffer.count
        
        while bufferSize >= Self.chunkSize {
            defer {
                bufferPointer = bufferPointer.advanced(by: Self.chunkSize)
                bufferSize = bufferSize &- Self.chunkSize
            }
            
            update(pointer: bufferPointer)
        }
        
        memcpy(remainder, bufferPointer, bufferSize)
        containedRemainder = bufferSize
    }
    
    public func update<S: Sequence>(sequence: inout S) where S.Element == UInt8 {
        Array(sequence).withUnsafeBufferPointer { buffer in
            update(buffer)
        }
    }
}
