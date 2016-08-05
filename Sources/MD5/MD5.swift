import Core
import Essentials

public class MD5: StreamingHash {
    // MARK - MD5 Specific variables
    public static let blockSize  = 64
    internal static var chunkSize = 64
    
    private static let s: [UInt32] = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21]
   
    public required init() {
        message = Chunks(chunkSize: MD5.chunkSize)
        h = MD5.H
    }
    
    var message: Chunks
    var h: [UInt32]
    
    private static let k: [UInt32] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
        0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
        0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
        0xd62f105d,0x2441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
        0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
        0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x4881d05,
        0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
        0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
        0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391]
    
    internal static let H: [UInt32] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    
    // MARK - MD5 specific calculation code
    func result() -> Bytes {
        var result = Bytes()
        
        // Store result in little endian
        for int in h {
            let int = int.littleEndian
            
            result += [Byte(int & 0xff), Byte((int >> 8) & 0xff), Byte((int >> 16) & 0xff), Byte((int >> 24) & 0xff)]
        }
        
        return result
    }
    
    internal func processChunk(_ chunk: Bytes) {
        var chunk: [UInt32] = toUInt32Array(chunk[0..<chunk.count])
        
        var a = h[0]
        var b = h[1]
        var c = h[2]
        var d = h[3]
        
        // Main loop
        for i in 0..<64 {
            var g = 0
            var F: UInt32 = 0
            
            var temp: UInt32
            
            switch i {
            case 0..<16:
                F = (b & c) | ((~b) & d)
                g = i
            case 16..<32:
                F = (d & b) | ((~d) & c)
                g = (5 * i + 1) % 16
            case 32..<48:
                F = b ^ c ^ d
                g = (3 * i + 5) % 16
            case 48..<64:
                F = c ^ (b | (~d))
                g = (7 * i) % 16
            default:
                fatalError("Strange bug")
            }
            
            temp = d
            d = c
            c = b
            
            let x = (a &+ F &+ MD5.k[i] &+ chunk[g])
            let c = MD5.s[i]
            
            b = b &+ leftRotate(x, count: c)
            a = temp
        }
        
        // Add this chunk's hash to the result
        h[0] = h[0] &+ a
        h[1] = h[1] &+ b
        h[2] = h[2] &+ c
        h[3] = h[3] &+ d
    }
    
    // MARK - Hashing helpers
    public func append(bytes: Bytes) {
        message.append(bytes: bytes)
        processChunks()
    }
    
    private func processChunks() {
        for chunk in message {
            processChunk(chunk)
        }
    }
    
    public func complete() -> Bytes {
        let originalCount = message.count
        
        self.applyPadding(until: MD5.chunkSize)
        self.applyBitLength(of: originalCount)
        
        processChunks()
        
        return result()
    }
    
    private func applyPadding(until length: Int) {
        self.message.append(0x80)
        
        while self.message.count % length != (length - 8) {
            self.message.append(0x00)
        }
    }
    
    private func applyBitLength(of length: Int, reversed: Bool = true) {
        let lengthInBits = length * 8
        let lengthBytes = arrayOfBytes(lengthInBits, length: 8)
        
        if reversed {
            message.append(bytes: lengthBytes.reversed())
        } else {
            message.append(bytes: lengthBytes)
        }
    }
    
    // MARK - MD5 Specific performant override
    public static func hash(_ message: Bytes) -> Bytes {
        var newMessage = message
        
        newMessage.append(0x80)
        
        // Append `0x00` until the (message length) -mod- 512 == 448
        // TODO: faster method
        while newMessage.count % self.chunkSize != self.chunkSize - 8 {
            newMessage.append(0x00)
        }
        
        var hash = MD5.H
        
        // Append length and a 64-bit representation of the length in bits
        let lengthInBits = message.count * 8
        let lengthBytes = arrayOfBytes(lengthInBits, length: 8)
        newMessage += lengthBytes.reversed()
        
        // Process in 64-byte chunks
        let chunks = newMessage.count / self.chunkSize
        
        //        if newMessage.count % 64 > 0 {
        //            chunks += 1
        //        }
        
        // Loop over the chunks
        for i in 0..<chunks {
            let chunkOffset = i * self.chunkSize
            let end = Swift.min(self.chunkSize, newMessage.count - chunkOffset)
            var chunk: [UInt32] = toUInt32Array(newMessage[chunkOffset..<(chunkOffset + end)])
            
            var a = hash[0]
            var b = hash[1]
            var c = hash[2]
            var d = hash[3]
            
            // Main loop
            for i in 0..<64 {
                var g = 0
                var F: UInt32 = 0
                
                var temp: UInt32
                
                switch i {
                case 0..<16:
                    F = (b & c) | ((~b) & d)
                    g = i
                case 16..<32:
                    F = (d & b) | ((~d) & c)
                    g = (5 * i + 1) % 16
                case 32..<48:
                    F = b ^ c ^ d
                    g = (3 * i + 5) % 16
                case 48..<64:
                    F = c ^ (b | (~d))
                    g = (7 * i) % 16
                default:
                    break
                }
                
                temp = d
                d = c
                c = b
                
                let x = (a &+ F &+ k[i] &+ chunk[g])
                let c = s[i]
                
                b = b &+ leftRotate(x, count: c)
                a = temp
            }
            
            // Add this chunk's hash to the result
            hash[0] = hash[0] &+ a
            hash[1] = hash[1] &+ b
            hash[2] = hash[2] &+ c
            hash[3] = hash[3] &+ d
        }
        
        var result = Bytes()
        
        // Store result in little endian
        for int in hash {
            let int = int.littleEndian
            
            result += [Byte(int & 0xff), Byte((int >> 8) & 0xff), Byte((int >> 16) & 0xff), Byte((int >> 24) & 0xff)]
        }
        
        return result
    }
}
