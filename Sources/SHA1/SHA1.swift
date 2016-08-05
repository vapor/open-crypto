import Core
import Essentials

public class SHA1: StreamingHash {
    // MARK - MD5 Specific variables
    public static let blockSize  = 20
    internal static var chunkSize = 64
    
    public required init() {
        message = Chunks(chunkSize: SHA1.chunkSize)
        h = SHA1.H
    }
    
    var message: Chunks
    var h: [UInt32]
    
    internal static let H: [UInt32] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    
    // MARK - SHA1 specific calculation code
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
        // break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15, big-endian
        // Extend the sixteen 32-bit words into eighty 32-bit words:
        var w = [UInt32](repeating: 0, count: 80)
        for j in 0..<80 {
            switch (j) {
            case 0..<16:
                let start = chunk.startIndex + (j * sizeofValue(w[j]))
                let end = start + 4
                w[j] = toUInt32(chunk[start..<end], fromIndex: start).bigEndian
                break
            default:
                w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], count: 1)
                break
            }
        }
        
        var a = h[0]
        var b = h[1]
        var c = h[2]
        var d = h[3]
        var e = h[4]
        
        // Main loop
        for j in 0..<80 {
            var f: UInt32
            var k: UInt32
            
            switch (j) {
            case 0..<20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
                break
            case 20..<40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
                break
            case 40..<60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
                break
            case 60..<80:
                f = b ^ c ^ d
                k = 0xCA62C1D6
                break
            default:
                fatalError("Strange bug")
            }
            
            let temp = (leftRotate(a, count: 5) &+ f &+ e &+ w[j] &+ k) & 0xffffffff
            e = d
            d = c
            c = leftRotate(b, count: 30)
            b = a
            a = temp
        }
        
        h[0] = (h[0] &+ a) & 0xffffffff
        h[1] = (h[1] &+ b) & 0xffffffff
        h[2] = (h[2] &+ c) & 0xffffffff
        h[3] = (h[3] &+ d) & 0xffffffff
        h[4] = (h[4] &+ e) & 0xffffffff
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
        
        self.applyPadding(until: SHA1.chunkSize)
        self.applyBitLength(of: originalCount, reversed: false)
        
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
    
    // MARK - SHA1 Specific performant override
    public static func hash(_ message: Bytes) -> Bytes {
        var newMessage = message
        
        newMessage.append(0x80)
        
        // Append `0x00` until the (message length) -mod- 512 == 448
        // TODO: faster method
        while newMessage.count % self.chunkSize != self.chunkSize - 8 {
            newMessage.append(0x00)
        }
        
        var hash = SHA1.H
        
        // Append length and a 64-bit representation of the length in bits
        let lengthInBits = message.count * 8
        newMessage += arrayOfBytes(lengthInBits, length: 8)
        
        // Process in 64-byte chunks
        let chunks = newMessage.count / self.chunkSize
        
        // Loop over the chunks
        for i in 0..<chunks {
            let chunkOffset = i * self.chunkSize
            let end = Swift.min(self.chunkSize, newMessage.count - chunkOffset)
            var chunk = newMessage[chunkOffset..<(chunkOffset + end)]
            
            // break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15, big-endian
            // Extend the sixteen 32-bit words into eighty 32-bit words:
            var w = [UInt32](repeating: 0, count: 80)
            for j in 0..<w.count {
                switch (j) {
                case 0..<16:
                    let start = chunk.startIndex + (j * sizeofValue(w[j]))
                    let end = start + 4
                    w[j] = toUInt32(chunk[start..<end], fromIndex: start).bigEndian
                default:
                    w[j] = leftRotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], count: 1)
                    break
                }
            }
            
            var a = hash[0]
            var b = hash[1]
            var c = hash[2]
            var d = hash[3]
            var e = hash[4]
            
            // Main loop
            for j in 0..<80 {
                var f: UInt32
                var k: UInt32
                
                switch (j) {
                case 0..<20:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                    break
                case 20..<40:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                    break
                case 40..<60:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                    break
                case 60..<80:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                    break
                default:
                    fatalError("Strange bug")
                }
                
                let temp = (leftRotate(a, count: 5) &+ f &+ e &+ w[j] &+ k) & 0xffffffff
                e = d
                d = c
                c = leftRotate(b, count: 30)
                b = a
                a = temp
            }
            
            hash[0] = (hash[0] &+ a) & 0xffffffff
            hash[1] = (hash[1] &+ b) & 0xffffffff
            hash[2] = (hash[2] &+ c) & 0xffffffff
            hash[3] = (hash[3] &+ d) & 0xffffffff
            hash[4] = (hash[4] &+ e) & 0xffffffff
        }
        
        var result = Bytes()
        
        // Store result in little endian
        for int in hash {
            let int = int.bigEndian
            
            result += [Byte(int & 0xff), Byte((int >> 8) & 0xff), Byte((int >> 16) & 0xff), Byte((int >> 24) & 0xff)]
        }
        
        return result
    }
}
