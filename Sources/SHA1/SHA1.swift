import Core
import Essentials

public final class SHA1: Hash {
    public static let blockSize  = 64
    
    public init() {
        h = SHA1.H
    }

    var h: [UInt32]
    
    internal static let H: [UInt32] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

    private func process(_ bytes: Bytes) {
        var w = [UInt32](repeating: 0, count: 80)
        for j in 0..<w.count {
            switch (j) {
            // break chunk into sixteen 32-bit big-endian words
            case 0..<16:
                let start = bytes.startIndex + (j * sizeofValue(w[j]))
                let end = start + 4
                w[j] = toUInt32(bytes[start..<end], fromIndex: start).bigEndian
                
            // Extend the sixteen 32-bit words into eighty 32-bit words:
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
    
    // MARK - HASH

    public func hash(_ stream: ByteStream) -> ByteStream {
        var count = 0
        while var bytes = stream.next(SHA1.blockSize) {
            if bytes.count < SHA1.blockSize {
                bytes = bytes.applyPadding(until: SHA1.blockSize)
                bytes = bytes.applyBitLength(of: count, reversed: false)
            }

            process(bytes)
            count += bytes.count
        }

        var result: Bytes = []

        for int in h {
            let int = int.bigEndian
            result += [
                Byte(int & 0xff),
                Byte((int >> 8) & 0xff),
                Byte((int >> 16) & 0xff),
                Byte((int >> 24) & 0xff)
            ]
        }

        return BasicByteStream(bytes: result)
    }
}

extension Sequence where Iterator.Element == Byte {
    private func applyPadding(until length: Int) -> Bytes {
        var bytes = Array(self)
        bytes.append(0x80)

        while bytes.count % length != (length - 8) {
            bytes.append(0x00)
        }

        return bytes
    }

    private func applyBitLength(of length: Int, reversed: Bool = true) -> Bytes {
        var lengthBytes = arrayOfBytes(length * 8, length: 8)

        if reversed {
            lengthBytes = lengthBytes.reversed()
        }

        return self + lengthBytes
    }
}
