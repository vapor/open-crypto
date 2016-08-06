import Core
import Essentials

public final class SHA1: Hash {

    public enum Error: Swift.Error {
        case invalidByteCount
        case switchError
    }

    private var h: [UInt32]
    private var stream: ByteStream

    /**
        Create a new SHA1 capable of hashing a Stream.
    */
    public init(_ s: ByteStream) {
        stream = s
        h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]
    }

    // MARK - Hash Protocol

    /**
        SHA1 uses a block size of 64.
    */
    public static let blockSize = 64

    /**
        Create a hashed ByteStream from an input ByteStream
        using the SHA1 protocol.
    */
    public func hash() throws -> ByteStream {
        var count = 0
        while !stream.closed {
            let slice = try stream.next(SHA1.blockSize)

            if stream.closed {
                var bytes = Array(slice)
                if bytes.count > SHA1.blockSize - 8 {
                    // if the block is slightly too big, just pad and process
                    bytes = bytes.applyPadding(until: SHA1.blockSize)

                    try process(BytesSlice(bytes))
                    count += bytes.count

                    // give an empty block for padding
                    bytes = []
                } else {
                    // add this block's count to the total
                    count += bytes.count
                }

                // pad and process the last block 
                // adding the bit length
                bytes = bytes.applyPadding(until: SHA1.blockSize - 8)
                bytes = bytes.applyBitLength(of: count, reversed: false)
                try process(BytesSlice(bytes))
            } else {
                // if the stream is still open,
                // process as normal
                try process(slice)
                count += SHA1.blockSize
            }
        }

        // convert the hash into a byte
        // array of results
        var result: Bytes = []
        h.forEach { int in
            result += convert(int)
        }

        // return a basic byte stream
        return BasicByteStream(result)
    }

    // MARK: Processing

    private func convert(_ int: UInt32) -> Bytes {
        let int = int.bigEndian
        return [
            Byte(int & 0xff),
            Byte((int >> 8) & 0xff),
            Byte((int >> 16) & 0xff),
            Byte((int >> 24) & 0xff)
        ]
    }

    private func process(_ bytes: BytesSlice) throws {
        if bytes.count != SHA1.blockSize {
            throw Error.invalidByteCount
        }

        var w = [UInt32](repeating: 0, count: 80)

        var index = bytes.startIndex

        for j in 0..<w.count {
            switch j {
            // break chunk into sixteen 4-byte big-endian words
            case 0..<16:
                w[j] = toUInt32(bytes, from: index).bigEndian
                index = bytes.index(index, offsetBy: 4)
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
                throw Error.switchError
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

}
