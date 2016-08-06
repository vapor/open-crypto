import Core
import Essentials

public final class MD5: Hash {
    public enum Error: Swift.Error {
        case invalidByteCount
        case switchError
    }

    // MARK - MD5 Specific variables
    public static let blockSize = 64
    
    private static let s: [UInt32] = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ]
   
    public init(_ s: ByteStream) {
        stream = s
        digest = []
    }

    private var a0: UInt32 = 0x67452301
    private var b0: UInt32 = 0xefcdab89
    private var c0: UInt32 = 0x98badcfe
    private var d0: UInt32 = 0x10325476

    private let stream: ByteStream
    private var digest: [UInt32]

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
        0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    ]

    // MARK - Hash Protocol

    public func hash() throws -> ByteStream {
        var count = 0
        while !stream.closed {
            let slice = try stream.next(MD5.blockSize)

            if stream.closed {
                var bytes = Array(slice)
                count += bytes.count
                if bytes.count > MD5.blockSize - 8 {
                    // if the block is slightly too big, just pad and process
                    bytes.append(0x80)
                    bytes = bytes.applyPadding(until: MD5.blockSize)

                    try process(BytesSlice(bytes))

                    // give an empty block for padding
                    bytes = []
                } else {
                    // add this block's count to the total
                    bytes.append(0x80)
                }

                // pad and process the last block
                // adding the bit length
                bytes = bytes.applyPadding(until: MD5.blockSize - 8)
                bytes = bytes.applyBitLength(of: count, reversed: true)
                try process(BytesSlice(bytes))
            } else {
                // if the stream is still open,
                // process as normal
                try process(slice)
                count += MD5.blockSize
            }
        }

        // convert the hash into a byte
        // array of results
        var result: Bytes = []

        digest.append(a0)
        digest.append(b0)
        digest.append(c0)
        digest.append(d0)

        digest.forEach { int in
            result += convert(int)
        }

        // return a basic byte stream
        return BasicByteStream(result)
    }

    // MARK: Processing

    private func convert(_ int: UInt32) -> Bytes {
        let int = int.littleEndian
        return [
            Byte(int & 0xff),
            Byte((int >> 8) & 0xff),
            Byte((int >> 16) & 0xff),
            Byte((int >> 24) & 0xff)
        ]
    }

    private func process(_ bytes: BytesSlice) throws {
        if bytes.count != MD5.blockSize {
            throw Error.invalidByteCount
        }

        var chunk: [UInt32] = toUInt32Array(bytes)

        var a = a0
        var b = b0
        var c = c0
        var d = d0

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
                throw Error.switchError
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
        a0 = a0 &+ a
        b0 = b0 &+ b
        c0 = c0 &+ c
        d0 = d0 &+ d
    }

}
