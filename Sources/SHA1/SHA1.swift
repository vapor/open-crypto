import Core
import CLibreSSL
import Essentials

public final class SHA1: Hash {
    public static let blockSize = 64

    private var stream: ByteStream
    public init(_ s: ByteStream) {
        stream = s
    }

    public func hash() throws -> Bytes {
        var context = SHA_CTX()
        SHA1_Init(&context)

        while !stream.closed {
            let bytes = try stream.next()
            SHA1_Update(&context, bytes, bytes.count);
        }

        var digest = Bytes(repeating: 0, count: Int(SHA_DIGEST_LENGTH))
        SHA1_Final(&digest, &context);
        return digest
    }
}
