import Core
import CLibreSSL
import Essentials

/**
    Hashes according to the SHA224
    specification provided by LibreSSL.
 
    https://en.wikipedia.org/wiki/SHA-2
*/
public final class SHA224: Hash {
    private let stream: ByteStream

    /**
        Creates a SHA224 hasher.
        - see: Hash.hash
    */
    public init(_ s: ByteStream) {
        stream = s
    }

    /**
        Calculates a SHA224 hash.
        - see: Hash.hash
    */
    public func hash() throws -> Bytes {
        var context = SHA256_CTX()
        SHA224_Init(&context)

        while !stream.closed {
            let bytes = try stream.next()
            SHA224_Update(&context, bytes, bytes.count)
        }

        var digest = Bytes(repeating: 0, count: Int(SHA224_DIGEST_LENGTH))
        SHA224_Final(&digest, &context);
        return digest
    }
}

import HMAC

extension SHA224: Authenticatable {
    public static func method() -> Method {
        return .sha224
    }
}
