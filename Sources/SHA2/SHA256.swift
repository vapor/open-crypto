import Core
import CLibreSSL
import Essentials

/**
    Hashes according to the SHA256
    specification provided by LibreSSL.
 
    https://en.wikipedia.org/wiki/SHA-2
*/
public final class SHA256: Hash {
    private let stream: ByteStream

    /**
        Creates a SHA256 hasher.
        - see: Hash.hash
    */
    public init(_ s: ByteStream) {
        stream = s
    }

    /**
        Calculates a SHA256 hash.
        - see: Hash.hash
    */
    public func hash() throws -> Bytes {
        var context = SHA256_CTX()
        SHA256_Init(&context)

        while !stream.closed {
            let bytes = try stream.next()
            SHA256_Update(&context, bytes, bytes.count)
        }

        var digest = Bytes(repeating: 0, count: Int(SHA256_DIGEST_LENGTH))
        SHA256_Final(&digest, &context);
        return digest
    }
}

import HMAC

extension SHA256: Authenticatable {
    public static func method() -> Method {
        return .sha256
    }
}

