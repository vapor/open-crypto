import Core
import CLibreSSL
import Essentials

/**
    Hashes according to the SHA512
    specification provided by LibreSSL.
 
    https://en.wikipedia.org/wiki/SHA-2
*/
public final class SHA512: Hash {
    private var stream: ByteStream

    /**
        Creates a SHA512 hasher.
        - see: Hash.hash
    */
    public init(_ s: ByteStream) {
        stream = s
    }

    /**
        Calculates a SHA512 hash.
        - see: Hash.hash
    */
    public func hash() throws -> Bytes {
        var context = SHA512_CTX()
        SHA512_Init(&context)

        while !stream.closed {
            let bytes = try stream.next()
            SHA512_Update(&context, bytes, bytes.count);
        }

        var digest = Bytes(repeating: 0, count: Int(SHA512_DIGEST_LENGTH))
        SHA512_Final(&digest, &context);
        return digest
    }
}

import HMAC

extension SHA512: Authenticatable {
    public static func method() -> Method {
        return .sha512
    }
}

