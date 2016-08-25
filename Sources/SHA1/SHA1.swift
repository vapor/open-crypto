import Core
import CLibreSSL
import Essentials

/**
    Hashes according to the SHA1
    specification provided by LibreSSL.
 
    https://en.wikipedia.org/wiki/SHA-1
    https://github.com/libressl/libressl/blob/master/src/doc/crypto/SHA1.pod
*/
public final class SHA1: Hash {
    private let stream: ByteStream

    /**
        Creates a SHA1 hasher.
        - see: Hash.hash
    */
    public init(_ s: ByteStream) {
        stream = s
    }

    /**
        Calculates a SHA1 hash.
        - see: Hash.hash
    */
    public func hash() throws -> Bytes {
        var context = SHA_CTX()
        SHA1_Init(&context)

        while !stream.closed {
            let bytes = try stream.next()
            SHA1_Update(&context, bytes, bytes.count)
        }

        var digest = Bytes(repeating: 0, count: Int(SHA_DIGEST_LENGTH))
        SHA1_Final(&digest, &context);
        return digest
    }
}

import HMAC

extension SHA1: Authenticatable {
    public static func method() -> Method {
        return .sha1
    }
}
