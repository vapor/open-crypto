import Core
import CLibreSSL
import Essentials

/**
    Hashes according to the SHA384
    specification provided by LibreSSL.
 
    https://en.wikipedia.org/wiki/SHA-2
*/
public final class SHA384: Hash {
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
        var context = SHA512_CTX()
        SHA384_Init(&context)

        while !stream.closed {
            let bytes = try stream.next()
            SHA384_Update(&context, bytes, bytes.count);
        }

        var digest = Bytes(repeating: 0, count: Int(SHA384_DIGEST_LENGTH))
        SHA384_Final(&digest, &context);
        return digest
    }
}

import HMAC

extension SHA384: Authenticatable {
    public static func method() -> Method {
        return .sha384
    }
}

