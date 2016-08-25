import Core
import CLibreSSL
import Essentials

public final class MD5: Hash {
    private var stream: ByteStream
    public init(_ s: ByteStream) {
        stream = s
    }

    public func hash() throws -> Bytes {
        var context = MD5_CTX()
        MD5_Init(&context)

        while !stream.closed {
            let bytes = try stream.next()
            MD5_Update(&context, bytes, bytes.count);
        }

        var digest = Bytes(repeating: 0, count: Int(MD5_DIGEST_LENGTH))
        MD5_Final(&digest, &context);
        return digest
    }
}

import HMAC

extension MD5: Authenticatable {
    public static func method() -> Method {
        return .md5
    }
}
