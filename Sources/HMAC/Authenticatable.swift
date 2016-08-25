import CLibreSSL
import Essentials
import Core

/**
    Types conforming to Authenticatable
    can be passed to `HMAC` directly.
*/
public protocol Authenticatable {
    static func method() -> Method
}

extension Authenticatable where Self: Hash {
    public static func authenticate(_ message: Bytes, key: Bytes) throws -> Bytes {
        return try HMAC(Self.self, message).authenticate(key: key)
    }

    public static func authenticate(_ message: ByteStream, key: Bytes) throws -> Bytes {
        return try HMAC(Self.method(), message).authenticate(key: key)
    }

    public static func authenticate<
        B1: BytesRepresentable,
        B2: BytesRepresentable
    >(_ message: B1, key: B2) throws -> Bytes {
        return try authenticate(try message.makeBytes(), key: try key.makeBytes())
    }
}

/**
    Hashing method for calculating
    the HMAC authentication.
*/
public enum Method {
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512
    case md4
    case md5
    case dss1
    case ecdsa
    case ripemd160
    case whirlpool
    case streebog256
    case streebog512
    case gostr341194
}

extension Method {
    /**
        The internal EVP pointer.
    */
    var evp: UnsafePointer<EVP_MD> {
        switch self {
        case .sha1:
            return EVP_sha1()
        case .sha224:
            return EVP_sha224()
        case .sha256:
            return EVP_sha256()
        case .sha384:
            return EVP_sha384()
        case .sha512:
            return EVP_sha512()
        case .md4:
            return EVP_md4()
        case .md5:
            return EVP_md5()
        case .dss1:
            return EVP_dss1()
        case .ecdsa:
            return EVP_ecdsa()
        case .ripemd160:
            return EVP_ripemd160()
        case .whirlpool:
            return EVP_whirlpool()
        case .streebog256:
            return EVP_streebog256()
        case .streebog512:
            return EVP_streebog512()
        case .gostr341194:
            return EVP_gostr341194()
        }
    }
}
