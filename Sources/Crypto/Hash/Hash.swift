import CNIOOpenSSL
import Foundation

typealias CEVPAlgorithm = UnsafePointer<EVP_MD>
typealias CEVPAlgorithmContext = UnsafeMutablePointer<EVP_MD_CTX>?

protocol COpenSSLEVPDigest {
    static var md: CEVPAlgorithm { get }
    var ctx: COpenSSLEVPDigestContext { get }
}

extension COpenSSLEVPDigest {
    public func reset() throws {
        EVP_DigestInit_ex(ctx.c, Self.md, nil);
    }

    public func update(data: Data) throws {
        let i = data.withUnsafeBytes { ptr in
            return EVP_DigestUpdate(ctx.c, ptr, data.count)
        }
        print(i)
    }

    public func finish() throws -> Data {
        var hash = Data(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0
        EVP_DigestFinal_ex(ctx.c, hash.withUnsafeMutableBytes { $0 }, &count);
        return Data(hash[0..<Int(count)])
    }
}

final class COpenSSLEVPDigestContext {
    let c: CEVPAlgorithmContext

    init() {
        c = EVP_MD_CTX_create()
    }

    deinit {
        EVP_MD_CTX_destroy(c)
    }
}

public protocol DigestAlgorithm {
    func reset() throws
    func update(data: Data) throws
    func finish() throws -> Data 
}

public protocol DefaultConfigurable {
    static func configureDefault() throws -> Self
}

extension DigestAlgorithm where Self: DefaultConfigurable {
    public static func hash(data: Data) throws -> Data {
        return try configureDefault().hash(data: data)
    }

    public static func hash(_ data: LosslessDataConvertible) throws -> Data {
        return try configureDefault().hash(data)
    }
}

extension DigestAlgorithm {
    public func update(_ data: LosslessDataConvertible) throws {
        return try update(data: data.convertToData())
    }

    public func hash(data: Data) throws -> Data {
        try reset()
        try update(data: data)
        return try finish()
    }

    public func hash(_ data: LosslessDataConvertible) throws -> Data {
        return try hash(data: data.convertToData())
    }
}

public final class SHA1: DigestAlgorithm, COpenSSLEVPDigest, DefaultConfigurable {
    static var md: UnsafePointer<EVP_MD> = EVP_sha1()
    var ctx: COpenSSLEVPDigestContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> SHA1 { return .init() }
}

public final class SHA224: DigestAlgorithm, COpenSSLEVPDigest, DefaultConfigurable {
    static var md: UnsafePointer<EVP_MD> = EVP_sha224()
    var ctx: COpenSSLEVPDigestContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> SHA224 { return .init() }
}

public final class SHA256: DigestAlgorithm, COpenSSLEVPDigest, DefaultConfigurable {
    static var md: UnsafePointer<EVP_MD> = EVP_sha256()
    var ctx: COpenSSLEVPDigestContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> SHA256 { return .init() }
}

public final class SHA384: DigestAlgorithm, COpenSSLEVPDigest, DefaultConfigurable {
    static var md: UnsafePointer<EVP_MD> = EVP_sha384()
    var ctx: COpenSSLEVPDigestContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> SHA384 { return .init() }
}

public final class SHA512: DigestAlgorithm, COpenSSLEVPDigest, DefaultConfigurable {
    static var md: UnsafePointer<EVP_MD> = EVP_sha512()
    var ctx: COpenSSLEVPDigestContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> SHA512 { return .init() }
}

public final class MD4: DigestAlgorithm, COpenSSLEVPDigest, DefaultConfigurable {
    static var md: UnsafePointer<EVP_MD> = EVP_md4()
    var ctx: COpenSSLEVPDigestContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> MD4 { return .init() }
}

public final class MD5: DigestAlgorithm, COpenSSLEVPDigest, DefaultConfigurable {
    static var md: UnsafePointer<EVP_MD> = EVP_md5()
    var ctx: COpenSSLEVPDigestContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> MD5 { return .init() }
}
