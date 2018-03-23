import CNIOOpenSSL
import Foundation

final class COpenSSLHMACContext {
    var c: HMAC_CTX

    init() {
        c = HMAC_CTX()
    }

    deinit {
        HMAC_CTX_cleanup(&c)
    }
}

public protocol MACDigestAlgorithm {
    func reset(key: Data) throws
    func update(data: Data) throws
    func finish() throws -> Data
}

public final class HMACMD5: MACDigestAlgorithm, COpenSSLHMAC, DefaultConfigurable {
    static var md: CEVPAlgorithm = EVP_md5()
    var ctx: COpenSSLHMACContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> Self {
        return .init()
    }
}

public final class HMACSHA1: MACDigestAlgorithm, COpenSSLHMAC, DefaultConfigurable {
    static var md: CEVPAlgorithm = EVP_sha1()
    var ctx: COpenSSLHMACContext
    public init() { ctx = .init() }
    public static func configureDefault() throws -> Self {
        return .init()
    }
}

protocol COpenSSLHMAC {
    static var md: CEVPAlgorithm { get }
    var ctx: COpenSSLHMACContext { get }
}

extension MACDigestAlgorithm {
    public func update(_ data: LosslessDataConvertible) throws {
        return try update(data: data.convertToData())
    }

    public func authenticate(data: Data, withKey key: Data) throws -> Data {
        try reset(key: key)
        try update(data: data)
        return try finish()
    }

    public func authenticate(_ data: LosslessDataConvertible, withKey key: LosslessDataConvertible) throws -> Data {
        return try authenticate(data: data.convertToData(), withKey: key.convertToData())
    }
}

extension MACDigestAlgorithm where Self: DefaultConfigurable {
    public static func authenticate(data: Data, withKey key: Data) throws -> Data {
        return try configureDefault().authenticate(data: data, withKey: key)
    }

    public static func authenticate(_ data: LosslessDataConvertible, withKey key: LosslessDataConvertible) throws -> Data {
        return try configureDefault().authenticate(data, withKey: key)
    }
}


extension COpenSSLHMAC {
    public func reset(key: Data) throws {
        HMAC_Init_ex(&ctx.c, .init(key.withUnsafeBytes { $0 }), Int32(key.count), Self.md, nil)
    }

    public func update(data: Data) throws {
        HMAC_Update(&ctx.c, .init(data.withUnsafeBytes { $0 }), data.count)
    }

    public func finish() throws -> Data {
        var hash = Data(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0
        HMAC_Final(&ctx.c, hash.withUnsafeMutableBytes { $0 }, &count);
        return Data(hash[0..<Int(count)])
    }
}
