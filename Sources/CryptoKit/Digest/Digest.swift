import CCryptoOpenSSL
import Foundation

// MARK: Digests

/// MD4 digest.
///
/// https://en.wikipedia.org/wiki/MD4
public var MD4: Digest { return .init(algorithm: .md4) }

/// MD5 digest.
///
/// https://en.wikipedia.org/wiki/MD5
public var MD5: Digest { return .init(algorithm: .md5) }

/// SHA-1 digest.
///
/// https://en.wikipedia.org/wiki/SHA-1
public var SHA1: Digest { return .init(algorithm: .sha1) }

/// SHA-224 (SHA-2) digest.
///
/// https://en.wikipedia.org/wiki/SHA-2
public var SHA224: Digest { return .init(algorithm: .sha224) }

/// SHA-256 (SHA-2) digest.
///
/// https://en.wikipedia.org/wiki/SHA-2
public var SHA256: Digest { return .init(algorithm: .sha256) }

/// SHA-384 (SHA-2) digest.
///
/// https://en.wikipedia.org/wiki/SHA-2
public var SHA384: Digest { return .init(algorithm: .sha384) }

/// SHA-512 (SHA-2) digest.
///
/// https://en.wikipedia.org/wiki/SHA-2
public var SHA512: Digest { return .init(algorithm: .sha512) }

/// Cryptographic hash functions convert data of arbitrary size to a fixed-size digest.
///
///     let digest = try SHA1.hash("hello")
///     print(digest.hexEncodedString()) // aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
///
/// See `HMAC` for keyed-hash functions.
///
/// Read more about hashing on [Wikipedia](https://en.wikipedia.org/wiki/Cryptographic_hash_function).
///
/// Read more about OpenSSL's [EVP message digest](https://www.openssl.org/docs/man1.1.0/crypto/EVP_MD_CTX_free.html)/
public final class Digest {
    // MARK: Properties

    /// The `DigestAlgorithm` (e.g., SHA1, MD5, SHA256) to use.
    public let algorithm: DigestAlgorithm

    /// Internal OpenSSL `EVP_MD_CTX` context.
    let ctx: OpaquePointer

    // MARK: Init

    /// Creates a new `Digest` using the supplied `DigestAlgorithm`.
    ///
    /// You can use the convenience static variables for common algorithms.
    ///
    ///     try SHA256.hash(...)
    ///
    /// You can also use this `init(algorithm:)` method manually to supply custom `DigestAlgorithm`.
    ///
    ///     try Digest(algorithm: .named("sha256")).hash(...)
    ///
    public init(algorithm: DigestAlgorithm) {
        self.algorithm = algorithm
        self.ctx = EVP_MD_CTX_new().convert()
    }

    // MARK: Methods

    /// Creates a digest for the supplied data. This method will call `.reset()`, `.update(data:)`, and `.finish()`.
    ///
    ///     let digest = try SHA256.hash("hello")
    ///     print(digest) /// Data
    ///
    /// - parameters:
    ///     - data: Data to digest
    /// - returns: Digest
    /// - throws: `CryptoError` if reset, update, or finalization steps fail or if data conversion fails.
    public func hash(_ data: LosslessDataConvertible) throws -> Data {
        try reset()
        try update(data: data)
        return try finish()
    }

    /// Resets / initializes the digest algorithm context. This must be called once before calling `update(data:)`.
    ///
    ///     var sha256 = try Digest(algorithm: .sha256)
    ///     try sha256.reset()
    ///
    /// - throws: `CryptoError` if reset fails.
    public func reset() throws {
        guard EVP_DigestInit_ex(ctx.convert(), algorithm.c.convert(), nil) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_DigestInit_ex", reason: "Failed initializing digest context.")
        }
    }

    /// Updates the digest with another data chunk. This can be called multiple times. Use this method for streaming digests.
    ///
    ///     var sha256 = try Digest(algorithm: .sha256)
    ///     try sha256.reset()
    ///     try sha256.update(data: "hello")
    ///     try sha256.update(data: "world")
    ///
    /// Note: You _must_ call `reset()` once before calling this method.
    ///
    /// - parameters:
    ///     - data: Message chunk to digest.
    /// - throws: `CryptoError` if update fails or data conversion fails.
    public func update(data: LosslessDataConvertible) throws {
        let data = data.convertToData()
        
        guard data.withByteBuffer({ EVP_DigestUpdate(ctx.convert(), $0.baseAddress!, $0.count) }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_DigestUpdate", reason: "Failed updating digest.")
        }
    }

    /// Finalizes the digest, returning the digest data.
    ///
    ///     var sha256 = try Digest(algorithm: .sha256)
    ///     try sha256.reset()
    ///     try sha256.update(data: "hello")
    ///     try sha256.update(data: "world")
    ///     let digest = try sha256.finish()
    ///     print(digest) /// Data
    ///
    /// - returns: Digest data
    /// - throws: `CryptoError` if the finalization step fails.
    public func finish() throws -> Data {
        var hash = Data(count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0

        guard hash.withMutableByteBuffer({ EVP_DigestFinal_ex(ctx.convert(), $0.baseAddress!, &count) }) == 1 else {
            throw CryptoError.openssl(identifier: "EVP_DigestFinal_ex", reason: "Failed finalizing digest.")
        }
        return hash.prefix(upTo: Int(count))
    }

    deinit {
        EVP_MD_CTX_free(ctx.convert())
    }
}
