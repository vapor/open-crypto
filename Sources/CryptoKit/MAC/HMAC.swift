import CCryptoOpenSSL
import Foundation

/// HMAC is a MAC (message authentication code), i.e. a keyed hash function used for message authentication, which is based on a hash function.
///
///     let digest = try HMAC.SHA1.authenticate("hello", key: "vapor")
///     print(digest.hexEncodedString()) // bb2a9aabb537902647f3f40bfecb679bf0d7d64b
///
/// Read more about [HMAC on Wikipedia](https://en.wikipedia.org/wiki/HMAC).
///
/// Read more about OpenSSL's [HMAC methods](https://www.openssl.org/docs/man1.0.2/crypto/hmac.html)
public final class HMAC {
    // MARK: Static

    /// MD4 digest based HMAC.
    ///
    /// https://en.wikipedia.org/wiki/MD4
    public static var MD4: HMAC { return .init(algorithm: .md4) }

    /// MD5 digest based HMAC.
    ///
    /// https://en.wikipedia.org/wiki/MD5
    public static var MD5: HMAC { return .init(algorithm: .md5) }

    /// SHA-1 digest based HMAC.
    ///
    /// https://en.wikipedia.org/wiki/SHA-1
    public static var SHA1: HMAC { return .init(algorithm: .sha1) }

    /// SHA-224 (SHA-2) digest based HMAC.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA224: HMAC { return .init(algorithm: .sha224) }

    /// SHA-256 (SHA-2) digest based HMAC.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA256: HMAC { return .init(algorithm: .sha256) }

    /// SHA-384 (SHA-2) digest based HMAC.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA384: HMAC { return .init(algorithm: .sha384) }

    /// SHA-512 (SHA-2) digest based HMAC.
    ///
    /// https://en.wikipedia.org/wiki/SHA-2
    public static var SHA512: HMAC { return .init(algorithm: .sha512) }

    // MARK: Properties

    /// The `DigestAlgorithm` (e.g., SHA1, MD5, SHA256) to base the message authentication on.
    public let algorithm: DigestAlgorithm

    /// Internal OpenSSL `HMAC_CTX` context.
    var ctx: OpaquePointer

    // MARK: Init

    /// Creates a new `HMAC` using the supplied `DigestAlgorithm`.
    ///
    /// You can use the convenience static variables on HMAC for common algorithms.
    ///
    ///     try HMAC.SHA256.authenticate(...)
    ///
    /// You can also use this `init(algorithm:)` method manually to supply custom `DigestAlgorithm`.
    ///
    ///     try HMAC(algorithm: .named("sha256")).authenticate(...)
    ///
    public init(algorithm: DigestAlgorithm) {
        self.algorithm = algorithm
        ctx = HMAC_CTX_new()
    }

    // MARK: Methods

    /// Authenticates the message using the supplied key. This method will first initialize or reset the HMAC
    /// context. The supplied message will be digested using one call to `update(data:)`.
    ///
    /// For streaming HMAC authentication, use the `reset(key:)`, `update(data:)` and `finish()` methods individually.
    ///
    ///    let digest = try HMAC.SHA256.authenticate("hello", key: "vapor")
    ///    print(digest) /// Data
    ///
    /// - parameters:
    ///     - data: Message to digest / authenticate.
    ///     - key: HMAC key
    /// - returns: Digested data
    /// - throws: `CryptoError` if reset, update, or finalization steps fail or data conversion fails.
    public func authenticate(_ data: CryptoData, key: CryptoData) throws -> CryptoData {
        try reset(key: key)
        try update(data: data)
        return try finish()
    }

    /// Initializes or resets the HMAC context. This method sets this HMAC's key for subsequent calls to `update(data:)`.
    ///
    ///     let hmacsha256 = try HMAC(algorithm: .sha256)
    ///     try hmacsha256.reset(key: "vapor")
    ///
    /// - parameters:
    ///     - key: HMAC key
    /// - throws: `CryptoError` if the initialization / reset fails or data conversion fails.
    public func reset(key: CryptoData) throws {
        guard key.withUnsafeBytes({
            return HMAC_Init_ex(ctx, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32($0.count), algorithm.c, nil)
        }) == 1 else {
            throw CryptoError.openssl(identifier: "HMAC_Init_ex", reason: "Failed initializing HMAC context.")
        }
    }

    /// Updates the HMAC digest with a new chunk of data. This method can be called repeatedly for each new chunk.
    /// Use this method for streaming HMAC digests.
    ///
    ///     let hmacsha256 = try HMAC(algorithm: .sha256)
    ///     try hmacsha256.reset(key: "vapor")
    ///     try hmacsha256.update(data: "hello")
    ///     try hmacsha256.update(data: "world")
    ///
    /// note: You _must_ call `.reset(key:)` once before streaming data.
    ///
    /// - parameters:
    ///     - data: Message chunk to digest / authenticate
    /// - throws: `CryptoError` if the update fails or data conversion fails.
    public func update(data: CryptoData) throws {
        guard data.withUnsafeBytes({
            return HMAC_Update(ctx, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count)
        }) == 1 else {
            throw CryptoError.openssl(identifier: "HMAC_Update", reason: "Failed updating HMAC digest.")
        }
    }

    /// Completes the HMAC digest. This method should be called once after one call to `reset(key:)` and one more
    /// more calls to `update(data:)`.
    ///
    ///     let hmacsha256 = try HMAC(algorithm: .sha256)
    ///     try hmacsha256.reset(key: "vapor")
    ///     try hmacsha256.update(data: "hello")
    ///     try hmacsha256.update(data: "world")
    ///     let digest = try hmacsha256.finish()
    ///     print(digest) // Data
    ///
    /// - returns: Digest data
    /// - throws: `CryptoError` if the finalization step fails.
    public func finish() throws -> CryptoData {
        var hash = [UInt8](repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0
        
        guard hash.withUnsafeMutableBytes({
            return HMAC_Final(ctx, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), &count)
        }) == 1 else {
            throw CryptoError.openssl(identifier: "HMAC_Final", reason: "Failed finalizing HMAC digest.")
        }
        return .bytesSlice(hash.prefix(upTo: Int(count)))
    }

    deinit {
        HMAC_CTX_free(ctx)
    }
}
