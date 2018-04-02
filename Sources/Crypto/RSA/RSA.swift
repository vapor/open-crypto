import CNIOOpenSSL
import Debugging
import Foundation

/// RSA is an asymmetric cryptographic algorithm for signing and verifying data.
///
/// Use `sign(_:key:)` to create a fixed-size signature for aribtrary plaintext data.
///
///     let ciphertext = try RSA.SHA512.sign("vapor", key: .private(pem: ...))
///
/// Use `verify(_:signs:key:)` to verify that a given signature was created by some plaintext data.
///
///     try RSA.SHA512.verify(ciphertext, signs: "vapor", key: .public(pem: ...))
///
/// RSA has two key types: public and private. Private keys can sign and verify data. Public keys
/// can only verify data.
///
/// Read more about RSA on [Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).
public final class RSA {
    /// The hashing algorithm to use, (e.g., SHA512). See `DigestAlgorithm`.
    public let algorithm: DigestAlgorithm

    /// The padding algorithm used.
    public let paddingScheme: RSAPaddingScheme

    /// RSA using SHA256 digest.
    public static var SHA256: RSA { return .init(algorithm: .sha256) }

    /// RSA using SHA384 digest.
    public static var SHA384: RSA { return .init(algorithm: .sha384) }

    /// RSA using SHA512 digest.
    public static var SHA512: RSA { return .init(algorithm: .sha512) }

    /// Creates a new RSA cipher.
    public init(algorithm: DigestAlgorithm, paddingScheme: RSAPaddingScheme = .pkcs1) {
        self.algorithm = algorithm
        self.paddingScheme = paddingScheme
    }

    /// Signs the supplied input (in format specified by `format`).
    ///
    ///     let ciphertext = try RSA.SHA512.sign("vapor", key: .private(pem: ...))
    ///
    /// - parameters:
    ///     - input: Plaintext message or message digest to sign.
    ///     - format: Format of the input, either plaintext message or digest.
    ///     - key: `RSAKey` to use for signing this data.
    /// - returns: RSA signature for this data.
    /// - throws: `CryptoError` if signing fails or data conversion fails.
    public func sign(_ input: LosslessDataConvertible, format: RSAInputFormat = .message, key: RSAKey) throws -> Data {
        switch key.type {
        case .public: throw CryptoError(identifier: "rsaSign", reason: "Cannot create RSA signature with a public key. A private key is required.")
        case .private: break
        }

        var siglen: UInt32 = 0
        var sig = Data(
            repeating: 0,
            count: Int(RSA_size(key.c.pointer))
        )

        switch paddingScheme {
        case .pkcs1: break
        case .pss: throw CryptoError(identifier: "rsaPaddingScheme", reason: "RSA PSS not yet supported on Linux. Use PKCS#1.")
        }

        var input = try input.convertToData()

        switch format {
        case .digest: break // leave input as is
        case .message: input = try Digest(algorithm: algorithm).hash(input)
        }

        let ret = RSA_sign(
            algorithm.type,
            input.withUnsafeBytes { $0 },
            UInt32(input.count),
            sig.withUnsafeMutableBytes { $0 },
            &siglen,
            key.c.pointer
        )

        guard ret == 1 else {
            throw CryptoError.openssl(identifier: "rsaSign", reason: "RSA signature creation failed")
        }

        return sig
    }

    /// Returns `true` if the supplied signature was created by signing the plaintext data.
    ///
    ///     try RSA.SHA512.verify(ciphertext, signs: "vapor", key: .public(pem: ...))
    ///
    /// - parameters:
    ///     - signature: RSA signature from `sign(_:key:)` method.
    ///     - input: Plaintext message or message digest to verify against.
    ///     - format: Format of the input, either plaintext message or digest.
    ///     - key: `RSAKey` to use for signing this data.
    /// - returns: `true` if signature matches plaintext input.
    /// - throws: `CryptoError` if verification fails or data conversion fails.
    public func verify(_ signature: LosslessDataConvertible, signs input: LosslessDataConvertible, format: RSAInputFormat = .message, key: RSAKey) throws -> Bool {
        var input = try input.convertToData()
        var signature = try signature.convertToData()

        switch format {
        case .digest: break // leave input as is
        case .message: input = try Digest(algorithm: algorithm).hash(input)
        }

        let result = RSA_verify(
            algorithm.type,
            input.withUnsafeBytes { $0 },
            UInt32(input.count),
            signature.withUnsafeBytes { $0 },
            UInt32(signature.count),
            key.c.pointer
        )
        return result == 1
    }
}

/// Supported RSA input formats.
public enum RSAInputFormat {
    /// The input has been hashed already.
    case digest
    /// Raw, unhashed message
    case message
}

/// Supported RSA padding type.
public enum RSAPaddingScheme {
    /// PKCS#1
    case pkcs1
    /// Probabilistic Signature Scheme
    case pss
}
