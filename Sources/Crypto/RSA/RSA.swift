import CNIOOpenSSL
import Debugging
import Foundation

/// RSA cipher.
public struct RSA {
    /// This cipher's key.
    public let key: RSAKey

    /// The hashing algorithm to use/used.
    public let digestAlgorithm: DigestAlgorithm

    /// The padding algorithm used.
    public let paddingScheme: RSAPaddingScheme

    /// The input format type.
    public let inputFormat: RSAInputFormat

    /// Creates a new RSA cipher.
    public init(
        digestAlgorithm: DigestAlgorithm = .sha512,
        paddingScheme: RSAPaddingScheme = .pkcs1,
        inputFormat: RSAInputFormat = .message,
        key: RSAKey
    ) {
        self.digestAlgorithm = digestAlgorithm
        self.paddingScheme = paddingScheme
        self.inputFormat = inputFormat
        self.key = key
    }

    /// Signs the supplied input (in format specified by `inputFormat`)
    /// returning signature data.
    public func sign(_ input: LosslessDataConvertible) throws -> Data {
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

        switch inputFormat {
        case .digest: break // leave input as is
        case .message: input = try Digest(algorithm: digestAlgorithm).hash(input)
        }

        let ret = RSA_sign(
            digestAlgorithm.type,
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

    /// Verifies a signature (created using RSA with identical hash and padding settings)
    /// matches supplied input (in format specified by `inputFormat`).
    public func verify(_ signature: LosslessDataConvertible, signs input: LosslessDataConvertible) throws -> Bool {
        var input = try input.convertToData()
        var signature = try signature.convertToData()

        switch inputFormat {
        case .digest: break // leave input as is
        case .message: input = try Digest(algorithm: digestAlgorithm).hash(input)
        }

        let result = RSA_verify(
            digestAlgorithm.type,
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
