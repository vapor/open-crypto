import CNIOOpenSSL
import Debugging
import Foundation

/// RSA cipher.
public struct RSA {
    /// This cipher's key.
    public let key: RSAKey

    /// The hashing algorithm to use/used.
    public let hashAlgorithm: RSAHashAlgorithm

    /// The padding algorithm used.
    public let paddingScheme: RSAPaddingScheme

    /// The input format type.
    public let inputFormat: RSAInputFormat

    /// Creates a new RSA cipher.
    public init(
        hashAlgorithm: RSAHashAlgorithm = .sha512,
        paddingScheme: RSAPaddingScheme = .pkcs1,
        inputFormat: RSAInputFormat = .message,
        key: RSAKey
    ) {
        self.hashAlgorithm = hashAlgorithm
        self.paddingScheme = paddingScheme
        self.inputFormat = inputFormat
        self.key = key
    }

    /// Signs the supplied input (in format specified by `inputFormat`)
    /// returning signature data.
    public func sign(_ input: DataRepresentable) throws -> Data {
        switch key.type {
        case .public: throw RSAError(identifier: "sign", reason: "Cannot create RSA signature with a public key. A private key is required.")
        case .private: break
        }

        var siglen: UInt32 = 0
        var sig = Data(
            repeating: 0,
            count: Int(RSA_size(key.c.pointer))
        )

        switch paddingScheme {
        case .pkcs1: break
        case .pss: throw RSAError(identifier: "paddingScheme", reason: "RSA PSS not yet supported on Linux. Use PKCS#1.")
        }

        var input = try input.makeData()

        switch inputFormat {
        case .digest: break // leave input as is
        case .message:
            switch hashAlgorithm {
            case .sha1: input = SHA1.hash(input)
            case .sha224: input = SHA224.hash(input)
            case .sha256: input = SHA256.hash(input)
            case .sha384: input = SHA384.hash(input)
            case .sha512: input = SHA512.hash(input)
            }
        }

        let ret = RSA_sign(
            hashAlgorithm.c,
            input.withUnsafeBytes { $0 },
            UInt32(input.count),
            sig.withUnsafeMutableBytes { $0 },
            &siglen,
            key.c.pointer
        )

        guard ret == 1 else {
            throw RSAError.c(identifier: "sign", reason: "Signature creation failed")
        }

        return sig
    }

    /// Verifies a signature *created using RSA with identical hash and padding settings)
    /// matches supplied input (in format specified by `inputFormat`).
    public func verify(_ signature: DataRepresentable, signs input: DataRepresentable) throws -> Bool {
        var input = try input.makeData()
        var signature = try signature.makeData()

        switch inputFormat {
        case .digest: break // leave input as is
        case .message:
            switch hashAlgorithm {
            case .sha1: input = SHA1.hash(input)
            case .sha224: input = SHA224.hash(input)
            case .sha256: input = SHA256.hash(input)
            case .sha384: input = SHA384.hash(input)
            case .sha512: input = SHA512.hash(input)
            }
        }

        let result = RSA_verify(
            hashAlgorithm.c,
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
    /// The input has been hash already.
    case digest
    /// Raw, unhashed message
    case message
}

/// Supported RSA hash types.
public enum RSAHashAlgorithm {
    /// SHA-1 hash.
    case sha1
    /// SHA-2 224 bit hash.
    case sha224
    /// SHA-2 256 bit hash.
    case sha256
    /// SHA-2 284 bit hash.
    case sha384
    /// SHA-2 512 bit hash.
    case sha512

    /// Internal OpenSSL representation.
    internal var c: Int32 {
        switch self {
        case .sha1: return NID_sha1
        case .sha224: return NID_sha224
        case .sha256: return NID_sha256
        case .sha384: return NID_sha384
        case .sha512: return NID_sha512
        }
    }
}

/// Supported RSA padding type.
public enum RSAPaddingScheme {
    /// PKCS#1
    case pkcs1
    /// Probabilistic Signature Scheme
    case pss
}
