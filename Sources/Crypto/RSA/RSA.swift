import Foundation

/// Represents an in-memory RSA key.
public struct RSAKey {
    /// The bit-count of this RSA key.
    public var bits: Int

    /// The specific RSA key type. Either public or private.
    ///
    /// Note: public keys can only verify signatures. A private key
    /// is required to create new signatures.
    public var type: RSAKeyType

    /// The raw RSA key data. This data should have
    /// already been base-64 decoded.
    ///
    /// Note: The length of this data does not need to equal
    /// the `bits` count. RSA public/private keys have different
    /// and varying lengths.
    public var data: Data

    public init(bits: Int, type: RSAKeyType, data: Data) {
        self.bits = bits
        self.type = type
        self.data = data
    }

    /// MARK: Convenience
    public static func public512(_ data: Data) -> RSAKey { return .init(bits: 512, type: .public, data: data) }
    public static func public1024(_ data: Data) -> RSAKey { return .init(bits: 1024, type: .public, data: data) }
    public static func public2048(_ data: Data) -> RSAKey { return .init(bits: 2048, type: .public, data: data) }
    public static func public4096(_ data: Data) -> RSAKey { return .init(bits: 4096, type: .public, data: data) }
    public static func private512(_ data: Data) -> RSAKey { return .init(bits: 512, type: .private, data: data) }
    public static func private1024(_ data: Data) -> RSAKey { return .init(bits: 1024, type: .private, data: data) }
    public static func private2048(_ data: Data) -> RSAKey { return .init(bits: 2048, type: .private, data: data) }
    public static func private4096(_ data: Data) -> RSAKey { return .init(bits: 4096, type: .private, data: data) }
}

/// Supported RSA key types.
public enum RSAKeyType {
    /// A public RSA key. Used for verifying signatures.
    case `public`
    /// A private RSA key. Used for creating and verifying signatures.
    case `private`
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
}

/// Supported RSA padding type.
public enum RSAPaddingScheme {
    /// PKCS#1
    case pkcs1
    /// Probabilistic Signature Scheme
    case pss
}

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
    public func sign(_ input: Data) throws -> Data {
        #if os(macOS)
        return try AppleRSA.sign(input, for: self)
        #else
        fatalError("Only macOS supported.")
        #endif
    }

    /// Verifies a signature *created using RSA with identical hash and padding settings)
    /// matches supplied input (in format specified by `inputFormat`).
    public func verify(signature: Data, matches input: Data) throws -> Bool {
        #if os(macOS)
        return try AppleRSA.verify(signature: signature, matches: input, for: self)
        #else
        fatalError("Only macOS supported.")
        #endif
    }
}
