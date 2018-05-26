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

    typealias RSAPkeySymmetricCoder = @convention(c) (Int32, UnsafePointer<UInt8>?, UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<CNIOOpenSSL.RSA>?, Int32) -> Int32

    // MARK: Static

    /// RSA using SHA256 digest.
    @available(*, deprecated, message: "Use sign(_:algorithm:format:key:) or verify(_:algorithm:signs:format:key:)")
    public static var SHA256: RSA { return .init(algorithm: .sha256) }

    /// RSA using SHA384 digest.
    @available(*, deprecated, message: "Use sign(_:algorithm:format:key:) or verify(_:algorithm:signs:format:key:)")
    public static var SHA384: RSA { return .init(algorithm: .sha384) }

    /// RSA using SHA512 digest.
    @available(*, deprecated, message: "Use sign(_:algorithm:format:key:) or verify(_:algorithm:signs:format:key:)")
    public static var SHA512: RSA { return .init(algorithm: .sha512) }

    // MARK: Properties

    /// The hashing algorithm to use, (e.g., SHA512). See `DigestAlgorithm`.
    public let algorithm: DigestAlgorithm

    @available(*, deprecated, message: "Use sign(_:algorithm:format:key:) or verify(_:algorithm:signs:format:key:)")
    public init(algorithm: DigestAlgorithm) {
        self.algorithm = algorithm
    }

    // MARK: Init

    /// Creates a new RSA cipher with the default unsafe md4 DigestAlgorithm.
    /// You should use the sign and verify methods to provide a safer algorithm.
    public init() {
        self.algorithm = .md4
    }

    @available(*, deprecated, message: "Use sign(_:algorithm:format:key:)")
    public func sign(_ input: LosslessDataConvertible, format: RSAInputFormat = .message, key: RSAKey) throws -> Data {
        return try sign(input, algorithm: self.algorithm, format: format, key: key)
    }


    // MARK: Methods

    /// Signs the supplied input (in format specified by `format`).
    ///
    ///     let ciphertext = try RSA.SHA512.sign("vapor", algorithm: .sha256,key: .private(pem: ...))
    ///
    /// - parameters:
    ///     - input: Plaintext message or message digest to sign.
    ///     - format: Format of the input, either plaintext message or digest.
    ///     - algorithm: Digest algorithm to use.
    ///     - key: `RSAKey` to use for signing this data.
    /// - returns: RSA signature for this data.
    /// - throws: `CryptoError` if signing fails or data conversion fails.
    public func sign(_ input: LosslessDataConvertible, algorithm: DigestAlgorithm, format: RSAInputFormat = .message, key: RSAKey) throws -> Data {
        switch key.type {
        case .public: throw CryptoError(identifier: "rsaSign", reason: "Cannot create RSA signature with a public key. A private key is required.")
        case .private: break
        }

        var siglen: UInt32 = 0
        var sig = Data(
            repeating: 0,
            count: Int(RSA_size(key.c.pointer))
        )

        var input = input.convertToData()

        switch format {
        case .digest: break // leave input as is
        case .message: input = try Digest(algorithm: algorithm).hash(input)
        }

        let ret = input.withByteBuffer { inputBuffer in
            return sig.withMutableByteBuffer { sigBuffer in
                return RSA_sign(
                    algorithm.type,
                    inputBuffer.baseAddress!,
                    UInt32(inputBuffer.count),
                    sigBuffer.baseAddress!,
                    &siglen,
                    key.c.pointer
                )
            }
        }

        guard ret == 1 else {
            throw CryptoError.openssl(identifier: "rsaSign", reason: "RSA signature creation failed")
        }

        return sig
    }

    @available(*, deprecated, message: "Use verify(_:algorithm:signs:format:key:)")
    public func verify(_ signature: LosslessDataConvertible, signs input: LosslessDataConvertible, format: RSAInputFormat = .message, key: RSAKey) throws -> Bool {
        return try verify(signature, algorithm: self.algorithm, signs: input, format: format, key: key)
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
    public func verify(_ signature: LosslessDataConvertible, algorithm: DigestAlgorithm, signs input: LosslessDataConvertible, format: RSAInputFormat = .message, key: RSAKey) throws -> Bool {
        var input = input.convertToData()
        let signature = signature.convertToData()

        switch format {
        case .digest: break // leave input as is
        case .message: input = try Digest(algorithm: algorithm).hash(input)
        }

        let result = input.withByteBuffer { inputBuffer in
            return signature.withByteBuffer { signatureBuffer in
                return RSA_verify(
                    algorithm.type,
                    inputBuffer.baseAddress!,
                    UInt32(inputBuffer.count),
                    signatureBuffer.baseAddress!,
                    UInt32(signatureBuffer.count),
                    key.c.pointer
                )
            }
        }
        return result == 1
    }


    /// Dencrypts the supplied input.
    ///
    ///     let decryptedData = try RSA().sign("vapor", padding: .pkcs1 ,key: .private(pem: ...))
    ///
    /// - parameters:
    ///     - input: Encrypted message to decrypt.
    ///     - padding: Padding used in the decryption.
    ///     - key: `RSAKey` to use for decrypting this data.
    /// - returns: Decrypted data.
    /// - throws: `CryptoError` if encrypting fails.
    public func decrypt(_ input: LosslessDataConvertible, padding: RSAPadding, key: RSAKey) throws -> Data {
        return try rsaPkeyCrypt(input, padding: padding, key: key, coder: RSA_private_decrypt)
    }

    /// Encrypts the supplied input.
    ///
    ///     let encryptedData = try RSA().encrypt("vapor", padding: .pkcs1 ,key: .public(pem: ...))
    ///
    /// - parameters:
    ///     - input: Plaintext message to encrypt.
    ///     - padding: Padding used in the encryption.
    ///     - key: `RSAKey` to use for encrypting this data.
    /// - returns: Encrypted data.
    /// - throws: `CryptoError` if encrypting fails.
    public func encrypt(_ input: LosslessDataConvertible, padding: RSAPadding, key: RSAKey) throws -> Data {
        return try rsaPkeyCrypt(input, padding: padding, key: key, coder: RSA_public_encrypt)
    }

    fileprivate func rsaPkeyCrypt(_ input: LosslessDataConvertible, padding: RSAPadding, key: RSAKey, coder: RSAPkeySymmetricCoder) throws -> Data {
        var outputData = Data(count: Int(RSA_size(key.c.pointer)))

        let outputLen = input.convertToData().withByteBuffer { inputBuffer in
            return outputData.withMutableByteBuffer { outputBuffer -> Int32 in
                return coder(
                    Int32(inputBuffer.count), // flen - input length
                    inputBuffer.baseAddress!, // from - input bytes
                    outputBuffer.baseAddress!, // to - output buffer
                    key.c.pointer, // rsa - the key itself
                    padding.rawValue // padding - padding mode
                )
            }
        }

        guard outputLen >= 0 else {
            throw CryptoError.openssl(identifier: "rsaPkeyCrypt", reason: "RSA data encryption operation failed")
        }
        return outputData.prefix(upTo: Int(outputLen))
    }

}

/// Supported RSA input formats.
public enum RSAInputFormat {
    /// The input has been hashed already.
    case digest
    /// Raw, unhashed message
    case message
}
