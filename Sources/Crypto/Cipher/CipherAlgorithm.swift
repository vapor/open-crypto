import CCryptoOpenSSL

/// Specifies a cipher algorithm (e.g., AES128-ECB) to be used with a `Cipher`.
///
/// Common cipher algorithms are provided as static properties on this class.
///
/// There are also static methods for creating `CipherAlgorithm` such as `CipherAlgorithm.named(_:)`
public final class CipherAlgorithm {
    // MARK: Static

    /// Looks up a cipher function algorithm by name (e.g., "aes-128-cbc").
    /// Uses OpenSSL's `EVP_get_cipherbyname` function.
    ///
    ///     let algorithm = try CipherAlgorithm.named("aes-128-cbc")
    ///
    /// - parameters:
    ///     - name: Cipher function name
    /// - returns: Found `CipherAlgorithm`
    /// - throws: `CryptoError` if no cipher for that name is found.
    public static func named(_ name: String) throws -> CipherAlgorithm {
        guard let cipher = EVP_get_cipherbyname(name) else {
            throw CryptoError.openssl(identifier: "EVP_get_cipherbyname", reason: "No cipher named \(name) was found.")
        }
        return .init(c: cipher.convert())
    }

    /// AES-128 ECB cipher. Deprecated (see https://github.com/vapor/crypto/issues/59).
    @available(*, deprecated, message: "Stream encryption in ECB mode is unsafe (see https://github.com/vapor/crypto/issues/59). Use AES256 in GCM mode instead.")
    public static let aes128ecb: CipherAlgorithm = .init(c: EVP_aes_128_ecb().convert())

    /// AES-256 ECB cipher. Deprecated (see https://github.com/vapor/crypto/issues/59).
    @available(*, deprecated, message: "Stream encryption in ECB mode is unsafe (see https://github.com/vapor/crypto/issues/59). Use AES256 in GCM mode instead.")
    public static let aes256ecb: CipherAlgorithm = .init(c: EVP_aes_256_ecb().convert())

    /// AES-256 CBC cipher.
    /// Only use this if you know what you are doing; use AES-256 GCM otherwise (see https://github.com/vapor/crypto/issues/59).
    public static let aes256cbc: CipherAlgorithm = .init(c: EVP_aes_256_cbc().convert())

    /// AES-256 CFB cipher. May not be available on all platforms.
    /// Only use this if you know what you are doing; use AES-256 GCM otherwise (see https://github.com/vapor/crypto/issues/59).
    public static let aes256cfb: CipherAlgorithm = .init(c: EVP_aes_256_cfb128().convert())

    /// AES-256 GCM cipher. This is the recommended cipher.
    /// See the global `AES256GCM` constant on usage.
    public static let aes256gcm: CipherAlgorithm = .init(c: EVP_aes_256_gcm().convert())

    /// OpenSSL `EVP_CIPHER` context.
    public let c: OpaquePointer

    /// Internal init accepting a `EVP_CIPHER`.
    public init(c: OpaquePointer) {
        self.c = c
    }

    // MARK: Instance

    /// Returns the OpenSSL NID type for this algorithm.
    public var type: Int32 {
        return EVP_CIPHER_type(c.convert())
    }

    /// This cipher's required key length.
    public var keySize: Int32 {
        return EVP_CIPHER_key_length(c.convert())
    }

    /// This cipher's required initialization vector length.
    public var ivSize: Int32 {
        return EVP_CIPHER_iv_length(c.convert())
    }

    /// This cipher's block size, used internally to allocate "out" buffers.
    public var blockSize: Int32 {
        return EVP_CIPHER_block_size(c.convert())
    }
}
