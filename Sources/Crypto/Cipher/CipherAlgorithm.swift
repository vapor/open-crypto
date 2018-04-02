import CNIOOpenSSL

public final class CipherAlgorithm {
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
        return .init(c: cipher)
    }

    /// OpenSSL `EVP_CIPHER` context.
    let c: UnsafePointer<EVP_CIPHER>

    /// Internal init accepting a `EVP_CIPHER`.
    init(c: UnsafePointer<EVP_CIPHER>) {
        self.c = c
    }

    /// Returns the OpenSSL NID type for this algorithm.
    public var type: Int32 {
        return EVP_CIPHER_type(c)
    }

    public var keySize: Int32 {
        return EVP_CIPHER_key_length(c)
    }

    public var ivSize: Int32 {
        return EVP_CIPHER_iv_length(c)
    }

    public var blockSize: Int32 {
        return EVP_CIPHER_block_size(c)
    }

    public static let aes128ecb: CipherAlgorithm = .init(c: EVP_aes_128_ecb())

    public static let aes256ecb: CipherAlgorithm = .init(c: EVP_aes_256_ecb())
}
