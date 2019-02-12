import CCryptoOpenSSL

/// Specifies an authenticated cipher algorithm (e.g., AES-256-GCM) to be used with an `AuthenticatedCipher`.
///
/// Common authenticated cipher algorithms are provided as static properties on this class.
///
/// There are also static methods for creating `AuthenticatedCipherAlgorithm` such as `AuthenticatedCipherAlgorithm.named(_:)`
public final class AuthenticatedCipherAlgorithm: OpenSSLCipherAlgorithm {
    // MARK: Static

    /// Looks up an authenticated cipher function algorithm by name (e.g., "aes-256-gcm").
    /// Uses OpenSSL's `EVP_get_cipherbyname` function.
    ///
    ///     let algorithm = try CipherAlgorithm.named("aes-256-gcm")
    ///
    /// - parameters:
    ///     - name: Cipher function name
    /// - returns: Found `AuthenticatedCipherAlgorithm`
    /// - throws: `CryptoError` if no cipher for that name is found.
    public static func named(_ name: String) throws -> AuthenticatedCipherAlgorithm {
        guard let cipher = EVP_get_cipherbyname(name) else {
            throw CryptoError.openssl(identifier: "EVP_get_cipherbyname", reason: "No cipher named \(name) was found.")
        }
        return .init(c: cipher)
    }

    /// AES-256 GCM cipher. This is the recommended cipher.
    /// See the global `AES256GCM` constant on usage.
    public static let aes256gcm: AuthenticatedCipherAlgorithm = .init(c: EVP_aes_256_gcm())

    /// OpenSSL `EVP_CIPHER` context.
    public let c: UnsafePointer<EVP_CIPHER>

    /// Internal init accepting a `EVP_CIPHER`.
    public init(c: UnsafePointer<EVP_CIPHER>) {
        self.c = c
    }
}
