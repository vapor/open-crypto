import CNIOOpenSSL
import NIOOpenSSL
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

    /// The C OpenSSL key ref.
    internal let c: CRSAKey

    /// Creates a new `RSAKey` from a public or private key.
    public init(bits: Int, type: RSAKeyType, key: DataRepresentable) throws {
        self.bits = bits
        self.type = type
        self.c = try .make(type: type, from: key.makeData())
    }

    /// Creates a new `RSAKey` from a certificate.
    public init(bits: Int, certificate: DataRepresentable) throws {
        self.bits = bits
        self.type = .public
        self.c = try .make(type: .public, from: certificate.makeData(), x509: true)
    }
}

/// Supported RSA key types.
public enum RSAKeyType {
    /// A public RSA key. Used for verifying signatures.
    case `public`
    /// A private RSA key. Used for creating and verifying signatures.
    case `private`
}

/// Reference pointer to an OpenSSL rsa_st key.
/// This wrapper is important for ensuring the key is freed when it is no longer in use.
final class CRSAKey {
    /// The wrapped pointer.
    let pointer: UnsafeMutablePointer<rsa_st>

    /// Creates a new `CRSAKey` from a pointer.
    private init(_ pointer: UnsafeMutablePointer<rsa_st>) {
        self.pointer = pointer
    }

    /// Creates a new `CRSAKey` from type, data. Specifying `x509` true will treat the data as a certificate.
    static func make(type: RSAKeyType, from data: Data, x509: Bool = false) throws -> CRSAKey {
        let bio = BIO_new(BIO_s_mem())
        defer { BIO_free(bio) }

        let nullTerminatedData = data + Data(bytes: [0])
        _ = nullTerminatedData.withUnsafeBytes { key in
            return BIO_puts(bio, key)
        }

        let maybePkey: UnsafeMutablePointer<EVP_PKEY>?

        if x509 {
            guard let x509 = PEM_read_bio_X509(bio, nil, nil, nil) else {
                throw RSAError.c(identifier: "x509", reason: "Key creation from certificate failed")
            }

            defer { X509_free(x509) }
            maybePkey = X509_get_pubkey(x509)
        } else {
            switch type {
            case .public: maybePkey = PEM_read_bio_PUBKEY(bio, nil, nil, nil)
            case .private: maybePkey = PEM_read_bio_PrivateKey(bio, nil, nil, nil)
            }
        }

        guard let pkey = maybePkey else {
            print("type: \(type) x509: \(x509)")
            throw RSAError.c(identifier: "pkeynull", reason: "Key creation failed")
        }
        defer { EVP_PKEY_free(pkey) }

        guard let rsa = EVP_PKEY_get1_RSA(pkey) else {
            throw RSAError.c(identifier: "pkeyget1", reason: "Key creation failed")
        }
        return .init(rsa)
    }

    deinit { RSA_free(pointer) }
}
