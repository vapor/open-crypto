import CCryptoOpenSSL
import Foundation

/// RSA Paddings
public enum RSAPadding: Int32 {
    /// PKCS #1 v1.5 padding
    case pkcs1
    /// SSLv23 padding
    case sslv23
    /// No padding
    case none
    /// PKCS #1 v2.0 EME-OAEP + SHA-1 + MGF1 padding
    case pkcs1_OAEP
    /// X9.31 padding
    case x931

    /// Creates a new RSAPadding from an Int32.
    /// Valid raw values are defined in OpenSSL
    public init?(rawValue: Int32) {
        switch rawValue {
        case RSA_PKCS1_PADDING:
            self = .pkcs1
        case RSA_SSLV23_PADDING:
            self = .sslv23
        case RSA_NO_PADDING:
            self = .none
        case RSA_PKCS1_OAEP_PADDING:
            self = .pkcs1_OAEP
        case RSA_X931_PADDING:
            self = .x931
        default:
            return nil
        }
    }

    /// See `RawRepresentable`.
    public var rawValue: Int32 {
        switch self {
        case .pkcs1:
            return RSA_PKCS1_PADDING
        case .sslv23:
            return RSA_SSLV23_PADDING
        case .none:
            return RSA_NO_PADDING
        case .pkcs1_OAEP:
            return RSA_PKCS1_OAEP_PADDING
        case .x931:
            return RSA_X931_PADDING
        }
    }
}
