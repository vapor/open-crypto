import CNIOOpenSSL
import Foundation

/// RSA Paddings
public enum RSAPadding: Int32 {
    case pkcs1
    case sslv23
    case none
    case pkcs1_OAEP
    case x931

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
