import CNIOOpenSSL
import Debugging

/// An error encountered while working with RSA ciphers.
public struct RSAError: Debuggable {
    /// See `Debuggable.identifier`
    public var identifier: String

    /// See `Debuggable.reason`
    public var reason: String

    /// Internal error creation from OpenSSLL
    internal static func c(identifier: String, reason: String) -> RSAError {
        let errmsg: UnsafeMutablePointer<Int8>? = nil
        ERR_error_string(ERR_get_error(), errmsg)

        let cReason: String
        if let e = errmsg {
            cReason = String(validatingUTF8: e) ?? "unknown (invalid error message UTF8)"
        } else {
            cReason = "unknown"
        }

        return RSAError(identifier: identifier, reason: "\(reason): \(cReason).")
    }
}
