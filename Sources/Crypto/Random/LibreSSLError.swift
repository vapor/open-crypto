import CTLS

/// Represents an error returned by a LibreSSL function
public class LibreSSLError: Swift.Error, CustomStringConvertible {
    public let errorCode: UInt
    public let functionName: String?

    public init(errorCode: UInt? = nil, functionName: String? = nil) {
        self.errorCode = errorCode ?? ERR_get_error()
        self.functionName = functionName
    }

    public var description: String {
        var errorMessage = "Error \(errorCode)"

        // If we know the failing function's name, add it
        if let fn = functionName {
            errorMessage += " in \(fn)"
        }

        // Try to get a nice error message from LibreSSL
        if let errorCStr = ERR_error_string(errorCode, nil) {
            let errorStr = String(cString: UnsafePointer<CChar>(errorCStr))
            errorMessage += ": \(errorStr)"
        }
        return errorMessage
    }
}
