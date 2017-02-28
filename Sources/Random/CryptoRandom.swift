import CLibreSSL
import Core


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


/// Generates cryptographically secure random data using LibreSSL
public final class CryptoRandom: Random, EmptyInitializable {
    public init() {}

    public func bytes(count: Int) throws -> Bytes {
        var random = Bytes(repeating: 0, count: count)
        guard RAND_bytes(&random, Int32(count)) == 1 else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw LibreSSLError(functionName: "RAND_bytes")
        }
        return random
    }
}


/// Generates non-secure pseudorandom data using LibreSSL
public final class PseudoRandom: Random, EmptyInitializable {
    public init() {}

    public func bytes(count: Int) throws -> Bytes {
        var random = Bytes(repeating: 0, count: count)
        guard RAND_pseudo_bytes(&random, Int32(count)) == 1 else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw LibreSSLError(functionName: "RAND_pseudo_bytes")
        }
        return random
    }
}


// Class name has typo ('e' and 'u' reversed)
@available(*, deprecated, renamed: "PseudoRandom")
typealias PsuedoRandom = PseudoRandom
