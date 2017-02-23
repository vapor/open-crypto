import Core
import libc

/**
    URandom represents a file connection to /dev/urandom on Unix systems.
    /dev/urandom is a cryptographically secure random generator provided by the OS.
*/
public final class URandom: Random {
    private let file = fopen("/dev/urandom", "rb")
    
    /// Initialize URandom
    public init() {}
    
    deinit {
        fclose(file)
    }
    
    private func read(numBytes: Int) -> [Int8] {
        // Initialize an empty array with space for numBytes bytes
        var bytes = [Int8](repeating: 0, count: numBytes)
		guard fread(&bytes, 1, numBytes, file) == numBytes else {
			// If the requested number of random bytes couldn't be read,
			// we need to fail fast and hard.
			abort()
		}
        return bytes
    }
    
    /// Get a byte array of random UInt8s
    public func bytes(_ num: Int) -> Bytes {
        return read(numBytes: num).map({ Byte(bitPattern: $0) })
    }
}
