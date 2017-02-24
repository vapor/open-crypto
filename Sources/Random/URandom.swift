import Core
import libc

/**
    URandom represents a file connection to /dev/urandom on Unix systems.
    /dev/urandom is a cryptographically secure random generator provided by the OS.
*/
public final class URandom: Random {
    public enum Error: Swift.Error {
        case open(errno_t)
        case read(errno_t)
    }

    private let file = fopen("/dev/urandom", "rb")

    /// Initialize URandom
    public init() {}

    deinit {
        fclose(file)
    }

    private func read(numBytes: Int) throws -> [Int8] {
        // The Random protocol doesn't allow init to fail, so we have to
        // check whether /dev/urandom was successfully opened here
        guard file != nil else {
            throw Error.open(errno)
        }

        // Initialize an empty array with space for numBytes bytes
        var bytes = [Int8](repeating: 0, count: numBytes)
        guard fread(&bytes, 1, numBytes, file) == numBytes else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw Error.read(errno)
        }
        return bytes
    }

    /// Get a random array of Bytes
    public func bytes(count: Int) throws -> Bytes {
        return try read(numBytes: count).map({ Byte(bitPattern: $0) })
    }
}
