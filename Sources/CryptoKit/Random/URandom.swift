import Foundation

/// URandom represents a file connection to /dev/urandom on Unix systems.
/// `/dev/urandom` is a cryptographically secure random generator provided by the OS.
public final class URandom: DataGenerator {
    /// Internal error type.
    internal enum Error: Swift.Error {
        case open(Int32)
        case read(Int32)
    }

    /// Internal file pointer.
    private let file: UnsafeMutablePointer<FILE>

    /// Initialize URandom
    public init(path: String = "/dev/urandom") throws {
        guard let file = fopen(path, "rb") else {
            // The Random protocol doesn't allow init to fail, so we have to
            // check whether /dev/urandom was successfully opened here
            throw Error.open(errno)
        }
        self.file = file
    }

    /// Clean up file descriptor.
    deinit {
        fclose(file)
    }

    /// Internal read method.
    private func read(numBytes: Int) throws -> Data {
        // Initialize an empty array with space for numBytes bytes
        var bytes = [UInt8](repeating: 0, count: numBytes)

        guard fread(&bytes, 1, numBytes, file) == numBytes else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw Error.read(errno)
        }

        return Data(bytes)
    }

    /// Get a random array of Bytes
    public func generateData(count: Int) throws -> Data {
        return try read(numBytes: count)
    }
}
