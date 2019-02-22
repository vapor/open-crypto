#if os(Linux)
import Glibc
#else
import Darwin
#endif

/// Uses the operating system's Random function uses `random` on Linux and `arc4random` on macOS.
public struct OSRandom: DataGenerator {
    /// Create a new `OSRandom`
    public init() {}

    /// See `DataGenerator`.
    public func generateData(count: Int) -> [UInt8] {
        var bytes: [UInt8] = []

        for _ in 0..<count {
            let random = makeRandom(min: 0, max: .maxByte)
            bytes.append(UInt8(random))
        }

        return bytes
    }

    fileprivate func makeRandom(min: Int, max: Int) -> Int {
        let top = max - min + 1
        #if os(Linux)
            // will always be initialized
            guard randomInitialized else { fatalError() }
            return Int(random() % top) + min
        #else
            return Int(arc4random_uniform(UInt32(top))) + min
        #endif
    }
}

extension Int {
    fileprivate static let maxByte: Int = Int(UInt8.max)
}
#if os(Linux)
import struct Foundation.Date
    /// Generates a random number between (and inclusive of)
    /// the given minimum and maximum.
    private let randomInitialized: Bool = {
        /// This stylized initializer is used to work around dispatch_once
        /// not existing and still guarantee thread safety
        let current = Date().timeIntervalSinceReferenceDate
        let salt = current.truncatingRemainder(dividingBy: 1) * 100000000
        srand(UInt32(current + salt))
        return true
    }()
#endif


