import XCTest
import Core
@testable import SHA1

class SHA1Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance)
    ]

    func testBasic() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-1#Example_hashes
        let tests = [
            "The quick brown fox jumps over the lazy dog": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
            "The quick brown fox jumps over the lazy cog": "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3",
            "": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ]

        for (key, expected) in tests {
            let result = try SHA1.hash(key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }
    
    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.250 release
        measure {
            let hasher = SHA1(data)
            _ = try! hasher.hash()
        }
    }
}
