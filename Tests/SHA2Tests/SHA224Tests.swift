import XCTest
import Core
@testable import SHA2

class SHA224Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance)
    ]

    func testBasic() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525",
            "The quick brown fox jumps over the lazy cog": "fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b",
            "": "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        ]

        for (key, expected) in tests {
            let result = try SHA224.hash(key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }
    
    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.250 release
        measure {
            let hasher = SHA224(data)
            _ = try! hasher.hash()
        }
    }
}
