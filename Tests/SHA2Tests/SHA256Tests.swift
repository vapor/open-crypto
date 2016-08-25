import XCTest
import Core
@testable import SHA2

class SHA256Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance)
    ]

    func testBasic() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            "The quick brown fox jumps over the lazy cog": "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be",
            "": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ]

        for (key, expected) in tests {
            let result = try SHA256.hash(key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }
    
    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.250 release
        measure {
            let hasher = SHA256(data)
            _ = try! hasher.hash()
        }
    }
}
