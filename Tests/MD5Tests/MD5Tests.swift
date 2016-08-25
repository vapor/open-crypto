import XCTest
import Core
@testable import MD5

class MD5Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance)
    ]

    func testBasic() throws {
        // Source: https://en.wikipedia.org/wiki/MD5#MD5_hashes
        let tests = [
            "The quick brown fox jumps over the lazy dog": "9e107d9d372bb6826bd81d3542a419d6",
            "The quick brown fox jumps over the lazy dog.": "e4d909c290d0fb1ca068ffaddf22cbd0",
            "": "d41d8cd98f00b204e9800998ecf8427e"
        ]

        for (key, expected) in tests {
            let result = try MD5.hash(key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }

    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.250 release
        measure {
            let hasher = MD5(data)
            _ = try! hasher.hash()
        }
    }
}
