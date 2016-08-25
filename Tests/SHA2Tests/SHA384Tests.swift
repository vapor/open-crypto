import XCTest
import Core
@testable import SHA2

class SHA384Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance)
    ]

    func testBasic() throws {
        // Source: https://en.wikipedia.org/wiki/SHA-2
        let tests = [
            "The quick brown fox jumps over the lazy dog": "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1",
            "The quick brown fox jumps over the lazy cog": "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b",
            "": "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        ]

        for (key, expected) in tests {
            let result = try SHA384.hash(key.bytes).hexString.lowercased()
            XCTAssertEqual(result, expected.lowercased())
        }
    }
    
    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.250 release
        measure {
            let hasher = SHA384(data)
            _ = try! hasher.hash()
        }
    }
}
