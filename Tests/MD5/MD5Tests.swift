import XCTest
import Core
@testable import MD5
import HMAC

class MD5Tests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic)
    ]

    func testBasic() throws {
        // Source: https://github.com/bcgit/bc-java/blob/adecd89d33edf278a5c601af2de696f0a6f65251/core/src/test/java/org/bouncycastle/crypto/test/MD5DigestTest.java
        let tests = [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b")
        ]
        
        for test in tests {
            let result = try MD5.hash(test.0.bytes).hexString.lowercased()
            XCTAssertEqual(result, test.1.lowercased())
        }
    }

    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.150 release
        measure {
            let hasher = MD5(data)
            _ = try! hasher.hash()
        }
    }


    func testHMAC() throws {
        let tests: [(key: String, message: String, expected: String)] = [
            (
                "vapor",
                "hello",
                "bbd98ab1dbed72cdf3e924ae7eaf7943"
            ),
            (
                "true",
                "2+2=4",
                "37bda9a2b521d4623883b3acb7d9c3f7"
            )
        ]

        for (i, test) in tests.enumerated() {
            do {
                let result = try HMAC<MD5>().authenticate(
                    test.message.bytes,
                    key: test.key.bytes
                    ).hexString.lowercased()
                XCTAssertEqual(result, test.expected.lowercased())
            } catch {
                XCTFail("Test \(i) failed: \(error)")
            }
        }
    }
}
