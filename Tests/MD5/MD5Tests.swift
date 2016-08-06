import XCTest
import Core
@testable import MD5
@testable import HMAC

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
    
}
