import XCTest
import Crypto
import CTLS

class HMACTests: XCTestCase {
    static var allTests = [
        ("testBasic", testBasic),
        ("testPerformance", testPerformance)
    ]

    func testBasic() throws {
        let digest = try HMAC(.sha1, "vapor").authenticate(key: "42")
        XCTAssertEqual(digest.hexString, "b15d2d34c729a0647a6f124d5afe1927e55a9d7c")
    }

    func testCustom() throws {
        let digest = try HMAC(.ripemd160, "vapor").authenticate(key: "42")
        XCTAssertEqual(digest.hexString, "5d58ce7fc433f91466129c792f6e66a9be170663")
    }

    func testConvenience() throws {
        let digest = try HMAC(.sha256, "vapor").authenticate(key: "42")
        XCTAssertEqual(digest.hexString, "6b3291cf4676ee313efc7a35adc889426847975aee8cebcac28e46df5a2f9bbe")

    }

    func testPerformance() {
        let data = Bytes(repeating: Byte.A, count: 10_000_000)

        // ~0.020 release
        measure {
            let hmac = HMAC(.sha1, data)
            _ = try! hmac.authenticate(key: "42".makeBytes())
        }
    }
}
