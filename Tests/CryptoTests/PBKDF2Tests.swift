import XCTest
@testable import Crypto

class PBKDF2Tests: XCTestCase {
    static let allTests = [
        ("testSanity", testSanity),
    ]
    
    func testSanity() throws {
        let pbkdf2 = PBKDF2.SHA256
        
        for (key, salt, iterations, keySize, expectation) in tests {
            let result = try pbkdf2.hash(key, salt: salt, iterations: iterations, keySize: keySize)
            XCTAssertEqual(result.hexEncodedString(), expectation)
        }
    }
}

fileprivate let tests: [(key: String, salt: String, iterations: Int, keySize: PBKDF2KeySize, expectation: String)] = [
    ("password", "salt", 1, .fixed(20), "120fb6cffcf8b32c43e7225256c4f837a86548c9"),
    ("password", "salt", 2, .fixed(20), "ae4d0c95af6b46d32d0adff928f06dd02a303f8e"),
    ("password", "salt", 4_096, .fixed(20), "c5e478d59288c841aa530db6845c4c8d962893a0"),
    ("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4_096, .fixed(25), "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c"),
    ("pass\0word", "sa\0lt", 4_096, .fixed(16), "89b69d0516f829893c696226650a8687"),
]
