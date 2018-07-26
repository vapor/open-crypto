import XCTest
import Crypto

class OTPTests: XCTestCase {
    func testTOTPBasic() throws {
        let key = "hi"
        let code = try TOTP.SHA1.generateRange(degree: 1, secret: key)
        XCTAssertEqual(code.count, 3)
    }

    func testHOTPBasic() throws {
        let key = "hi"
        try XCTAssertEqual(HOTP.SHA1.generate(secret: key, counter: 0), "208503")
        try XCTAssertEqual(HOTP.SHA1.generate(digits: .seven, secret: key, counter: 0), "3208503")
        try XCTAssertEqual(HOTP.SHA1.generate(digits: .eight, secret: key, counter: 0), "63208503")
        try XCTAssertEqual(HOTP.SHA1.generate(digits: .eight, secret: key, counter: 1), "94463990")
    }
    
    static var allTests = [
        ("testTOTPBasic", testTOTPBasic),
        ("testHOTPBasic", testHOTPBasic),
    ]
}
