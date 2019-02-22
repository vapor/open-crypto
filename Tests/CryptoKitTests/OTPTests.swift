import XCTest
import CryptoKit

class OTPTests: XCTestCase {
    func testTOTPBasic() throws {
        let key: CryptoData = "hi"
        let code = try TOTP.SHA1.generateRange(degree: 1, secret: key)
        XCTAssertEqual(code.count, 3)
    }

    func testHOTPBasic() throws {
        let key: CryptoData = "hi"
        try XCTAssertEqual(HOTP.SHA1.generate(secret: key, counter: 0), "208503")
        try XCTAssertEqual(HOTP.SHA1.generate(digits: .seven, secret: key, counter: 0), "3208503")
        try XCTAssertEqual(HOTP.SHA1.generate(digits: .eight, secret: key, counter: 0), "63208503")
        try XCTAssertEqual(HOTP.SHA1.generate(digits: .eight, secret: key, counter: 1), "94463990")
    }
    
    func testBase32() throws {
        let message: CryptoData = "Hello, world!"
        let encoded = message.base32EncodedString()
        let decoded = Data(base32Encoded: encoded) ?? .init()
        XCTAssertEqual(.data(decoded), message)
    }
    
    static var allTests = [
        ("testTOTPBasic", testTOTPBasic),
        ("testHOTPBasic", testHOTPBasic),
        ("testBase32", testBase32),
    ]
}
