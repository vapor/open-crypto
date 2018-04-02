import XCTest
import Crypto

class CipherTests: XCTestCase {
    func testAES128Basic() throws {
        let message = "vapor"
        let key = "passwordpassword"
        let ciphertext = try AES128.encrypt(message, key: key)
        XCTAssertEqual(ciphertext.hexEncodedString(), "6fb70cc0bebacac2b3efebe62b1a092e")
        try XCTAssertEqual(AES128.decrypt(ciphertext, key: key).convert(), message)
    }

    func testAES128WellKnownDecode() throws {
        let key = "passwordpassword"
        let ciphertext = Data(bytes: [0x6F, 0xB7, 0x0C, 0xC0, 0xBE, 0xBA, 0xCA, 0xC2, 0xB3, 0xEF, 0xEB, 0xE6, 0x2B, 0x1A, 0x09, 0x2E])
        try XCTAssertEqual(AES128.decrypt(ciphertext, key: key).convert(), "vapor")
    }

    func testCipherReuse() throws {
        let cipher = AES128
        do {
            let message = "vapor1"
            let key = "passwordpasswor1"
            let ciphertext = try cipher.encrypt(message, key: key)
            XCTAssertEqual(ciphertext.hexEncodedString(), "6a074f4ae8305d64d3d8c6e97630c6ca")
            try XCTAssertEqual(cipher.decrypt(ciphertext, key: key).convert(), message)
        }
        do {
            let message = "vapor2"
            let key = "passwordpasswor2"
            let ciphertext = try cipher.encrypt(message, key: key)
            XCTAssertEqual(ciphertext.hexEncodedString(), "84b1bba5f1cb060902b25dab3dfce5cb")
            try XCTAssertEqual(cipher.decrypt(ciphertext, key: key).convert(), message)
        }
    }

    func testAES256Basic() throws {
        let message = "vapor"
        let key = "passwordpasswordpasswordpassword"
        let ciphertext = try AES256.encrypt(message, key: key)
        XCTAssertEqual(ciphertext.hexEncodedString(), "8eb630e88555b42eed039b21c0fa9ce1")
        try XCTAssertEqual(AES256.decrypt(ciphertext, key: key).convert(), message)
    }

    func testAES128Manual() throws {
        let key = "passwordpassword"
        let aes128 = Cipher(algorithm: .aes128ecb)
        try aes128.reset(key: key, mode: .encrypt)
        var buffer = Data()
        try aes128.update(data: "hello", into: &buffer)
        try aes128.update(data: "world", into: &buffer)
        try aes128.finish(into: &buffer)
        XCTAssertEqual(buffer.hexEncodedString(), "30474812739e34062c8fbb3610f95830")
        try XCTAssertEqual(AES128.decrypt(buffer, key: key).convert(), "helloworld")
    }

    static var allTests = [
        ("testAES128Basic", testAES128Basic),
        ("testAES128WellKnownDecode", testAES128WellKnownDecode),
        ("testCipherReuse", testCipherReuse),
        ("testAES256Basic", testAES256Basic),
        ("testAES128Manual", testAES128Manual),
    ]
}

extension Data {
    public func convert<T>(to type: T.Type = T.self) throws -> T where T: LosslessDataConvertible {
        return try T.convertFromData(self)
    }
}
