import XCTest
@testable import Crypto

class BCryptTests: XCTestCase {
    static let allTests = [
        ("testVersion", testVersion),
        ("testFail", testFail),
        ("testSanity", testSanity),
        ("testInvalidSalt", testInvalidSalt),
        ("testVerify", testVerify)
    ]
    
    func testVersion() throws {
        let digest = try BCrypt.hash("foo", cost: 6)
        XCTAssert(String(bytes: digest, encoding: .utf8)!.hasPrefix("$2y$06$"))
    }
    
    func testFail() throws {
        let digest = try BCrypt.hash("foo", cost: 6)
        let res = try BCrypt.verify("bar", created: digest)
        XCTAssertEqual(res, false)
    }
    
    func testSanity() throws {
        let secret = "passwordpassword"
        let res = try BCrypt.hash("foo", cost: 4, salt: secret)

        let parser = try BCryptParser(serialized: res)
        let parsedSalt = try parser.parseConfig()
        
        XCTAssertEqual(secret, String(bytes: parsedSalt.salt, encoding: .utf8))
    }
    
    func testInvalidSalt() throws {
        do {
            _ = try BCryptParser(serialized: Data("foo".utf8))
            XCTFail("Should have failed")
        } catch let error as CryptoError {
            print(error)
        }
    }
    
    func testVerify() throws {
        for (desired, message) in tests {
            let result = try BCrypt.verify(message, created: desired)
            XCTAssert(result, "\(message): did not match \(desired)")
        }
    }
}

let tests = [
    "$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm": "vapor",
    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.": "",
    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe": "a",
    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i": "abc",
    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC": "abcdefghijklmnopqrstuvwxyz",
    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO": "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"
]
