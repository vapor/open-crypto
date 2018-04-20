import XCTest
@testable import Crypto

class BCryptTests: XCTestCase {
    static let allTests = [
        ("testVersion", testVersion),
        ("testFail", testFail),
        ("testInvalidSalt", testInvalidSalt),
        ("testVerify", testVerify),
        ("testNotVerify", testNotVerify),
    ]

    func testVersion() throws {
        let digest = try BCrypt.hash("foo", cost: 6)
        XCTAssert(digest.hasPrefix("$2b$06$"))
    }

    func testFail() throws {
        let digest = try BCrypt.hash("foo", cost: 6)
        let res = try BCrypt.verify("bar", created: digest)
        XCTAssertEqual(res, false)
    }

    func testInvalidSalt() throws {
        do {
            _ = try BCrypt.verify("", created: "foo")
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

    func testNotVerify() throws {
        let testCase = tests.first!
        let message = "vapor_" + testCase.value
        let shouldNotMatch = testCase.key
        let result = try BCrypt.verify(message, created: shouldNotMatch)
        XCTAssertFalse(result, "\(shouldNotMatch): matched \(message)")
    }
}

let tests = [
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" : "U*U",
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK" : "U*U*",
    "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a" : "U*U*U",
    "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui" :
        "0123456789abcdefghijklmnopqrstuvwxyz" +
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
        "chars after 72 are ignored",
    "$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm" : "vapor",
    "$2y$11$kHM/VXmCVsGXDGIVu9mD8eY/uEYI.Nva9sHgrLYuLzr0il28DDOGO" : "Vapor3",
    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." : "",
    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" : "a",
    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" : "abc",
    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" : "abcdefghijklmnopqrstuvwxyz",
    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" : "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
]
