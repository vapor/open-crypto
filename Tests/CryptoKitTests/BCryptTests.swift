import XCTest
import CryptoKit

public class BCryptTests: XCTestCase {
    public func testVersion() throws {
        let digest = try BCrypt.hash("foo", cost: 6)
        XCTAssert(digest.string().hasPrefix("$2b$06$"))
    }

    public func testFail() throws {
        let digest = try BCrypt.hash("foo", cost: 6)
        let res = try BCrypt.verify("bar", created: digest)
        XCTAssertEqual(res, false)
    }
    
    public func testInvalidMinCost() throws {
        XCTAssertThrowsError(try BCrypt.hash("foo", cost: 2))
    }

    public func testInvalidMaxCost() throws {
        XCTAssertThrowsError(try BCrypt.hash("foo", cost: 32))
    }

    public func testInvalidSalt() throws {
        do {
            _ = try BCrypt.verify("", created: "foo")
            XCTFail("Should have failed")
        } catch let error as CryptoError {
            print(error)
        }
    }

    public func testVerify() throws {
        for (desired, message) in tests {
            let result = try BCrypt.verify(message, created: desired)
            XCTAssert(result, "\(message): did not match \(desired)")
        }
    }

    public func testNotVerify() throws {
        let testCase = tests.first!
        let message = "vapor_" + testCase.1.string()
        let shouldNotMatch = testCase.0.string()
        let result = try BCrypt.verify(.string(message), created: .string(shouldNotMatch))
        XCTAssertFalse(result, "\(shouldNotMatch): matched \(message)")
    }
    
    public func testExample1() throws {
        let hash = try BCrypt.hash("vapor", cost: 4)
        try XCTAssertEqual(BCrypt.verify("vapor", created: hash), true)
        try XCTAssertEqual(BCrypt.verify("foo", created: hash), false)
    }
    
    public static let allTests = [
        ("testVersion", testVersion),
        ("testFail", testFail),
        ("testInvalidSalt", testInvalidSalt),
        ("testVerify", testVerify),
        ("testNotVerify", testNotVerify),
        ("testInvalidMinCost", testInvalidMinCost),
        ("testInvalidMaxCost", testInvalidMaxCost),
        ("testExample1", testExample1),
    ]
}

let tests: [(CryptoData, CryptoData)] = [
    ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U"),
    ("$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", "U*U*"),
    ("$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a", "U*U*U"),
    ("$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui", "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789chars after 72 are ignored"),
    ("$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm", "vapor"),
    ("$2y$11$kHM/VXmCVsGXDGIVu9mD8eY/uEYI.Nva9sHgrLYuLzr0il28DDOGO", "Vapor3"),
    ("$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s.", ""),
    ("$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe", "a"),
    ("$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i", "abc"),
    ("$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC", "abcdefghijklmnopqrstuvwxyz"),
    ("$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD"),
]
