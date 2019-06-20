import XCTest
import OpenCrypto

class AESTests: XCTestCase {
    func testAESGCM() throws {
        try test([
            ("passwordpasswordpasswordpassword", "vapor", "123456789012"),
            ("passwordpasswordpassword", "vapor", "123456789012"),
            ("passwordpassword", "vapor", "123456789012"),
        ])
    }
}

private func test(_ tests: [(key: String, plaintext: String, iv: String)], line: UInt = #line) throws {
    var line = line
    for test in tests {
        line += 1
        let key = SymmetricKey(data: [UInt8](test.key.utf8))
        let box = try AES.GCM.seal(
            [UInt8](test.plaintext.utf8),
            using: key,
            nonce: .init(data: [UInt8](test.iv.utf8))
        )
        let plaintext = try AES.GCM.open(box, using: key)
        XCTAssertEqual(test.plaintext, String(decoding: plaintext, as: UTF8.self), line: line)
    }
}
