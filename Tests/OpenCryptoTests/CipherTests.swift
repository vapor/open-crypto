import XCTest
import OpenCrypto

class CipherTests: XCTestCase {
    func testAESGCM() throws {
        try test(AES.GCM.self, [
            ("passwordpasswordpasswordpassword", "vapor"),
            ("passwordpasswordpassword", "vapor"),
            ("passwordpassword", "vapor"),
            ("passwordpasswordpasswordpassword", ""),
            ("passwordpasswordpassword", ""),
            ("passwordpassword", ""),
        ])
    }
    func testChaChaPoly() throws {
        try test(ChaChaPoly.self, [
            ("passwordpasswordpasswordpassword", "vapor"),
            ("passwordpasswordpasswordpassword", ""),
        ])
    }
}

private func test<C>(_ cipher: C.Type, _ tests: [(key: String, plaintext: String)], line: UInt = #line) throws
    where C: CipherFunction
{
    var line = line
    for test in tests {
        line += 1
        let key = SymmetricKey(data: [UInt8](test.key.utf8))
        let box = try C.seal(
            [UInt8](test.plaintext.utf8),
            using: key
        )
        let plaintext = try C.open(box, using: key)
        XCTAssertEqual(test.plaintext, String(decoding: plaintext, as: UTF8.self), line: line)
    }
}

private extension String {
    var bytes: [UInt8] {
        return .init(self.utf8)
    }
}
