import XCTest
import OpenCrypto

class MACTests: XCTestCase {
    func testSHA1() throws {
        test(Insecure.SHA1.self, [
            ("vapor", "hello", "bb2a9aabb537902647f3f40bfecb679bf0d7d64b"),
            ("true", "2+2=4", "35836a9520eb061ad7e267ac37ab3ee1fafa6e4b"),
        ])
    }

    func testMD5() throws {
        test(Insecure.MD5.self, [
            ("vapor", "hello", "bbd98ab1dbed72cdf3e924ae7eaf7943"),
            ("true", "2+2=4", "37bda9a2b521d4623883b3acb7d9c3f7")
        ])
    }
}

private func test<H>(_ hash: H.Type, _ tests: [(key: String, plaintext: String, code: String)], line: UInt = #line)
    where H: HashFunction
{
    var line = line
    for test in tests {
        line += 1
        let code = HMAC<H>.authenticationCode(
            for: [UInt8](test.plaintext.utf8),
            using: SymmetricKey(data: [UInt8](test.key.utf8))
        )
        XCTAssertEqual(code.description, test.code.lowercased(), line: line)
    }
}
