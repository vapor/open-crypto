import XCTest
import OpenCrypto

class MD5Tests: XCTestCase {
    func testMD5() throws {
        test(Insecure.MD5.self, [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
            ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"),
            ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"),
        ])
    }

    func testSHA1() throws {
        test(Insecure.SHA1.self, [
            ("The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"),
            ("The quick brown fox jumps over the lazy cog", "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3"),
            ("", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            ("abc", "A9993E364706816ABA3E25717850C26C9CD0D89D"),
            ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"),
            ("a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8"),
            ("0123456701234567012345670123456701234567012345670123456701234567", "e0c094e867ef46c350ef54a7f59dd60bed92ae83")
        ])
    }

    func testSHA256() throws {
        test(SHA256.self, [
            ("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
            ("The quick brown fox jumps over the lazy cog", "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be"),
            ("Pa$SW0|2d", "c2bb64cc6937ab83020d6114d411d6d3de14d89ad73560a4036b7267b3121856")
        ])
    }

    func testSHA384() throws {
        test(SHA384.self, [
            ("The quick brown fox jumps over the lazy dog", "ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1"),
            ("The quick brown fox jumps over the lazy cog", "098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b"),
            ("Pa$SW0|2d", "8625b180d9108f2ce79f4b45462b90e0bf3ac6672333bb4b61b81ed0dd2b7f75d9e0a21a4a9201b6f4366d05cd25d3ec")
        ])
    }

    public func testSHA512() throws {
        test(SHA512.self, [
            ("The quick brown fox jumps over the lazy dog", "07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6"),
            ("The quick brown fox jumps over the lazy cog", "3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045"),
            ("Pa$SW0|2d", "d9d9d269119f146e54677895d44f712b8f1c361df6a085b03a44a00018479239b0835137e2921400c2d9a51f02d009804f563cd4c95d09c494b6e12242a81eff")
        ])
    }
}

func test<H>(_ hash: H.Type, _ tests: [(plaintext: String, digest: String)], line: UInt = #line)
    where H: HashFunction
{
    var line = line
    for test in tests {
        line += 1
        let digest = H.hash(data: [UInt8](test.plaintext.utf8))
        XCTAssertEqual(digest.description, test.digest.lowercased(), line: line)
    }
}
