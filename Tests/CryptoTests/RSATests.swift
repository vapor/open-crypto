import XCTest
import Bits
import Crypto

class RSATests: XCTestCase {
    func testPrivateKey() throws {
        let privateKey = try Base64Decoder(encoding: .base64).decode(string: privateKeyString)
        let plaintext = Data("vapor".utf8)
        let rsa = RSA(key: .private2048(privateKey))
        try XCTAssertTrue(rsa.verify(rsa.sign(plaintext), signs: plaintext))
    }

    func testPublicKey() throws {
        let publicKey = try Base64Decoder(encoding: .base64).decode(string: publicKeyString)
        let plaintext = Data("vapor".utf8)
        let rsa = RSA(key: .public2048(publicKey))
        try XCTAssertTrue(rsa.verify(testSignature, signs: plaintext))
    }

    func testFailure() throws {
        let plaintext = Data("vapor".utf8)
        let publicKey = try Base64Decoder(encoding: .base64).decode(string: publicKeyString)
        let rsa = RSA(key: .public2048(publicKey))
        try XCTAssertFalse(rsa.verify(Data("fake".utf8), signs: plaintext))
    }

    static var allTests = [
        ("testPrivateKey", testPrivateKey),
        ("testPublicKey", testPublicKey),
        ("testFailure", testFailure),
    ]
}

let testSignature = Data([89, 214, 169, 236, 21, 246, 207, 217, 142, 28, 105, 179, 141, 64, 202, 250, 90, 130, 245, 201, 158, 123, 23, 75, 95, 235, 116, 103, 240, 91, 211, 185, 117, 143, 222, 94, 247, 165, 211, 71, 97, 251, 23, 3, 160, 69, 127, 22, 112, 251, 111, 196, 212, 36, 255, 229, 91, 79, 220, 158, 241, 117, 253, 95, 23, 196, 41, 54, 96, 191, 42, 126, 249, 32, 110, 147, 165, 231, 108, 29, 231, 75, 80, 104, 217, 157, 134, 198, 138, 111, 188, 235, 171, 100, 59, 21, 244, 33, 176, 234, 22, 77, 202, 164, 38, 50, 183, 16, 45, 106, 225, 228, 20, 136, 87, 204, 192, 243, 177, 208, 157, 151, 194, 252, 223, 152, 165, 34, 143, 125, 162, 51, 162, 86, 203, 191, 216, 170, 184, 67, 145, 6, 75, 46, 66, 203, 47, 54, 106, 98, 136, 143, 190, 234, 233, 113, 132, 217, 61, 25, 73, 202, 30, 210, 185, 5, 52, 153, 165, 119, 215, 196, 79, 118, 83, 79, 184, 142, 255, 54, 209, 12, 227, 247, 63, 228, 84, 92, 109, 84, 238, 132, 29, 8, 175, 156, 97, 156, 176, 67, 24, 95, 182, 27, 191, 44, 117, 163, 89, 253, 105, 212, 81, 80, 130, 217, 24, 99, 34, 21, 103, 225, 60, 201, 54, 16, 132, 15, 22, 139, 41, 96, 74, 173, 224, 128, 63, 9, 238, 59, 102, 250, 44, 63, 66, 13, 82, 98, 93, 163, 73, 142, 74, 125, 172, 247])

let privateKeyString = """
MIIEpAIBAAKCAQEAk+dWlCTQIr85rtUi56yD6FT6vuG68Q9xJ4B9bAo4wys+ndlP
SX0UQkrPOpnNZcsHOob6DbRI5Cc4qce00nNJAlCxYqAJDDDryyQEtUv8ghGGWnjU
gBRytm39UM9s/UxyLfGWk3P1Z1us8q5RvsrceC28uG94Lr+w2XmcBwxP020qJIiU
qOff8me1vI7vogvec3yO6pLvb1zcqMioKIdQ/kWjgMvhVyFyg44IqEI1iApjt05C
jTQ30W1xyN/9b/cedQzEg8Nq2MQdhKCIZJh2vjSUuWOBCnx+ttErIYt0roisNj1O
howtSM6k0vV1LPDrCjV7lFPmE1njwTfdV/vlcQIDAQABAoIBAGBwjt6oJmMRx139
sfXYYmZiyuEeNRQsGn9EZAPHon14PCsW4IEtosEbIIa4dNq0CPGbw36eGI1UGbly
86/p5igxT4jciym82HMr+Dny4yI4pR9m/EDLlITpsSw5JHsBls3oYmOhT9nmSB4x
ljHO+vUN9alZXcc1zO3xQtDBsWdNG73YFRAv2HJ6us50wQXw4cEsuQo6X/fUREkB
nznkArTcm/VcnZFaRUg4sXQBBQdy3LhRh3zQ5V64iBe9AWgenDv7tO5Bk8xhrLE/
kBdvyrTsWKaKSSnes28oB5YLfbFpRYnYGGuaWbu5f0deOuQlS5F5HxuaHHsdRxaU
Xee7BLECgYEA60QxWsXdeIWXmMhOoCapq6OTdaPVVzZfZc57s82xy5IgghBJj3up
QbOIcfcBNTmpG4ohtB5EEmOozBKEm3dg09RF9aQ/t4Gx4TOmbtCt8IiuNAr4zj7+
xsLWh1sWGK0UvZ1hkkKoFxHU7ienXCfhfiEjBLWtNGzVHieoIc1Ly00CgYEAoPAr
Txegn2ZreU4vn6CP9pHIxY6JV7nFPbGng6q8hkMMCu7CY/w9UP9iZG6uvQcoSqGt
7rIUUqYWUcf8qcAtvWyLTZmtkCm+LIHiJak4PZXwTrpYOZQScpBTw8ViuVREsJSw
5oHgworZg3rD9oLbiSt+Iy//U14g7gzA7mJVyLUCgYEA6pHoX6gOpH8WYme9NSK3
YwHKIa4DJVx6C2ivn9uD3QPKU8PnhB746CAX+AEd/DKMcH/uEMdoealSAH6qJtQE
/8+THVLxkIbIk1BLLgv0kXHFtvAFmKXoosZa3UQtKNdRaakEQq8hJzdJRVbWICVH
R9nEL4rwseedKd7CXUlyu7UCgYBrjnbzQfAn95QGGxm6zdzIxb9vQIZLaa0HQS6Z
0UZzWGW4/L5Pgikcc8E3K71+OUVVM16BsuPgJH2wJD6Y2AX5nYwvzW/wc+VT623P
C5u5lPZoNyN1P59gj1Jb+RO0ljvd41Gii9RBT/h0ZVyH6AZ+UuHW9GHoPnU1grKB
3phELQKBgQDOWrOLmd/v43r99fxqrkZv9twFkAPlcpYOMn/SDpmJfWR3sGWCz5eI
czQFrr4k36C5HwgornNShezXpbU9bGaG7zAdd3egdqjYeWQeqj/WQFAoP6+jA+yL
hR/bpssdZZaF7Ah0AR/IHGgbNLAfdpGBjyEl1WRoq+tuJ9oMcbKezQ==
""".replacingOccurrences(of: "\n", with: "")

let publicKeyString = """
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk+dWlCTQIr85rtUi56yD
6FT6vuG68Q9xJ4B9bAo4wys+ndlPSX0UQkrPOpnNZcsHOob6DbRI5Cc4qce00nNJ
AlCxYqAJDDDryyQEtUv8ghGGWnjUgBRytm39UM9s/UxyLfGWk3P1Z1us8q5Rvsrc
eC28uG94Lr+w2XmcBwxP020qJIiUqOff8me1vI7vogvec3yO6pLvb1zcqMioKIdQ
/kWjgMvhVyFyg44IqEI1iApjt05CjTQ30W1xyN/9b/cedQzEg8Nq2MQdhKCIZJh2
vjSUuWOBCnx+ttErIYt0roisNj1OhowtSM6k0vV1LPDrCjV7lFPmE1njwTfdV/vl
cQIDAQAB
""".replacingOccurrences(of: "\n", with: "")
