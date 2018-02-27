import XCTest
import Bits
import Crypto

class RSATests: XCTestCase {
    func testBasic() throws {
        let privateKey = try Base64Decoder(encoding: .base64).decode(string: privateKeyString)
        let publicKey = try Base64Decoder(encoding: .base64).decode(string: publicKeyString)
        let plaintext = Data("vapor".utf8)
        let rsa = RSA(privateKey: privateKey, publicKey: publicKey)
        let sig = try rsa.makeCiphertext(from: plaintext)
        let matches = try rsa.verifyCiphertext(sig, matches: plaintext)
        XCTAssertEqual(matches, true)
    }


    static var allTests = [
        ("testBasic", testBasic),
    ]
}

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
