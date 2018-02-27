import Foundation

public struct RSA {
    public var jwtAlgorithmName: String
    let privateKey: Data
    let publicKey: Data

    public init(privateKey: Data, publicKey: Data) {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.jwtAlgorithmName = "rsa"
    }

    public func makeCiphertext(from plaintext: Data) throws -> Data {
        #if os(macOS)
        return try AppleRSA.makeCiphertext(from: plaintext, privateKey: privateKey)
        #else
        fatalError("Only macOS supported.")
        #endif
    }

    public func verifyCiphertext(_ ciphertext: Data, matches plaintext: Data) throws -> Bool {
        #if os(macOS)
        return try AppleRSA.verifyCiphertext(ciphertext, matches: plaintext, publicKey: publicKey)
        #else
        fatalError("Only macOS supported.")
        #endif
    }
}
