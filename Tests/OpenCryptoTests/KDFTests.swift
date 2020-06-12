//
//  KDFTests.swift
//
//
//  Created by Craz1k0ek on 12/06/2020.
//

import XCTest
import OpenCrypto

class KDFTests: XCTestCase {
    // Tests ran from https://tools.ietf.org/html/rfc5869#appendix-A
    
    func testBasicSHA256() throws {
        let ikm = Data(base64Encoded: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==")!
        let salt = Data(base64Encoded: "AAECAwQFBgcICQoLDA==")!
        let info = Data(base64Encoded: "8PHy8/T19vf4+Q==")!
        let outputCount = 42
        let expectedOkm = SymmetricKey(data: Data(base64Encoded: "PLJfJfqs1XqQQ09k0DYvKi0tCpDPGlpMXbAtVuzExb80AHII1biHGFhl")!)
        
        let okm = KDF.hkdf(using: SHA256(), secret: ikm, salt: salt, sharedInfo: info, outputByteCount: outputCount)
        print(expectedOkm)
        print(okm)
        XCTAssertEqual(okm, expectedOkm)
    }
    
    func testLongerSHA256() throws {
        let ikm = Data(base64Encoded: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk8=")!
        let salt = Data(base64Encoded: "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq8=")!
        let info = Data(base64Encoded: "sLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8=")!
        let outputCount = 82
        let expectedOkm = SymmetricKey(data: Data(base64Encoded: "sR45jcgDJ6HI5/eMWWpJNE8BLtotTvrYoFDMTBmvqXxZBFqZyseCcnHLQcZeWQ4J2jJ1YAwvCbg2d5OprKPbccwwxYF57D6HwUwB1cHzQ08dhw==")!)
        
        let okm = KDF.hkdf(using: SHA256(), secret: ikm, salt: salt, sharedInfo: info, outputByteCount: outputCount)
        print(expectedOkm)
        print(okm)
        XCTAssertEqual(okm, expectedOkm)
    }
    
    func testZeroSaltInfoSHA256() throws {
        let ikm = Data(base64Encoded: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==")!
        let outputCount = 42
        
        let expectedOkm = SymmetricKey(data: Data(base64Encoded: "jaTndaVjwY9xX4AqBjxaMbihH1xe4Yeew0VOXzxzjS2dIBOV+qS2GpbI")!)
        
        let okm = KDF.hkdf(using: SHA256(), secret: ikm, outputByteCount: outputCount)
        print(expectedOkm)
        print(okm)
        XCTAssertEqual(okm, expectedOkm)
    }
    
    func testBasicSHA1() throws {
        let ikm = Data(base64Encoded: "CwsLCwsLCwsLCws=")!
        let salt = Data(base64Encoded: "AAECAwQFBgcICQoLDA==")!
        let info = Data(base64Encoded: "8PHy8/T19vf4+Q==")!
        let outputCount = 42
        let expectedOkm = SymmetricKey(data: Data(base64Encoded: "CFoB6hsQ82kzBotW76WtgaTxS4IvWwkVaKnN1PFV/aLCLkIkeNMF8/iW")!)
        
        let okm = KDF.hkdf(using: Insecure.SHA1(), secret: ikm, salt: salt, sharedInfo: info, outputByteCount: outputCount)
        print(expectedOkm)
        print(okm)
        XCTAssertEqual(okm, expectedOkm)
    }
    
    func testLongerSHA1() throws {
        let ikm = Data(base64Encoded: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0BBQkNERUZHSElKS0xNTk8=")!
        let salt = Data(base64Encoded: "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn+AgYKDhIWGh4iJiouMjY6PkJGSk5SVlpeYmZqbnJ2en6ChoqOkpaanqKmqq6ytrq8=")!
        let info = Data(base64Encoded: "sLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8=")!
        let outputCount = 82
        let expectedOkm = SymmetricKey(data: Data(base64Encoded: "C9dwp00RYPfJ8SzVkSoG6/9q3K6JnZIZH+QwVnO6L/6Po/Gk5a158/M0s7ICshc8SG6jfOPTl+0DTH+d/rFcXpJzNtBEH0xDAOLP8NCQC1LTtA==")!)
        
        let okm = KDF.hkdf(using: Insecure.SHA1(), secret: ikm, salt: salt, sharedInfo: info, outputByteCount: outputCount)
        print(expectedOkm)
        print(okm)
        XCTAssertEqual(okm, expectedOkm)
    }
    
    func testZeroSaltInfoSHA1() throws {
        let ikm = Data(base64Encoded: "CwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==")!
        let outputCount = 42
        let expectedOkm = SymmetricKey(data: Data(base64Encoded: "CsGvcAKz12HR5VKY2p0FBrmuUgVyIKMG4Htrh+jfIdDqAAM94DmE00kY")!)
        
        let okm = KDF.hkdf(using: Insecure.SHA1(), secret: ikm, outputByteCount: outputCount)
        print(expectedOkm)
        print(okm)
        XCTAssertEqual(okm, expectedOkm)
    }
}
