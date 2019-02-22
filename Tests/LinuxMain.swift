import XCTest
import CryptoKitTests

XCTMain([
    testCase(BCryptTests.allTests),
    testCase(CipherTests.allTests),
    testCase(MD5Tests.allTests),
    testCase(RSATests.allTests),
    testCase(SHA1Tests.allTests),
    testCase(SHA2Tests.allTests),
    testCase(RSATests.allTests),
    testCase(OTPTests.allTests),
    testCase(RandomTests.allTests),
    testCase(PBKDF2Tests.allTests),
])
