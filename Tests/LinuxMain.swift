import XCTest
@testable import CryptoTests
@testable import RandomTests

XCTMain([
    /// Crypto
    testCase(BCryptTests.allTests),
    testCase(CipherTests.allTests),
    testCase(MD5Tests.allTests),
    testCase(RSATests.allTests),
    testCase(SHA1Tests.allTests),
    testCase(SHA2Tests.allTests),
    testCase(OTPTests.allTests),

    /// Random
    testCase(RandomTests.allTests),
])
