import XCTest
@testable import CryptoTests

XCTMain([
    testCase(MD5Tests.allTests),
    testCase(SHA1Tests.allTests),
    testCase(SHA2Tests.allTests),
    testCase(RSATests.allTests),
])
