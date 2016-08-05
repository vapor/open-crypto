import XCTest
@testable import CryptoTestSuite

XCTMain([
     testCase(MD5Tests.allTests),
     testCase(SHA1Tests.allTests),
])
