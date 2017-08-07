// swift-tools-version:3.0
import PackageDescription

let package = Package(
    name: "Crypto",
    dependencies: [
        // Module for generating random bytes and numbers.
        .Package(url: "https://github.com/vapor/random.git", majorVersion: 1),

        // LibreSSL / OpenSSL module map for Swift.
        .Package(url: "https://github.com/vapor/ctls.git", majorVersion: 1),
    ]
)
