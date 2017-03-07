import PackageDescription

let package = Package(
    name: "Crypto",
    dependencies: [
        // Module for generating random bytes and numbers.
        .Package(url: "https://github.com/vapor/random.git", majorVersion: 0),

        // LibreSSL wrapped in a Swift package.
        .Package(url: "https://github.com/tanner0101/ctls.git", majorVersion: 0)
    ]
)
