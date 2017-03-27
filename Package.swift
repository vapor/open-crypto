import PackageDescription

let package = Package(
    name: "Crypto",
    dependencies: [
        // Module for generating random bytes and numbers.
        .Package(url: "https://github.com/vapor/random.git", Version(1,0,0, prereleaseIdentifiers: ["beta"])),

        // LibreSSL / OpenSSL module map for Swift.
        .Package(url: "https://github.com/vapor/ctls.git", Version(1,0,0, prereleaseIdentifiers: ["beta"]))
    ]
)
