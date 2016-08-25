import PackageDescription

let package = Package(
    name: "Crypto",
    targets: [
        Target(name: "Essentials"),
        Target(name: "BCrypt", dependencies: ["Random"]),
        Target(name: "MD5", dependencies: ["Essentials", "HMAC"]),
        Target(name: "Random", dependencies: ["Essentials"]),
        Target(name: "SHA1", dependencies: ["Essentials", "HMAC"]),
        Target(name: "SHA2", dependencies: ["Essentials", "HMAC"]),
        Target(name: "HMAC", dependencies: ["Essentials"]),
    ],
    dependencies: [
        .Package(url: "https://github.com/vapor/core.git", majorVersion: 0, minor: 4),
        .Package(url: "https://github.com/vapor/clibressl.git", majorVersion: 0, minor: 1)
    ]
)
