import PackageDescription

let package = Package(
    name: "Crypto",
    targets: [
        Target(name: "Essentials"),
        Target(name: "MD5", dependencies: ["Essentials"]),
        Target(name: "Random", dependencies: ["Essentials"]),
        Target(name: "HMAC", dependencies: ["Essentials"]),
        Target(name: "PBKDF2", dependencies: ["HMAC", "MD5", "SHA1"]),
        Target(name: "SHA1", dependencies: ["Essentials", "HMAC"]),
        Target(name: "BCrypt", dependencies: ["Random"]),
    ],
    dependencies: [
        .Package(url: "https://github.com/vapor/core.git", majorVersion: 0, minor: 4),
        .Package(url: "https://github.com/vapor/ctls.git", majorVersion: 0, minor: 1)
    ]
)
