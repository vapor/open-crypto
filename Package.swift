import PackageDescription

let package = Package(
    name: "Crypto",
    targets: [
        Target(name: "Essentials"),
        Target(name: "BCrypt", dependencies: ["Random"]),
        Target(name: "Hash", dependencies: ["Essentials", "Random"]),
        Target(name: "Random", dependencies: ["Essentials"]),
        Target(name: "HMAC", dependencies: ["Essentials", "Random"]),
        Target(name: "Cipher", dependencies: ["Essentials"]),
    ],
    dependencies: [
        .Package(url: "https://github.com/vapor/core.git", majorVersion: 1),
        .Package(url: "https://github.com/vapor/clibressl.git", majorVersion: 1)
    ]
)
