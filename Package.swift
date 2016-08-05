import PackageDescription

let package = Package(
    name: "Crypto",
    dependencies: [
        .Package(url: "https://github.com/vapor/core.git", majorVersion: 0, minor: 3)
    ]
)
