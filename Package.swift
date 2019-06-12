// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "open-crypto",
    products: [
        .library(name: "OpenCrypto", targets: ["OpenCrypto"]),
    ],
    dependencies: [],
    targets: [
        .systemLibrary(
            name: "COpenCrypto",
            pkgConfig: "openssl",
            providers: [
                .apt(["openssl libssl-dev"]),
                .brew(["openssl@1.1"])
            ]
        ),
        .target(name: "OpenCrypto", dependencies: ["COpenCrypto"]),
        .testTarget(name: "OpenCryptoTests", dependencies: ["OpenCrypto"]),
    ]
)
