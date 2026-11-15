// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CryptoCore",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(
            name: "CryptoCore",
            targets: ["CryptoCore"]
        )
    ],
    dependencies: [],
    targets: [
        .target(
            name: "CryptoCore",
            dependencies: []
        ),
        .testTarget(
            name: "CryptoCoreTests",
            dependencies: ["CryptoCore"]
        )
    ]
)
