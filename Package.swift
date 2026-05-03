// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-netstack",
    platforms: [
        .macOS(.v15)
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-system.git", from: "1.6.1"),
        .package(url: "https://github.com/apple/swift-atomics.git", from: "1.2.0"),
        .package(url: "https://github.com/apple/swift-collections.git", from: "1.1.0"),
    ],
    targets: [
        .target(
            name: "SwiftNetStack",
            dependencies: [
                .product(name: "SystemPackage", package: "swift-system"),
                .product(name: "Atomics", package: "swift-atomics"),
                .product(name: "Collections", package: "swift-collections"),
            ],
            path: "Sources/SwiftNetStack",
            exclude: ["main.swift"],
            linkerSettings: [
                .linkedFramework("Virtualization")
            ]
        ),
        .executableTarget(
            name: "netstack",
            dependencies: ["SwiftNetStack"],
            path: "Sources/netstack"
        ),
        .executableTarget(
            name: "vz-debug",
            dependencies: [
                "SwiftNetStack",
                .product(name: "SystemPackage", package: "swift-system"),
            ],
            path: "Sources/vz-debug",
            swiftSettings: [
                .interoperabilityMode(.Cxx)
            ]
        ),
        .executableTarget(
            name: "e2e-runner",
            dependencies: ["SwiftNetStack"],
            path: "Sources/e2e-runner",
            linkerSettings: [
                .linkedFramework("Virtualization")
            ]
        ),
        .testTarget(
            name: "SwiftNetStackTests",
            dependencies: ["SwiftNetStack"],
            path: "Tests/SwiftNetStackTests"
        ),
    ]
)
