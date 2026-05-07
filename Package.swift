// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "swift-netstack",
    platforms: [
        .macOS(.v15)
    ],
    targets: [
        .target(
            name: "SwiftNetStack",
            path: "Sources/SwiftNetStack"
        ),
        .executableTarget(
            name: "SwiftNetStackDemo",
            dependencies: ["SwiftNetStack"],
            path: "Sources/SwiftNetStackDemo",
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
