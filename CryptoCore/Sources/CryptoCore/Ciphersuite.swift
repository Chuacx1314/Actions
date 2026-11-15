import Foundation
import CryptoKit

public struct SideVaultConstants {
    public static let protocolVersion: UInt8 = 1
    public static let algorithmID: UInt8 = 1 // DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20Poly1305
    public static let ephemeralKeyLength = 32
    public static let nonceLength = 12
    public static let poly1305TagLength = 16
    public static let minEnvelopeLength = 1 + 1 + ephemeralKeyLength + nonceLength + poly1305TagLength // 62 bytes
    public static let defaultChunkSize = 64 * 1024 // 64 KB
    public static let maxClockSkewSeconds: Double = 300.0
    public static let defaultInfo = Data("SideVault-v1".utf8)
}
