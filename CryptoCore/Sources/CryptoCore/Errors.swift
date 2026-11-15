import Foundation

public enum CryptoCoreError: Error, LocalizedError, Equatable {
    case invalidKeyLength(expected: Int, actual: Int)
    case invalidEnvelope(reason: String)
    case timestampExpired(deltaSeconds: Double, maxAllowed: Double)
    case replayDetected(nonce: String)
    case invalidSignature
    case decryptionFailed
    case chunkCorrupted(index: Int)
    case invalidBase64(String)
    case keyDerivationFailed

    public var errorDescription: String? {
        switch self {
        case .invalidKeyLength(let expected, let actual):
            return "Invalid key length: expected \(expected) bytes, got \(actual) bytes"
        case .invalidEnvelope(let reason):
            return "Invalid envelope: \(reason)"
        case .timestampExpired(let delta, let maxAllowed):
            return "Timestamp outside acceptable window: delta \(delta)s exceeds \(maxAllowed)s"
        case .replayDetected(let nonce):
            return "Replay attack detected: nonce \(nonce) has already been processed"
        case .invalidSignature:
            return "Ed25519 signature verification failed"
        case .decryptionFailed:
            return "HPKE decryption failed: ciphertext corrupted, tag mismatch, or wrong key/AAD"
        case .chunkCorrupted(let index):
            return "Chunk corrupted at index \(index)"
        case .invalidBase64(let details):
            return "Invalid base64 encoding: \(details)"
        case .keyDerivationFailed:
            return "Key derivation failed"
        }
    }
}
