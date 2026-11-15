import Foundation
import CryptoKit

public struct HPKEService {
    public static let ciphersuite = HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly

    public static func generateRandomNonce(length: Int = SideVaultConstants.nonceLength) -> Data {
        let key = SymmetricKey(size: .init(bitCount: length * 8))
        return key.withUnsafeBytes { Data($0) }
    }

    public static func seal(
        plaintext: Data,
        recipientPublicKey: Curve25519.KeyAgreement.PublicKey,
        info: Data = SideVaultConstants.defaultInfo,
        aad: Data,
        nonce: Data? = nil
    ) throws -> SideVaultEnvelope {
        let requestNonce = nonce ?? generateRandomNonce()
        guard requestNonce.count == SideVaultConstants.nonceLength else {
            throw CryptoCoreError.invalidKeyLength(expected: SideVaultConstants.nonceLength, actual: requestNonce.count)
        }

        var sender = try HPKE.Sender(
            recipientKey: recipientPublicKey,
            ciphersuite: ciphersuite,
            info: info
        )

        let ciphertextAndTag = try sender.seal(plaintext, authenticating: aad)
        let enc = sender.encapsulatedKey

        return try SideVaultEnvelope(
            version: SideVaultConstants.protocolVersion,
            algorithm: SideVaultConstants.algorithmID,
            enc: enc,
            nonce: requestNonce,
            ciphertextAndTag: ciphertextAndTag
        )
    }

    public static func open(
        envelope: SideVaultEnvelope,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        info: Data = SideVaultConstants.defaultInfo,
        aad: Data
    ) throws -> Data {
        return try openRaw(
            enc: envelope.enc,
            ciphertextAndTag: envelope.ciphertextAndTag,
            recipientPrivateKey: recipientPrivateKey,
            info: info,
            aad: aad
        )
    }

    public static func openRaw(
        enc: Data,
        ciphertextAndTag: Data,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        info: Data = SideVaultConstants.defaultInfo,
        aad: Data
    ) throws -> Data {
        do {
            var recipient = try HPKE.Recipient(
                privateKey: recipientPrivateKey,
                ciphersuite: ciphersuite,
                info: info,
                encapsulatedKey: enc
            )
            return try recipient.open(ciphertextAndTag, authenticating: aad)
        } catch {
            throw CryptoCoreError.decryptionFailed
        }
    }
}
