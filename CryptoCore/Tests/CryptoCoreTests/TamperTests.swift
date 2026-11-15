import XCTest
import CryptoKit
@testable import CryptoCore

final class TamperTests: XCTestCase {
    func testTamperedCiphertextMustFail() throws {
        let recipientKeys = SideVaultKeyPair()
        let plaintext = "Sensitive Financial Data".data(using: .utf8)!
        let nonce = HPKEService.generateRandomNonce()
        let aad = SideVaultEnvelope.buildAAD(method: "POST", path: "/pay", timestamp: 1000, nonce: nonce)

        let envelope = try HPKEService.seal(
            plaintext: plaintext,
            recipientPublicKey: recipientKeys.x25519Public,
            aad: aad,
            nonce: nonce
        )

        // 1. Flip a bit in ciphertext
        var tamperedCT = envelope.ciphertextAndTag
        tamperedCT[0] ^= 0xFF
        let tamperedEnvelope = try SideVaultEnvelope(
            version: envelope.version,
            algorithm: envelope.algorithm,
            enc: envelope.enc,
            nonce: envelope.nonce,
            ciphertextAndTag: tamperedCT
        )

        XCTAssertThrowsError(try HPKEService.open(
            envelope: tamperedEnvelope,
            recipientPrivateKey: recipientKeys.x25519Private,
            aad: aad
        )) { error in
            XCTAssertEqual(error as? CryptoCoreError, CryptoCoreError.decryptionFailed)
        }
    }

    func testTamperedAADMustFail() throws {
        let recipientKeys = SideVaultKeyPair()
        let plaintext = "Important Command".data(using: .utf8)!
        let nonce = HPKEService.generateRandomNonce()
        let aad = SideVaultEnvelope.buildAAD(method: "POST", path: "/delete", timestamp: 1000, nonce: nonce)

        let envelope = try HPKEService.seal(
            plaintext: plaintext,
            recipientPublicKey: recipientKeys.x25519Public,
            aad: aad,
            nonce: nonce
        )

        // Changed path in AAD
        let tamperedAAD = SideVaultEnvelope.buildAAD(method: "POST", path: "/create", timestamp: 1000, nonce: nonce)

        XCTAssertThrowsError(try HPKEService.open(
            envelope: envelope,
            recipientPrivateKey: recipientKeys.x25519Private,
            aad: tamperedAAD
        )) { error in
            XCTAssertEqual(error as? CryptoCoreError, CryptoCoreError.decryptionFailed)
        }
    }

    func testTamperedSignatureMustFail() throws {
        let keyPair = SideVaultKeyPair()
        let message = "Original Instruction"
        let signature = try SigningService.sign(text: message, privateKey: keyPair.ed25519Private)

        // Verify with tampered message
        let tamperedMsgResult = SigningService.verify(
            base64Signature: signature,
            text: "Altered Instruction",
            base64PublicKey: keyPair.ed25519PublicKeyBase64
        )
        XCTAssertFalse(tamperedMsgResult)

        // Verify with wrong key
        let anotherKeyPair = SideVaultKeyPair()
        let wrongKeyResult = SigningService.verify(
            base64Signature: signature,
            text: message,
            base64PublicKey: anotherKeyPair.ed25519PublicKeyBase64
        )
        XCTAssertFalse(wrongKeyResult)
    }

    func testTamperedEnvelopeHeaderFails() throws {
        let recipientKeys = SideVaultKeyPair()
        let plaintext = "Test".data(using: .utf8)!
        let aad = Data("aad".utf8)
        let envelope = try HPKEService.seal(plaintext: plaintext, recipientPublicKey: recipientKeys.x25519Public, aad: aad)

        var binary = envelope.serializeBinary()
        // Tamper version byte to 99
        binary[0] = 99
        XCTAssertThrowsError(try SideVaultEnvelope.parseBinary(binary))
    }
}
