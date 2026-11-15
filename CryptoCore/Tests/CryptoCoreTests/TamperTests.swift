import XCTest
import CryptoKit
@testable import CryptoCore

final class TamperTests: XCTestCase {
    func testTamperedCiphertextMustFail() throws {
        let recipientKeys = SideVaultKeyPair()
        let plaintext = "Sensitive Financial Data".data(using: .utf8) ?? Data()
        let nonce = HPKEService.generateRandomNonce()
        let aad = SideVaultEnvelope.buildAAD(method: "POST", path: "/pay", timestamp: 1000, nonce: nonce)

        let envelope = try HPKEService.seal(
            plaintext: plaintext,
            recipientPublicKey: recipientKeys.x25519Public,
            aad: aad,
            nonce: nonce
        )

        // 1. Flip a bit safely using contiguous byte array
        var ctBytes = [UInt8](envelope.ciphertextAndTag)
        guard !ctBytes.isEmpty else {
            XCTFail("Ciphertext should not be empty")
            return
        }
        ctBytes[0] ^= 0xFF
        let tamperedCT = Data(ctBytes)

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
        let plaintext = "Important Command".data(using: .utf8) ?? Data()
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
        let plaintext = "Test".data(using: .utf8) ?? Data()
        let aad = Data("aad".utf8)
        let envelope = try HPKEService.seal(plaintext: plaintext, recipientPublicKey: recipientKeys.x25519Public, aad: aad)

        var binaryBytes = [UInt8](envelope.serializeBinary())
        guard !binaryBytes.isEmpty else {
            XCTFail("Binary should not be empty")
            return
        }
        // Tamper version byte to 99
        binaryBytes[0] = 99
        let binary = Data(binaryBytes)
        XCTAssertThrowsError(try SideVaultEnvelope.parseBinary(binary))
    }

    func testFuzzAndBoundaryInputsMustThrowWithoutCrash() throws {
        // 1. Empty string
        XCTAssertThrowsError(try SideVaultEnvelope.parseBase64URL(""))

        // 2. Corrupted base64 characters
        XCTAssertThrowsError(try SideVaultEnvelope.parseBase64URL("???%%%$$$@@@"))

        // 3. Short binary inputs (below minEnvelopeLength 62)
        for length in [0, 1, 10, 31, 45, 61] {
            let shortData = Data(repeating: 0x01, count: length)
            XCTAssertThrowsError(try SideVaultEnvelope.parseBinary(shortData))

            let shortB64 = SideVaultEnvelope.encodeBase64URL(shortData)
            XCTAssertThrowsError(try SideVaultEnvelope.parseBase64URL(shortB64))
        }

        // 4. Large invalid payload (10KB)
        let largeData = Data(repeating: 0xFF, count: 10_000)
        XCTAssertThrowsError(try SideVaultEnvelope.parseBinary(largeData))
    }
}
