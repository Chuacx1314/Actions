import XCTest
import CryptoKit
@testable import CryptoCore

final class RoundTripTests: XCTestCase {
    func testSingleMessageSealAndOpen() throws {
        let recipientKeys = SideVaultKeyPair()
        let plaintext = "Hello SideVault from iOS Shortcuts!".data(using: .utf8)!
        let aad = SideVaultEnvelope.buildAAD(
            method: "POST",
            path: "/api/v1/action",
            timestamp: 1731682800,
            nonce: HPKEService.generateRandomNonce()
        )

        // Seal
        let envelope = try HPKEService.seal(
            plaintext: plaintext,
            recipientPublicKey: recipientKeys.x25519Public,
            aad: aad
        )

        // Wire round-trip: Base64URL
        let base64URL = envelope.toBase64URL()
        let parsedEnvelope = try SideVaultEnvelope.parseBase64URL(base64URL)
        XCTAssertEqual(envelope, parsedEnvelope)

        // Binary serialization round-trip
        let binaryData = envelope.serializeBinary()
        let binaryParsed = try SideVaultEnvelope.parseBinary(binaryData)
        XCTAssertEqual(envelope, binaryParsed)

        // Open
        let decrypted = try HPKEService.open(
            envelope: parsedEnvelope,
            recipientPrivateKey: recipientKeys.x25519Private,
            aad: aad
        )

        XCTAssertEqual(decrypted, plaintext)
    }

    func testEd25519SigningRoundTrip() throws {
        let keyPair = SideVaultKeyPair()
        let message = "Payload integrity test"

        let signature = try SigningService.sign(text: message, privateKey: keyPair.ed25519Private)
        let isValid = SigningService.verify(
            base64Signature: signature,
            text: message,
            base64PublicKey: keyPair.ed25519PublicKeyBase64
        )
        XCTAssertTrue(isValid)

        // Fingerprint check
        XCTAssertEqual(keyPair.ed25519Fingerprint.count, 16)
        XCTAssertEqual(keyPair.x25519Fingerprint.count, 16)
    }

    func testPublicKeysJSONCodable() throws {
        let keyPair = SideVaultKeyPair()
        let publicKeys = SideVaultPublicKeys(keyPair: keyPair)

        let jsonString = try publicKeys.toJSONString()
        let restored = try SideVaultPublicKeys.fromJSONString(jsonString)

        XCTAssertEqual(publicKeys, restored)
        XCTAssertEqual(restored.x25519PublicKeyBase64, keyPair.x25519PublicKeyBase64)
        XCTAssertEqual(restored.ed25519PublicKeyBase64, keyPair.ed25519PublicKeyBase64)
    }
}
