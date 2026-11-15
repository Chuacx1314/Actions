import XCTest
import CryptoKit
@testable import CryptoCore

final class RFC9180VectorTests: XCTestCase {
    // RFC 9180 Appendix A.2: Mode 0, KEM 0x0020 (X25519), KDF 0x0001 (HKDF-SHA256), AEAD 0x0003 (ChaCha20Poly1305)
    func testOfficialRFC9180Vectors() throws {
        guard let info = SideVaultKeys.data(fromHexString: "4f6465206f6e2061204772656369616e2055726e"),
              let pkRm = SideVaultKeys.data(fromHexString: "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"),
              let skRm = SideVaultKeys.data(fromHexString: "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb"),
              let enc = SideVaultKeys.data(fromHexString: "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"),
              let expectedPt = SideVaultKeys.data(fromHexString: "4265617574792069732074727574682c20747275746820626561757479"),
              // Sequence 0
              let aad0 = SideVaultKeys.data(fromHexString: "436f756e742d30"),
              let ct0 = SideVaultKeys.data(fromHexString: "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"),
              // Sequence 1
              let aad1 = SideVaultKeys.data(fromHexString: "436f756e742d31"),
              let ct1 = SideVaultKeys.data(fromHexString: "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"),
              // Sequence 2
              let aad2 = SideVaultKeys.data(fromHexString: "436f756e742d32"),
              let ct2 = SideVaultKeys.data(fromHexString: "71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b")
        else {
            XCTFail("Failed to parse RFC 9180 hex vectors")
            return
        }

        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: skRm)
        XCTAssertEqual(privateKey.publicKey.rawRepresentation, pkRm)

        // 1. Single-shot open for sequence 0
        let decrypted0 = try HPKEService.openRaw(
            enc: enc,
            ciphertextAndTag: ct0,
            recipientPrivateKey: privateKey,
            info: info,
            aad: aad0
        )
        XCTAssertEqual(decrypted0, expectedPt)

        // 2. Sequential multi-message open on one context (Seq 0 -> 1 -> 2)
        var recipient = try HPKE.Recipient(
            privateKey: privateKey,
            ciphersuite: HPKEService.ciphersuite,
            info: info,
            encapsulatedKey: enc
        )

        let openSeq0 = try recipient.open(ct0, authenticating: aad0)
        XCTAssertEqual(openSeq0, expectedPt)

        let openSeq1 = try recipient.open(ct1, authenticating: aad1)
        XCTAssertEqual(openSeq1, expectedPt)

        let openSeq2 = try recipient.open(ct2, authenticating: aad2)
        XCTAssertEqual(openSeq2, expectedPt)
    }
}
