import XCTest
import CryptoKit
@testable import CryptoCore

final class ChunkBoundaryTests: XCTestCase {
    let baseAAD = Data("stream-auth-data".utf8)

    func testZeroBytesBoundary() throws {
        let recipientKeys = SideVaultKeyPair()
        let emptyData = Data()

        let stream = try SideVaultChunkedService.sealChunked(
            plaintext: emptyData,
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )

        let decrypted = try SideVaultChunkedService.openChunked(
            stream: stream,
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        )

        XCTAssertEqual(decrypted.count, 0)
    }

    func testOneByteBoundary() throws {
        let recipientKeys = SideVaultKeyPair()
        let oneByteData = Data([0x42])

        let stream = try SideVaultChunkedService.sealChunked(
            plaintext: oneByteData,
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )

        let decrypted = try SideVaultChunkedService.openChunked(
            stream: stream,
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        )

        XCTAssertEqual(decrypted, oneByteData)
    }

    func testExact64KBBoundary() throws {
        let recipientKeys = SideVaultKeyPair()
        let size = SideVaultChunkedService.defaultChunkSize // 65536
        var buffer = [UInt8](repeating: 0, count: size)
        for i in 0..<size {
            buffer[i] = UInt8(i % 251)
        }
        let data64KB = Data(buffer)

        let stream = try SideVaultChunkedService.sealChunked(
            plaintext: data64KB,
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )

        let decrypted = try SideVaultChunkedService.openChunked(
            stream: stream,
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        )

        XCTAssertEqual(decrypted.count, size)
        XCTAssertEqual(decrypted, data64KB)
    }

    func test64KBPlusOneByteBoundary() throws {
        let recipientKeys = SideVaultKeyPair()
        let size = SideVaultChunkedService.defaultChunkSize + 1 // 65537
        var buffer = [UInt8](repeating: 0, count: size)
        for i in 0..<size {
            buffer[i] = UInt8(i % 241)
        }
        let data64KBPlus1 = Data(buffer)

        let stream = try SideVaultChunkedService.sealChunked(
            plaintext: data64KBPlus1,
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )

        let decrypted = try SideVaultChunkedService.openChunked(
            stream: stream,
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        )

        XCTAssertEqual(decrypted.count, size)
        XCTAssertEqual(decrypted, data64KBPlus1)
    }

    func testChunkTamperingMustFail() throws {
        let recipientKeys = SideVaultKeyPair()
        let size = SideVaultChunkedService.defaultChunkSize + 100
        let data = Data(repeating: 0xAA, count: size)

        var stream = try SideVaultChunkedService.sealChunked(
            plaintext: data,
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )

        // Corrupt the last byte of stream
        let lastIdx = stream.count - 1
        stream[lastIdx] ^= 0x55

        XCTAssertThrowsError(try SideVaultChunkedService.openChunked(
            stream: stream,
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        ))
    }
}
