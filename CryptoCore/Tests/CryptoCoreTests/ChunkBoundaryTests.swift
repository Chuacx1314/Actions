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

        // Corrupt the last byte of stream safely
        var streamBytes = [UInt8](stream)
        guard !streamBytes.isEmpty else {
            XCTFail("Stream should not be empty")
            return
        }
        streamBytes[streamBytes.count - 1] ^= 0x55
        let tamperedStream = Data(streamBytes)

        XCTAssertThrowsError(try SideVaultChunkedService.openChunked(
            stream: tamperedStream,
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        ))
    }

    func testZeroChunkCountStreamMustThrow() throws {
        let recipientKeys = SideVaultKeyPair()
        let stream = try SideVaultChunkedService.sealChunked(
            plaintext: Data("sample".utf8),
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )

        var bytes = [UInt8](stream)
        // chunkCount is at offset: magic(4) + version(1) + enc(32) + nonce(12) = 49
        let countOffset = 49
        bytes[countOffset] = 0
        bytes[countOffset + 1] = 0
        bytes[countOffset + 2] = 0
        bytes[countOffset + 3] = 0

        XCTAssertThrowsError(try SideVaultChunkedService.openChunked(
            stream: Data(bytes),
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        )) { error in
            guard case CryptoCoreError.invalidEnvelope(let reason) = (error as? CryptoCoreError) ?? CryptoCoreError.keyDerivationFailed else {
                XCTFail("Expected invalidEnvelope error")
                return
            }
            XCTAssertTrue(reason.contains("positive"))
        }
    }

    func testTrailingGarbageBytesMustThrow() throws {
        let recipientKeys = SideVaultKeyPair()
        var stream = try SideVaultChunkedService.sealChunked(
            plaintext: Data("sample".utf8),
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )
        stream.append(Data([0xDE, 0xAD, 0xBE, 0xEF]))

        XCTAssertThrowsError(try SideVaultChunkedService.openChunked(
            stream: stream,
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        )) { error in
            guard case CryptoCoreError.invalidEnvelope(let reason) = (error as? CryptoCoreError) ?? CryptoCoreError.keyDerivationFailed else {
                XCTFail("Expected invalidEnvelope error")
                return
            }
            XCTAssertTrue(reason.contains("Trailing bytes"))
        }
    }

    func testHugeChunkCountMustThrowImmediately() throws {
        let recipientKeys = SideVaultKeyPair()
        let stream = try SideVaultChunkedService.sealChunked(
            plaintext: Data("sample".utf8),
            recipientPublicKey: recipientKeys.x25519Public,
            baseAAD: baseAAD
        )

        var bytes = [UInt8](stream)
        let countOffset = 49
        // Set chunkCount to 0x7FFFFFFF (over 2 billion chunks)
        bytes[countOffset] = 0x7F
        bytes[countOffset + 1] = 0xFF
        bytes[countOffset + 2] = 0xFF
        bytes[countOffset + 3] = 0xFF

        let start = Date()
        XCTAssertThrowsError(try SideVaultChunkedService.openChunked(
            stream: Data(bytes),
            recipientPrivateKey: recipientKeys.x25519Private,
            baseAAD: baseAAD
        )) { error in
            guard case CryptoCoreError.invalidEnvelope(let reason) = (error as? CryptoCoreError) ?? CryptoCoreError.keyDerivationFailed else {
                XCTFail("Expected invalidEnvelope error")
                return
            }
            XCTAssertTrue(reason.contains("exceeds stream capacity"))
        }
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 0.5, "Rejection must happen immediately without looping")
    }
}
