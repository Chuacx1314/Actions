import Foundation
import CryptoKit

public struct SideVaultChunkedService {
    public static let magic: UInt32 = 0x53564348 // "SVCH"
    public static let defaultChunkSize = SideVaultConstants.defaultChunkSize

    public static func sealChunked(
        plaintext: Data,
        recipientPublicKey: Curve25519.KeyAgreement.PublicKey,
        info: Data = SideVaultConstants.defaultInfo,
        baseAAD: Data,
        chunkSize: Int = defaultChunkSize,
        nonce: Data? = nil
    ) throws -> Data {
        let requestNonce = nonce ?? HPKEService.generateRandomNonce()
        guard requestNonce.count == SideVaultConstants.nonceLength else {
            throw CryptoCoreError.invalidKeyLength(expected: SideVaultConstants.nonceLength, actual: requestNonce.count)
        }

        var sender = try HPKE.Sender(
            recipientKey: recipientPublicKey,
            ciphersuite: HPKEService.ciphersuite,
            info: info
        )
        let enc = sender.encapsulatedKey

        // Split into chunks (if empty data, create 1 empty chunk to verify authentication)
        var chunks: [Data] = []
        if plaintext.isEmpty {
            chunks.append(Data())
        } else {
            var offset = 0
            while offset < plaintext.count {
                let end = min(offset + chunkSize, plaintext.count)
                chunks.append(plaintext.subdata(in: offset..<end))
                offset = end
            }
        }

        var stream = Data()
        var magicBE = magic.bigEndian
        stream.append(Data(bytes: &magicBE, count: 4))
        var version: UInt8 = SideVaultConstants.protocolVersion
        stream.append(Data(bytes: &version, count: 1))
        stream.append(enc)
        stream.append(requestNonce)
        var chunkCountBE = UInt32(chunks.count).bigEndian
        stream.append(Data(bytes: &chunkCountBE, count: 4))

        for (index, chunk) in chunks.enumerated() {
            let isLast = (index == chunks.count - 1)
            let chunkAAD = buildChunkAAD(baseAAD: baseAAD, index: index, isLast: isLast)
            let sealedChunk = try sender.seal(chunk, authenticating: chunkAAD)

            var chunkLenBE = UInt32(sealedChunk.count).bigEndian
            stream.append(Data(bytes: &chunkLenBE, count: 4))
            stream.append(sealedChunk)
        }

        return stream
    }

    public static func openChunked(
        stream: Data,
        recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        info: Data = SideVaultConstants.defaultInfo,
        baseAAD: Data
    ) throws -> Data {
        guard stream.count >= 4 + 1 + SideVaultConstants.ephemeralKeyLength + SideVaultConstants.nonceLength + 4 else {
            throw CryptoCoreError.invalidEnvelope(reason: "Chunked stream too short")
        }

        let bytes = [UInt8](stream)
        var offset = 0

        var magicVal: UInt32 = 0
        withUnsafeMutableBytes(of: &magicVal) { ptr in
            for i in 0..<4 { ptr[i] = bytes[offset + i] }
        }
        let streamMagic = UInt32(bigEndian: magicVal)
        offset += 4
        guard streamMagic == magic else {
            throw CryptoCoreError.invalidEnvelope(reason: "Invalid magic in chunked stream")
        }

        let version = bytes[offset]
        offset += 1
        guard version == SideVaultConstants.protocolVersion else {
            throw CryptoCoreError.invalidEnvelope(reason: "Unsupported chunked version \(version)")
        }

        let enc = Data(bytes[offset..<offset+SideVaultConstants.ephemeralKeyLength])
        offset += SideVaultConstants.ephemeralKeyLength

        let nonce = Data(bytes[offset..<offset+SideVaultConstants.nonceLength])
        offset += SideVaultConstants.nonceLength

        var countVal: UInt32 = 0
        withUnsafeMutableBytes(of: &countVal) { ptr in
            for i in 0..<4 { ptr[i] = bytes[offset + i] }
        }
        let chunkCount = Int(UInt32(bigEndian: countVal))
        offset += 4

        let minChunkOverhead = 4 + SideVaultConstants.poly1305TagLength // 20 bytes: 4B length + 16B tag
        let remainingBytes = bytes.count - offset
        let maxPossibleChunks = remainingBytes / minChunkOverhead

        guard chunkCount > 0 else {
            throw CryptoCoreError.invalidEnvelope(reason: "Chunk count must be positive")
        }
        guard chunkCount <= maxPossibleChunks else {
            throw CryptoCoreError.invalidEnvelope(reason: "Chunk count \(chunkCount) exceeds stream capacity \(maxPossibleChunks)")
        }

        var recipient = try HPKE.Recipient(
            privateKey: recipientPrivateKey,
            ciphersuite: HPKEService.ciphersuite,
            info: info,
            encapsulatedKey: enc
        )

        var result = Data()
        for index in 0..<chunkCount {
            guard offset + 4 <= bytes.count else {
                throw CryptoCoreError.chunkCorrupted(index: index)
            }
            var lenVal: UInt32 = 0
            withUnsafeMutableBytes(of: &lenVal) { ptr in
                for i in 0..<4 { ptr[i] = bytes[offset + i] }
            }
            let chunkLen = Int(UInt32(bigEndian: lenVal))
            offset += 4

            guard offset + chunkLen <= bytes.count else {
                throw CryptoCoreError.chunkCorrupted(index: index)
            }
            let chunkData = Data(bytes[offset..<offset+chunkLen])
            offset += chunkLen

            let isLast = (index == chunkCount - 1)
            let chunkAAD = buildChunkAAD(baseAAD: baseAAD, index: index, isLast: isLast)

            do {
                let decrypted = try recipient.open(chunkData, authenticating: chunkAAD)
                result.append(decrypted)
            } catch {
                throw CryptoCoreError.chunkCorrupted(index: index)
            }
        }

        guard offset == bytes.count else {
            throw CryptoCoreError.invalidEnvelope(reason: "Trailing bytes after last chunk")
        }

        return result
    }

    public static func buildChunkAAD(baseAAD: Data, index: Int, isLast: Bool) -> Data {
        var aadString = String(decoding: baseAAD, as: UTF8.self)
        aadString += "|chk:\(index)|\(isLast ? "last" : "more")"
        return Data(aadString.utf8)
    }
}
