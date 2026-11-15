import Foundation

public struct SideVaultEnvelope: Equatable {
    public let version: UInt8
    public let algorithm: UInt8
    public let enc: Data             // 32 bytes ephemeral public key
    public let nonce: Data           // 12 bytes anti-replay nonce
    public let ciphertextAndTag: Data // ciphertext + 16 bytes Poly1305 tag

    public var tag: Data {
        return Data(ciphertextAndTag.suffix(SideVaultConstants.poly1305TagLength))
    }

    public var rawCiphertext: Data {
        return Data(ciphertextAndTag.dropLast(SideVaultConstants.poly1305TagLength))
    }

    public init(
        version: UInt8 = SideVaultConstants.protocolVersion,
        algorithm: UInt8 = SideVaultConstants.algorithmID,
        enc: Data,
        nonce: Data,
        ciphertextAndTag: Data
    ) throws {
        guard enc.count == SideVaultConstants.ephemeralKeyLength else {
            throw CryptoCoreError.invalidKeyLength(expected: SideVaultConstants.ephemeralKeyLength, actual: enc.count)
        }
        guard nonce.count == SideVaultConstants.nonceLength else {
            throw CryptoCoreError.invalidKeyLength(expected: SideVaultConstants.nonceLength, actual: nonce.count)
        }
        guard ciphertextAndTag.count >= SideVaultConstants.poly1305TagLength else {
            throw CryptoCoreError.invalidEnvelope(reason: "Ciphertext must at least include 16-byte Poly1305 tag")
        }
        self.version = version
        self.algorithm = algorithm
        self.enc = Data(enc)
        self.nonce = Data(nonce)
        self.ciphertextAndTag = Data(ciphertextAndTag)
    }

    public func serializeBinary() -> Data {
        var data = Data(capacity: 1 + 1 + enc.count + nonce.count + ciphertextAndTag.count)
        data.append(version)
        data.append(algorithm)
        data.append(enc)
        data.append(nonce)
        data.append(ciphertextAndTag)
        return data
    }

    public static func parseBinary(_ inputData: Data) throws -> SideVaultEnvelope {
        guard inputData.count >= SideVaultConstants.minEnvelopeLength else {
            throw CryptoCoreError.invalidEnvelope(reason: "Binary length \(inputData.count) less than minimum \(SideVaultConstants.minEnvelopeLength)")
        }

        // Copy into contiguous byte array to guarantee 0-indexed safe access
        let bytes = [UInt8](inputData)
        let v = bytes[0]
        let alg = bytes[1]
        guard v == SideVaultConstants.protocolVersion else {
            throw CryptoCoreError.invalidEnvelope(reason: "Unsupported protocol version \(v)")
        }
        guard alg == SideVaultConstants.algorithmID else {
            throw CryptoCoreError.invalidEnvelope(reason: "Unsupported algorithm ID \(alg)")
        }

        let encStart = 2
        let encEnd = encStart + SideVaultConstants.ephemeralKeyLength
        let nonceEnd = encEnd + SideVaultConstants.nonceLength

        guard bytes.count >= nonceEnd + SideVaultConstants.poly1305TagLength else {
            throw CryptoCoreError.invalidEnvelope(reason: "Payload truncated before tag")
        }

        let enc = Data(bytes[encStart..<encEnd])
        let nonce = Data(bytes[encEnd..<nonceEnd])
        let ciphertextAndTag = Data(bytes[nonceEnd..<bytes.count])

        return try SideVaultEnvelope(
            version: v,
            algorithm: alg,
            enc: enc,
            nonce: nonce,
            ciphertextAndTag: ciphertextAndTag
        )
    }

    public func toBase64URL() -> String {
        return SideVaultEnvelope.encodeBase64URL(serializeBinary())
    }

    public static func parseBase64URL(_ base64URL: String) throws -> SideVaultEnvelope {
        guard let data = SideVaultEnvelope.decodeBase64URL(base64URL) else {
            throw CryptoCoreError.invalidBase64("Failed to decode Base64URL string")
        }
        return try parseBinary(data)
    }

    public static func encodeBase64URL(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }

    public static func decodeBase64URL(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let mod = base64.count % 4
        if mod > 0 {
            base64.append(String(repeating: "=", count: 4 - mod))
        }
        return Data(base64Encoded: base64)
    }

    public static func buildAAD(
        method: String,
        path: String,
        timestamp: Int64,
        nonce: Data
    ) -> Data {
        let nonceHex = SideVaultKeys.hexString(from: nonce)
        let aadString = "\(method.uppercased())|\(path)|\(timestamp)|\(nonceHex)"
        return Data(aadString.utf8)
    }

    public static func isTimestampValid(
        timestamp: Int64,
        maxSkew: Double = SideVaultConstants.maxClockSkewSeconds,
        referenceTime: Date = Date()
    ) -> (valid: Bool, delta: Double) {
        let now = referenceTime.timeIntervalSince1970
        let delta = abs(now - Double(timestamp))
        return (delta <= maxSkew, delta)
    }
}
