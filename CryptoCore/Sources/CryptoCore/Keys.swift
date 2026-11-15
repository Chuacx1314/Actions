import Foundation
import CryptoKit

public struct SideVaultKeys {
    public static func computeFingerprint(rawKey: Data) -> String {
        let digest = SHA256.hash(data: rawKey)
        let prefix = Array(digest.prefix(8))
        return prefix.map { String(format: "%02X", $0) }.joined()
    }

    public static func hexString(from data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }

    public static func data(fromHexString hex: String) -> Data? {
        var data = Data()
        var temp = ""
        for char in hex {
            temp.append(char)
            if temp.count == 2 {
                guard let byte = UInt8(temp, radix: 16) else { return nil }
                data.append(byte)
                temp = ""
            }
        }
        return temp.isEmpty ? data : nil
    }
}

public struct SideVaultKeyPair {
    public let x25519Private: Curve25519.KeyAgreement.PrivateKey
    public let ed25519Private: Curve25519.Signing.PrivateKey

    public var x25519Public: Curve25519.KeyAgreement.PublicKey {
        return x25519Private.publicKey
    }

    public var ed25519Public: Curve25519.Signing.PublicKey {
        return ed25519Private.publicKey
    }

    public var x25519PublicKeyBase64: String {
        return x25519Public.rawRepresentation.base64EncodedString()
    }

    public var ed25519PublicKeyBase64: String {
        return ed25519Public.rawRepresentation.base64EncodedString()
    }

    public var x25519Fingerprint: String {
        return SideVaultKeys.computeFingerprint(rawKey: x25519Public.rawRepresentation)
    }

    public var ed25519Fingerprint: String {
        return SideVaultKeys.computeFingerprint(rawKey: ed25519Public.rawRepresentation)
    }

    public init(
        x25519Private: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey(),
        ed25519Private: Curve25519.Signing.PrivateKey = Curve25519.Signing.PrivateKey()
    ) {
        self.x25519Private = x25519Private
        self.ed25519Private = ed25519Private
    }

    public init(x25519Raw: Data, ed25519Raw: Data) throws {
        guard x25519Raw.count == 32 else {
            throw CryptoCoreError.invalidKeyLength(expected: 32, actual: x25519Raw.count)
        }
        guard ed25519Raw.count == 32 else {
            throw CryptoCoreError.invalidKeyLength(expected: 32, actual: ed25519Raw.count)
        }
        self.x25519Private = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: x25519Raw)
        self.ed25519Private = try Curve25519.Signing.PrivateKey(rawRepresentation: ed25519Raw)
    }
}

public struct SideVaultPublicKeys: Codable, Equatable {
    public let x25519PublicKeyBase64: String
    public let ed25519PublicKeyBase64: String
    public let x25519Fingerprint: String
    public let ed25519Fingerprint: String

    public init(x25519PublicKeyBase64: String, ed25519PublicKeyBase64: String) throws {
        guard let xData = Data(base64Encoded: x25519PublicKeyBase64), xData.count == 32 else {
            throw CryptoCoreError.invalidKeyLength(expected: 32, actual: Data(base64Encoded: x25519PublicKeyBase64)?.count ?? 0)
        }
        guard let edData = Data(base64Encoded: ed25519PublicKeyBase64), edData.count == 32 else {
            throw CryptoCoreError.invalidKeyLength(expected: 32, actual: Data(base64Encoded: ed25519PublicKeyBase64)?.count ?? 0)
        }
        self.x25519PublicKeyBase64 = x25519PublicKeyBase64
        self.ed25519PublicKeyBase64 = ed25519PublicKeyBase64
        self.x25519Fingerprint = SideVaultKeys.computeFingerprint(rawKey: xData)
        self.ed25519Fingerprint = SideVaultKeys.computeFingerprint(rawKey: edData)
    }

    public init(keyPair: SideVaultKeyPair) {
        self.x25519PublicKeyBase64 = keyPair.x25519PublicKeyBase64
        self.ed25519PublicKeyBase64 = keyPair.ed25519PublicKeyBase64
        self.x25519Fingerprint = keyPair.x25519Fingerprint
        self.ed25519Fingerprint = keyPair.ed25519Fingerprint
    }

    public func toJSONString() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(self)
        guard let string = String(data: data, encoding: .utf8) else {
            throw CryptoCoreError.invalidEnvelope(reason: "UTF8 conversion failed")
        }
        return string
    }

    public static func fromJSONString(_ json: String) throws -> SideVaultPublicKeys {
        guard let data = json.data(using: .utf8) else {
            throw CryptoCoreError.invalidEnvelope(reason: "Invalid JSON UTF8")
        }
        return try JSONDecoder().decode(SideVaultPublicKeys.self, from: data)
    }
}
