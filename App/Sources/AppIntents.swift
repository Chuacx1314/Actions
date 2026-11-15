import AppIntents
import Foundation
import CryptoKit
import CryptoCore

// MARK: - 1. Generate Key Pair Intent
public struct GenerateKeyPairIntent: AppIntent {
    public static var title: LocalizedStringResource = "SideVault: 生成密钥对"
    public static var description = IntentDescription("生成 X25519 与 Ed25519 密钥对并安全存储在系统 Keychain 中。")
    public static var openAppWhenRun: Bool = false

    @Parameter(title: "密钥别名", default: "SideVault-Default")
    public var alias: String

    @Parameter(title: "覆盖已存在密钥", default: false)
    public var overwrite: Bool

    public init() {}

    public func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let keyPair = SideVaultKeyPair()
        try KeychainManager.shared.saveKeyPair(alias: alias, keyPair: keyPair, overwrite: overwrite)

        let result = """
        密钥对 [\(alias)] 创建成功！
        X25519 指纹: \(keyPair.x25519Fingerprint)
        Ed25519 指纹: \(keyPair.ed25519Fingerprint)
        """
        return .result(value: result)
    }
}

// MARK: - 2. Export Public Key Intent
public struct ExportPublicKeyIntent: AppIntent {
    public static var title: LocalizedStringResource = "SideVault: 导出公钥"
    public static var description = IntentDescription("导出指定别名的公钥信息（JSON 格式，包含 X25519、Ed25519 公钥及指纹）。")
    public static var openAppWhenRun: Bool = false

    @Parameter(title: "密钥别名", default: "SideVault-Default")
    public var alias: String

    public init() {}

    public func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let keyPair = try KeychainManager.shared.loadKeyPair(alias: alias)
        let publicKeys = SideVaultPublicKeys(keyPair: keyPair)
        let jsonString = try publicKeys.toJSONString()
        return .result(value: jsonString)
    }
}

// MARK: - 3. Hybrid Encrypt Intent
public struct HybridEncryptIntent: AppIntent {
    public static var title: LocalizedStringResource = "SideVault: 混合加密"
    public static var description = IntentDescription("使用对端 X25519 公钥进行 HPKE 混合加密。")
    public static var openAppWhenRun: Bool = false

    @Parameter(title: "待加密文本", default: "")
    public var textContent: String

    @Parameter(title: "对端 X25519 公钥 (Base64)")
    public var recipientPublicKeyBase64: String

    @Parameter(title: "请求路径 (绑定 AAD)", default: "/api/v1/action")
    public var requestPath: String

    @Parameter(title: "HTTP 方法", default: "POST")
    public var httpMethod: String

    @Parameter(title: "签名密钥别名 (可选)", default: "")
    public var signerAlias: String

    public init() {}

    public func perform() async throws -> some IntentResult & ReturnsValue<String> {
        guard let pkData = Data(base64Encoded: recipientPublicKeyBase64), pkData.count == 32 else {
            throw CryptoCoreError.invalidKeyLength(expected: 32, actual: Data(base64Encoded: recipientPublicKeyBase64)?.count ?? 0)
        }
        let recipientPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pkData)
        let plainData = Data(textContent.utf8)

        let nonce = HPKEService.generateRandomNonce()
        let timestamp = Int64(Date().timeIntervalSince1970)
        let aad = SideVaultEnvelope.buildAAD(
            method: httpMethod,
            path: requestPath,
            timestamp: timestamp,
            nonce: nonce
        )

        let envelope = try HPKEService.seal(
            plaintext: plainData,
            recipientPublicKey: recipientPublicKey,
            aad: aad,
            nonce: nonce
        )
        let envelopeB64URL = envelope.toBase64URL()

        var resultDict: [String: Any] = [
            "envelope": envelopeB64URL,
            "timestamp": timestamp
        ]

        if !signerAlias.isEmpty {
            let signerKeys = try KeychainManager.shared.loadKeyPair(alias: signerAlias)
            let signature = try SigningService.sign(text: envelopeB64URL, privateKey: signerKeys.ed25519Private)
            resultDict["sig"] = signature
            resultDict["signer_fp"] = signerKeys.ed25519Fingerprint
        }

        let jsonData = try JSONSerialization.data(withJSONObject: resultDict, options: [.prettyPrinted, .sortedKeys])
        return .result(value: String(decoding: jsonData, as: UTF8.self))
    }
}

// MARK: - 4. Hybrid Decrypt Intent
public struct HybridDecryptIntent: AppIntent {
    public static var title: LocalizedStringResource = "SideVault: 混合解密"
    public static var description = IntentDescription("解密接收到的 HPKE 密文报文，可校验时间戳与发送方签名。")
    public static var openAppWhenRun: Bool = false

    @Parameter(title: "加密报文 (Base64URL 或 JSON)")
    public var payload: String

    @Parameter(title: "本地私钥别名", default: "SideVault-Default")
    public var keyAlias: String

    @Parameter(title: "请求路径", default: "/api/v1/action")
    public var requestPath: String

    @Parameter(title: "HTTP 方法", default: "POST")
    public var httpMethod: String

    @Parameter(title: "发送方 Ed25519 公钥 (可选验签)", default: "")
    public var senderPublicKeyBase64: String

    // App Intents 的 @Parameter 只支持 Int 这一种整数类型(Value: _IntentValue),
    // Int64 会直接编译失败,所以这里用 Int,内部再转 Int64。
    @Parameter(title: "报文时间戳 (若 payload 是纯 Base64URL 则填此项，0 表示不校验)", default: 0)
    public var timestamp: Int

    public init() {}

    public func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let keyPair = try KeychainManager.shared.loadKeyPair(alias: keyAlias)
        var envelopeB64URL = payload.trimmingCharacters(in: .whitespacesAndNewlines)
        var effectiveTimestamp: Int64 = Int64(timestamp)

        // Parse JSON if passed as a wrapped envelope
        if envelopeB64URL.hasPrefix("{"),
           let data = envelopeB64URL.data(using: .utf8),
           let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            if let env = dict["envelope"] as? String {
                envelopeB64URL = env
            }
            if let tsNum = dict["timestamp"] as? NSNumber {
                effectiveTimestamp = tsNum.int64Value
            } else if let ts = dict["timestamp"] as? Int64 {
                effectiveTimestamp = ts
            } else if let ts = dict["timestamp"] as? Int {
                effectiveTimestamp = Int64(ts)
            }
            if let sig = dict["sig"] as? String, !senderPublicKeyBase64.isEmpty {
                let valid = SigningService.verify(
                    base64Signature: sig,
                    text: envelopeB64URL,
                    base64PublicKey: senderPublicKeyBase64
                )
                guard valid else {
                    throw CryptoCoreError.invalidSignature
                }
            }
        }

        let envelope = try SideVaultEnvelope.parseBase64URL(envelopeB64URL)

        if effectiveTimestamp > 0 {
            let (valid, delta) = SideVaultEnvelope.isTimestampValid(timestamp: effectiveTimestamp)
            guard valid else {
                throw CryptoCoreError.timestampExpired(deltaSeconds: delta, maxAllowed: SideVaultConstants.maxClockSkewSeconds)
            }
        }

        let aad = SideVaultEnvelope.buildAAD(
            method: httpMethod,
            path: requestPath,
            timestamp: effectiveTimestamp,
            nonce: envelope.nonce
        )

        let decrypted = try HPKEService.open(
            envelope: envelope,
            recipientPrivateKey: keyPair.x25519Private,
            aad: aad
        )

        guard let plaintext = String(data: decrypted, encoding: .utf8) else {
            throw CryptoCoreError.invalidEnvelope(reason: "Decrypted payload is not valid UTF-8 string")
        }

        return .result(value: plaintext)
    }
}

// MARK: - 5. Sign Message Intent
public struct SignMessageIntent: AppIntent {
    public static var title: LocalizedStringResource = "SideVault: 签名消息"
    public static var description = IntentDescription("使用本地 Ed25519 私钥对文本进行签名。")
    public static var openAppWhenRun: Bool = false

    @Parameter(title: "待签名消息")
    public var message: String

    @Parameter(title: "私钥别名", default: "SideVault-Default")
    public var keyAlias: String

    public init() {}

    public func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let keyPair = try KeychainManager.shared.loadKeyPair(alias: keyAlias)
        let signature = try SigningService.sign(text: message, privateKey: keyPair.ed25519Private)
        return .result(value: signature)
    }
}

// MARK: - 6. Verify Signature Intent
public struct VerifySignatureIntent: AppIntent {
    public static var title: LocalizedStringResource = "SideVault: 验证签名"
    public static var description = IntentDescription("使用 Ed25519 公钥验证文本签名。")
    public static var openAppWhenRun: Bool = false

    @Parameter(title: "原始消息")
    public var message: String

    @Parameter(title: "签名 (Base64)")
    public var signatureBase64: String

    @Parameter(title: "发送方公钥 (Base64)")
    public var publicKeyBase64: String

    public init() {}

    public func perform() async throws -> some IntentResult & ReturnsValue<String> {
        let isValid = SigningService.verify(
            base64Signature: signatureBase64,
            text: message,
            base64PublicKey: publicKeyBase64
        )
        return .result(value: isValid ? "VALID" : "INVALID")
    }
}
