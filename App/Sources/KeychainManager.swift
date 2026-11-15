import Foundation
import Security
import CryptoKit
import CryptoCore

public final class KeychainManager {
    public static let shared = KeychainManager()
    public static let serviceName = "dev.chuacx.sidevault.keys"
    public static let defaultAlias = "SideVault-Default"

    private init() {}

    public func saveKeyPair(alias: String = defaultAlias, keyPair: SideVaultKeyPair, overwrite: Bool = true) throws {
        let xData = keyPair.x25519Private.rawRepresentation
        let edData = keyPair.ed25519Private.rawRepresentation
        let payload = xData + edData // 64 bytes total: 32B x25519 + 32B ed25519

        if overwrite {
            deleteKeyPair(alias: alias)
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.serviceName,
            kSecAttrAccount as String: alias,
            kSecValueData as String: payload,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw CryptoCoreError.invalidEnvelope(reason: "Keychain save failed with status \(status)")
        }
    }

    public func loadKeyPair(alias: String = defaultAlias) throws -> SideVaultKeyPair {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.serviceName,
            kSecAttrAccount as String: alias,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data, data.count == 64 else {
            throw CryptoCoreError.invalidEnvelope(reason: "KeyPair not found or corrupted for alias \(alias) (status \(status))")
        }

        let xRaw = data.subdata(in: 0..<32)
        let edRaw = data.subdata(in: 32..<64)
        return try SideVaultKeyPair(x25519Raw: xRaw, ed25519Raw: edRaw)
    }

    public func deleteKeyPair(alias: String = defaultAlias) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: KeychainManager.serviceName,
            kSecAttrAccount as String: alias,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        SecItemDelete(query as CFDictionary)
    }

    public func exportEncryptedBackup(alias: String = defaultAlias, passphrase: String) throws -> String {
        let keyPair = try loadKeyPair(alias: alias)
        let salt = HPKEService.generateRandomNonce(length: 16)
        let derivedKey = deriveKey(passphrase: passphrase, salt: salt)

        let plainDict: [String: String] = [
            "alias": alias,
            "x25519": keyPair.x25519Private.rawRepresentation.base64EncodedString(),
            "ed25519": keyPair.ed25519Private.rawRepresentation.base64EncodedString()
        ]
        let plainData = try JSONSerialization.data(withJSONObject: plainDict)

        let symmetricKey = SymmetricKey(data: derivedKey)
        let sealedBox = try ChaChaPoly.seal(plainData, using: symmetricKey)

        let backupDict: [String: Any] = [
            "version": 1,
            "alias": alias,
            "salt": salt.base64EncodedString(),
            "nonce": Data(sealedBox.nonce).base64EncodedString(),
            "ciphertext": sealedBox.ciphertext.base64EncodedString(),
            "tag": sealedBox.tag.base64EncodedString()
        ]

        let backupData = try JSONSerialization.data(withJSONObject: backupDict, options: [.prettyPrinted, .sortedKeys])
        return String(decoding: backupData, as: UTF8.self)
    }

    public func restoreEncryptedBackup(backupJSON: String, passphrase: String) throws -> SideVaultKeyPair {
        guard let data = backupJSON.data(using: .utf8),
              let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let alias = dict["alias"] as? String,
              let saltB64 = dict["salt"] as? String,
              let salt = Data(base64Encoded: saltB64),
              let nonceB64 = dict["nonce"] as? String,
              let nonceData = Data(base64Encoded: nonceB64),
              let ctB64 = dict["ciphertext"] as? String,
              let ciphertext = Data(base64Encoded: ctB64),
              let tagB64 = dict["tag"] as? String,
              let tag = Data(base64Encoded: tagB64)
        else {
            throw CryptoCoreError.invalidEnvelope(reason: "Invalid backup JSON structure")
        }

        let derivedKey = deriveKey(passphrase: passphrase, salt: salt)
        let symmetricKey = SymmetricKey(data: derivedKey)
        let chachaNonce = try ChaChaPoly.Nonce(data: nonceData)
        let sealedBox = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ciphertext, tag: tag)

        let plainData = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        guard let plainDict = try JSONSerialization.jsonObject(with: plainData) as? [String: String],
              let xB64 = plainDict["x25519"], let xRaw = Data(base64Encoded: xB64),
              let edB64 = plainDict["ed25519"], let edRaw = Data(base64Encoded: edB64)
        else {
            throw CryptoCoreError.invalidEnvelope(reason: "Corrupted decrypted backup data")
        }

        let keyPair = try SideVaultKeyPair(x25519Raw: xRaw, ed25519Raw: edRaw)
        try saveKeyPair(alias: alias, keyPair: keyPair, overwrite: true)
        return keyPair
    }

    private func deriveKey(passphrase: String, salt: Data) -> Data {
        let inputKey = SymmetricKey(data: Data(passphrase.utf8))
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: salt,
            info: Data("SideVault-Backup-v1".utf8),
            outputByteCount: 32
        )
        return derived.withUnsafeBytes { Data($0) }
    }
}
