import SwiftUI
import UIKit
import CryptoCore

public struct SettingsView: View {
    @State private var x25519Fingerprint: String = "未生成"
    @State private var ed25519Fingerprint: String = "未生成"
    @State private var publicKeysJSON: String = ""
    @State private var passphrase: String = ""
    @State private var backupText: String = ""
    @State private var alertTitle: String = ""
    @State private var alertMessage: String = ""
    @State private var showAlert: Bool = false
    @State private var showShareSheet: Bool = false
    @State private var shareContent: String = ""

    public init() {}

    public var body: some View {
        NavigationStack {
            Form {
                Section(header: Text("本地密钥状态")) {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("X25519 加密公钥指纹")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(x25519Fingerprint)
                            .font(.system(.body, design: .monospaced))
                    }
                    .padding(.vertical, 2)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Ed25519 签名公钥指纹")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text(ed25519Fingerprint)
                            .font(.system(.body, design: .monospaced))
                    }
                    .padding(.vertical, 2)

                    Button(action: generateNewKeys) {
                        Label("生成 / 覆盖密钥对", systemImage: "key.fill")
                    }

                    if !publicKeysJSON.isEmpty {
                        Button(action: {
                            shareContent = publicKeysJSON
                            showShareSheet = true
                        }) {
                            Label("分享 / 导出公钥 JSON", systemImage: "square.and.arrow.up")
                        }
                    }
                }

                Section(
                    header: Text("防换号丢失：加密密钥备份"),
                    footer: Text("免费证书通过 SideStore 换 Apple ID 重签后，Keychain 访问组会变更导致读不到旧私钥。请务必设置口令并导出加密备份。")
                ) {
                    SecureField("备份加密口令", text: $passphrase)

                    Button(action: exportBackup) {
                        Label("导出加密备份", systemImage: "lock.doc.fill")
                    }
                    .disabled(passphrase.isEmpty)

                    Button(action: restoreBackup) {
                        Label("从备份文本恢复", systemImage: "arrow.counterclockwise.doc.fill")
                    }
                    .disabled(passphrase.isEmpty)

                    if !backupText.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("备份数据预览:")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            Text(backupText)
                                .font(.system(.caption2, design: .monospaced))
                                .lineLimit(3)
                            Button("复制备份数据") {
                                UIPasteboard.general.string = backupText
                                triggerAlert(title: "已复制", message: "加密备份内容已复制到剪贴板。")
                            }
                            .font(.footnote)
                        }
                    }
                }

                Section(header: Text("协议与安全说明")) {
                    LabeledContent("加密套件", value: "RFC 9180 HPKE")
                    LabeledContent("算法", value: "X25519 + ChaCha20Poly")
                    LabeledContent("签名算法", value: "Ed25519 (RFC 8032)")
                    LabeledContent("Shortcuts 动作", value: "6 个原生 AppIntents")
                }
            }
            .navigationTitle("SideVault")
            .onAppear(perform: loadCurrentKeys)
            .alert(alertTitle, isPresented: $showAlert) {
                Button("确定", role: .cancel) {}
            } message: {
                Text(alertMessage)
            }
            .sheet(isPresented: $showShareSheet) {
                ShareActivityView(activityItems: [shareContent])
            }
        }
    }

    private func loadCurrentKeys() {
        if let keyPair = try? KeychainManager.shared.loadKeyPair() {
            x25519Fingerprint = keyPair.x25519Fingerprint
            ed25519Fingerprint = keyPair.ed25519Fingerprint
            publicKeysJSON = (try? SideVaultPublicKeys(keyPair: keyPair).toJSONString()) ?? ""
        } else {
            x25519Fingerprint = "未生成"
            ed25519Fingerprint = "未生成"
            publicKeysJSON = ""
        }
    }

    private func generateNewKeys() {
        do {
            let keyPair = SideVaultKeyPair()
            try KeychainManager.shared.saveKeyPair(keyPair: keyPair, overwrite: true)
            loadCurrentKeys()
            triggerAlert(title: "成功", message: "新密钥对已生成并存入安全 Keychain。")
        } catch {
            triggerAlert(title: "失败", message: error.localizedDescription)
        }
    }

    private func exportBackup() {
        do {
            let backup = try KeychainManager.shared.exportEncryptedBackup(passphrase: passphrase)
            backupText = backup
            shareContent = backup
            showShareSheet = true
        } catch {
            triggerAlert(title: "备份失败", message: error.localizedDescription)
        }
    }

    private func restoreBackup() {
        let pasteboard = UIPasteboard.general.string ?? ""
        let targetText = backupText.isEmpty ? pasteboard : backupText
        guard !targetText.isEmpty else {
            triggerAlert(title: "恢复失败", message: "未找到备份数据，请先将备份文本复制到剪贴板。")
            return
        }

        do {
            _ = try KeychainManager.shared.restoreEncryptedBackup(backupJSON: targetText, passphrase: passphrase)
            loadCurrentKeys()
            triggerAlert(title: "恢复成功", message: "密钥已成功从加密备份导入系统 Keychain。")
        } catch {
            triggerAlert(title: "恢复失败", message: error.localizedDescription)
        }
    }

    private func triggerAlert(title: String, message: String) {
        alertTitle = title
        alertMessage = message
        showAlert = true
    }
}

public struct ShareActivityView: UIViewControllerRepresentable {
    public let activityItems: [Any]

    public func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    public func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
