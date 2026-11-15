# SideVault

一个只做**非对称 / 混合加密**的最小 iOS app，用 6 个原生 Shortcuts 动作，给局域网 HTTP 通道加一层应用层加密。

- 和原作者那个 [Actions](https://apps.apple.com/app/actions/id1473495100) app **共存、不冲突**：名字不同、bundle id 不同（`dev.chuacx.sidevault`），Shortcuts 里各显示各的动作。对称加密、JWT、URL 抓取这些动作继续用原作者那个 app，本项目不重复实现。
- 加密原语是 **RFC 9180 HPKE**（X25519 + HKDF-SHA256 + ChaCha20Poly1305）+ **Ed25519 签名**，全部走 CryptoKit / Node 标准库，没有任何自研拼装。
- 没有 HTTP 服务端。它只负责「封包 / 拆包」，实际的 HTTP 收发由 Shortcuts 的「获取 URL 内容」和你在 PC / NAS 上跑的服务端负责。

协议细节见 [docs/PROTOCOL.md](PROTOCOL.md)，装机步骤见 [INSTALL.md](INSTALL.md)。

---

## 当前状态

- CI 在 `macos-26`（Xcode 26.6）上两连绿，最近一次 run `43730058892`，2 分 15 秒。
- 每次运行依次验证：`swift test`（含 RFC 9180 附录 A.2 官方向量、往返、防篡改、分块边界与 fuzz 用例）→ Node 端 `npm ci && npm test`（同一套向量互通）→ xcodegen 生成工程 → 断言 `17.0` / `Swift 5.0` / bundle id → 编无签名 `.app` → 打 IPA 并验 `platform IOS` + `MinimumOSVersion=17.0`。
- 产物为 `SideVault-unsigned-ipa` artifact（约 132 KB，`Payload/SideVault.app` 里只有主二进制 + `Info.plist` + `Metadata.appintents/`，没有 appex、没有多余资源）。
- **还没在真机上装过**。CI 只证明它能编译、测试能过、包结构正确；能不能在你的 iOS 版本上装上并出现在 Shortcuts 里，以真机为准。

---

## 6 个动作

动作在 Shortcuts 里都带 `SideVault:` 前缀。默认密钥别名是 `SideVault-Default`。

| 动作 | 输入 | 输出 |
| :--- | :--- | :--- |
| `SideVault: 生成密钥对` | 密钥别名、是否覆盖 | 多行文本，含两把公钥的 16 位指纹 |
| `SideVault: 导出公钥` | 密钥别名 | JSON：`x25519PublicKeyBase64`、`ed25519PublicKeyBase64`、`x25519Fingerprint`、`ed25519Fingerprint` |
| `SideVault: 混合加密` | 待加密文本、对端 X25519 公钥（Base64）、请求路径、HTTP 方法、可选「签名密钥别名」 | JSON：`{"envelope","timestamp"}`，填了签名别名再加 `sig`、`signer_fp` |
| `SideVault: 混合解密` | 报文（JSON 或裸 Base64URL）、本地私钥别名、请求路径、HTTP 方法、可选「发送方 Ed25519 公钥」、可选时间戳 | 明文文本 |
| `SideVault: 签名消息` | 待签名消息、私钥别名 | Base64 的 64 字节 Ed25519 签名 |
| `SideVault: 验证签名` | 原始消息、签名（Base64）、发送方公钥（Base64） | 字符串 `VALID` 或 `INVALID` |

三个容易踩的点：

1. **路径和 HTTP 方法参与 AAD**：加密时填的 `请求路径` / `HTTP 方法`，解密时必须填成一样，否则解密必然失败（这是设计，不是 bug）。
2. **混合解密对时间戳的处理**：贴 JSON 报文时它自己从 `timestamp` 字段取值；只有你贴裸 Base64URL 时才需要手填时间戳，填 0 表示跳过时间窗校验——但那样 AAD 里的时间戳就是 0，除非加密端也是 0，否则解不开。
3. **加密动作目前只收文本**，不收文件。文件要么先转 Base64 再当文本传（受 Shortcuts 变量大小限制），要么在 PC 端用同一个 `CryptoCore` / `hpke-js` 走 64KB 分块 API。这是当前实现与最初设想（文本或文件都行）之间唯一的落差。

---

## 配对流程（手机 ⇄ PC）

首次配对是手工的，两个方向各一次。**指纹要对一遍**，这是唯一防中间人公钥替换的手段。

**第 1 步：手机 → PC（让 PC 知道加密给谁）**

1. 手机上打开 SideVault app 或跑一次 `导出公钥`。
2. 把整个 JSON 交给 PC 端，PC 只关心 `x25519PublicKeyBase64`（32 字节公钥的 Base64）和 `ed25519PublicKeyBase64`（用于验手机签名）。
3. 对一下指纹：app 设置页和 JSON 里的 `x25519Fingerprint` / `ed25519Fingerprint` 必须一致，且应该和 PC 端自己算的 `SHA256(公钥)[0..<8]` 大写十六进制一致。

**第 2 步：PC → 手机（让手机知道加密给谁）**

1. PC 端生成自己的 X25519 密钥对（Node：`hpke-js` 的 `suite.generateKeyPair()`；Python：`pyhpke` 的 `CipherSuite.new(...)`）。
2. 把 PC 的 X25519 **公钥原始 32 字节** 做 Base64 交给手机，粘进 `混合加密` 动作的「对端 X25519 公钥」参数。注意是 raw 32 字节，不是 PEM、不是 DER。
3. PC 的 Ed25519 公钥也一起给手机，粘进 `混合解密` 的「发送方 Ed25519 公钥」，这样 PC 回包时手机能验签（不填就跳过验签）。

**加密链路**：Shortcuts 里 `混合加密` → 拿到 JSON → 用「获取 URL 内容」POST 给 PC（body 就是这个 JSON）→ PC 验 timestamp/nonce/签名后解密。

**回包链路**：PC 用手机的 X25519 公钥加密、自己的 Ed25519 私钥签名 → 手机把 JSON 丢给 `混合解密`。

> 收包侧的防重放（±300s 时间窗、nonce 去重）由 PC 服务端实现，`CryptoCore` 只提供了 `isTimestampValid` 这个工具函数。协议规则见 [PROTOCOL.md](PROTOCOL.md) 第 4 节。

---

## 本地开发

Windows 上你能跑的部分：

```powershell
cd tools/interop
npm ci
npm test          # 6 组用例：官方向量、Base64URL 封包、端到端、防篡改、Ed25519、±300s 窗口
```

需要 macOS（或 CI）的部分：

```bash
cd CryptoCore
swift test --parallel        # 需要 macOS 14+ / 支持 HPKE 的 Swift 工具链

cd ..
xcodegen generate --spec App/project.yml --project App
xcodebuild -project App/SideVault.xcodeproj -scheme SideVault -configuration Release \
  -destination 'generic/platform=iOS' -derivedDataPath build/dd \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" build
```

注意：

- **不要提交 `App/SideVault.xcodeproj`**，它在 `.gitignore` 里，由 `App/project.yml` 生成。改了工程配置就改 `project.yml`，别去手改 pbxproj。
- 改了 `project.yml` 的 `name` / scheme / bundle id / deployment target，CI 的三道断言会在 generate 之后立刻失败，这是故意的。

---

## CI 怎么跑

`.github/workflows/ios.yml`，触发条件：push 到 `main`、PR、手动 `workflow_dispatch`。

- job `build`：工具链自检 → （有 `CryptoCore/Package.swift` 时）`swift test` → （有 `tools/interop/package.json` 时）`npm ci && npm test` → （有 `App/project.yml` 时）装 xcodegen、生成工程、断言设置、编无签名 `.app`、打 IPA、验 `platform IOS` / `MinimumOSVersion` / bundle id → 上传 artifact。
- job `testflight`：默认不跑，见下一节。

下载装机包：Actions → 最近一次成功的 run → Artifacts → `SideVault-unsigned-ipa` → 解压得到 `SideVault-unsigned.ipa`。仓库里的 `dist/` 是本地打包产物目录，**不入库**。

---

## 切到 TestFlight 路线（需要 $99/年）

免费签名的 IPA 不能直接装，得靠 SideStore 重签（7 天一次）。有付费开发者账号就走这条，装一次管 90 天。

需要先在 App Store Connect 建好 app 记录（bundle id 必须是 `dev.chuacx.sidevault`），然后：

| 类型 | 名称 | 内容 |
| :--- | :--- | :--- |
| secret | `ASC_KEY_P8` | `AuthKey_XXXXXXXXXX.p8` 的 **base64**（`base64 -w0 AuthKey_xxx.p8`） |
| secret | `ASC_KEY_ID` | API key 的 Key ID |
| secret | `ASC_ISSUER_ID` | Issuer ID |
| secret | `APPLE_TEAM_ID` | 10 位 Team ID，会被 `sed` 渲染进 `fastlane/ExportOptions.plist` 的 `__TEAM_ID__` |
| variable | `ENABLE_TESTFLIGHT` | 设为 `true` 才会启用这个 job |

然后在 Actions 里手动 `workflow_dispatch` 跑一次：它用 API key 自动签名 archive → 按 `fastlane/ExportOptions.plist`（`method=app-store-connect`）导出 IPA → `fastlane pilot` 上传 TestFlight。iOS 里装 TestFlight app 收包即可，内部测试员不需要送审。

`project.yml` 里是 `CODE_SIGN_STYLE: Manual`（为了无签名构建），TestFlight job 在命令行上覆盖成 `Automatic` 并传 `DEVELOPMENT_TEAM`——这条路径只在付费账号下有效，免费路线别开。

---

## 已知限制与待办

- 装到真机这一步还没做，Shortcuts 里能不能出现这 6 个动作，以真机为准（CI 里的 `Metadata.appintents/extract.actionsdata` 存在，说明编译期元数据提取正常）。
- `混合加密` 只收文本，不收文件（见上文）。
- 免费签名 7 天续签一次；换 Apple ID 重签会读不到旧私钥，所以 app 里必须先用「导出加密备份」留后路。
- `openChunked` 对 `chunkCount == 0` 的流会返回空明文（未经 AEAD 认证），且不检查末块之后的尾随字节。两条都是服务端侧的防御，等有真实服务端时再收紧。
