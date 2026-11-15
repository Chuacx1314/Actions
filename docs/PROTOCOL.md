# SideVault 安全通信协议规范 (v1)

本协议定义了基于 **RFC 9180 (HPKE)** 与 **RFC 8032 (Ed25519)** 的轻量级应用层非对称/混合加密通信标准，专为局域网不可信 HTTP 信道设计，兼顾 iOS 原生 Shortcuts (AppIntents) 与 PC/NAS 服务端的互通性与防重放安全。

---

## 1. 密码学套件 (Cryptographic Ciphersuite)

SideVault 采用标准公开密码学原语，严格杜绝私有拼装：

* **模式 (Mode)**: HPKE Base Mode (`0x00`) —— 发送方单向向接收方公钥加密
* **KEM (密钥封装)**: `0x0020` (`DHKEM(X25519, HKDF-SHA256)`)
* **KDF (密钥派生)**: `0x0001` (`HKDF-SHA256`)
* **AEAD (对称加密与认证)**: `0x0003` (`ChaCha20Poly1305`)
* **签名算法 (Signature)**: Ed25519 (64 字节纯签名)
* **默认协议上下文 (Info)**: `SideVault-v1`

### 1.1 密钥角色定义
* **X25519 密钥对**: 专用于 HPKE 协商会话对称密钥。
* **Ed25519 密钥对**: 专用于外层报文身份认证与数字签名，防止中间人公钥替换。
* **公钥指纹 (Fingerprint)**: `SHA256(RawPublicKeyBytes)[0..<8]`，编码为 16 位大写十六进制字符串（例如：`806673C56B7BD285`）。

---

## 2. 报文封包格式 (Envelope Wire Format)

单条报文采用紧凑二进制封包，传输时统一以 **Base64URL** (RFC 4648 §5，无填充 `=` 字符) 呈现：

### 2.1 紧凑二进制布局
```
+--------+--------+------------------------+------------------+------------------------------+
| v (1B) | alg(1B)|      enc (32B)         |    nonce (12B)   |   ciphertext + tag (N + 16B) |
+--------+--------+------------------------+------------------+------------------------------+
```

| 字段 | 字节长度 | 说明 |
| :--- | :--- | :--- |
| `v` | 1 字节 | 协议版本号，当前固定为 `0x01` |
| `alg` | 1 字节 | 密码套件标识，当前固定为 `0x01` (`X25519_HKDFSHA256_ChaCha20Poly1305`) |
| `enc` | 32 字节 | 发送方 HPKE 临时公钥 (Ephemeral Public Key) |
| `nonce` | 12 字节 | 客户端本次请求生成的随机防重放 Nonce |
| `ciphertext` | 变长 (N) | 对称密文明文加密后的结果 |
| `tag` | 16 字节 | ChaCha20Poly1305 产生的 Poly1305 消息认证标签 (紧随密文末尾) |

> 最小合法封包长度为：`1 + 1 + 32 + 12 + 16 = 62` 字节（对应明文 0 字节）。

### 2.2 外层 JSON 包装 (含签名时)
当发起调用需要携带数字签名进行客户端身份 Pinning 时，在 HTTP 请求体中使用如下包装：

```json
{
  "envelope": "<Base64URL(v1_binary_packet)>",
  "timestamp": 1731682800,
  "sig": "<Base64(64-Byte Ed25519 Signature)>",
  "signer_fp": "806673C56B7BD285"
}
```

签名计算规则：
$$\text{sig} = \text{Ed25519\_Sign}(\text{sk}_{\text{ed}}, \text{UTF8}(\text{envelope\_base64url}))$$

---

## 3. 关联认证数据 (AAD) 构造规范

为防止重放攻击、跨请求路径移花接木或跨接口调用篡改，HPKE 密封与解密时必须传入强绑定的 AAD：

$$\text{AAD} = \text{METHOD} \parallel \text{"|"} \parallel \text{PATH} \parallel \text{"|"} \parallel \text{TIMESTAMP} \parallel \text{"|"} \parallel \text{NONCE\_HEX}$$

* **METHOD**: HTTP 请求方法大写，如 `POST`、`GET`。
* **PATH**: 请求相对路径，如 `/api/v1/action`。
* **TIMESTAMP**: 客户端生成报文时的 UNIX 时间戳（秒，如 `1731682800`）。
* **NONCE_HEX**: 报文中 12 字节 Nonce 的 24 字符小写十六进制表示。

**示例**：
```text
POST|/api/v1/action|1731682800|e4f8b91234cdef0123456789
```

---

## 4. 防重放与时钟窗口规则 (Anti-Replay)

服务端接收到报文后，必须按以下顺序执行防重放过滤：

1. **时钟偏差检查**：
   $$\left| \text{Time}_{\text{now}} - \text{timestamp} \right| \le 300\text{ 秒}$$
   若超出 $\pm 300\text{s}$ 容差窗口，立即拒绝（错误码 `TIMESTAMP_EXPIRED`）。
2. **Nonce 去重过滤**：
   在内存滑窗集合或 Redis 中检查当前 `nonce` 是否存在：
   * 若已存在，判定为重放攻击，立即拒绝（错误码 `REPLAY_DETECTED`）。
   * 若不存在，将 `nonce` 存入集合，TTL 设定为 600 秒（覆盖整个时钟窗口）。
3. **AEAD 验密解密**：
   使用传入的 AAD 解密密文。如果黑客篡改了时间戳或请求路径，解密直接失败（错误码 `DECRYPTION_FAILED`）。

---

## 5. 大文件分块流传输协议 (Chunked Stream)

对于超过 64KB 的长报文或文件，采用分块流式封包（Magic `SVCH`，0x53564348）：

* **分块大小**: 64 KB (`65536` 字节)
* **密钥复用**: 双方仅进行一次 HPKE 密钥协商（产生一个 32 字节 `enc`）。
* **独立 Nonce**: HPKE 内部根据序列号自动递增派生每块独立的 Nonce：
  $$\text{nonce}_i = \text{base\_nonce} \oplus \text{seq}_i$$
* **分块 AAD**:
  $$\text{Chunk\_AAD}_i = \text{Base\_AAD} \parallel \text{"|chk:"} \parallel i \parallel \text{"|"} \parallel (\text{"last"} \text{ or } \text{"more"})$$

---

## 6. 标准错误码 (Error Codes)

| 错误码枚举 | HTTP 状态码 | 说明 |
| :--- | :--- | :--- |
| `INVALID_KEY_LENGTH` | 400 | 公私钥字节长度不为 32 字节 |
| `INVALID_ENVELOPE` | 400 | 报文头部损坏、版本号或算法不匹配、长度不足 |
| `TIMESTAMP_EXPIRED` | 400 | 时间戳偏离服务端当前时钟超过 $\pm 300$ 秒 |
| `REPLAY_DETECTED` | 403 | 请求 Nonce 已被消费，判定为重放 |
| `INVALID_SIGNATURE` | 401 | Ed25519 签名验证失败，发送方身份未通过 |
| `DECRYPTION_FAILED` | 400 | Poly1305 Tag 不匹配、密文被篡改或 AAD 错配 |
| `CHUNK_CORRUPTED` | 400 | 分块流在特定索引处校验失败或长度越界 |

---

## 7. Swift 与 Node.js API 映射对照表

| 功能操作 | Swift (iOS 17+ CryptoKit) | Node.js (`hpke-js` + `crypto`) |
| :--- | :--- | :--- |
| **HPKE 套件** | `HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly` | `new CipherSuite({ kem: KemId.DhkemX25519HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Chacha20Poly1305 })` |
| **X25519 私钥生成** | `Curve25519.KeyAgreement.PrivateKey()` | `await suite.generateKeyPair()` |
| **HPKE 发送加密** | `var sender = try HPKE.Sender(...)`<br>`let ct = try sender.seal(pt, authenticating: aad)` | `const sender = await suite.createSenderContext(...)`<br>`const ct = await sender.seal(pt, aad)` |
| **HPKE 接收解密** | `var recipient = try HPKE.Recipient(...)`<br>`let pt = try recipient.open(ct, authenticating: aad)` | `const recipient = await suite.createRecipientContext(...)`<br>`const pt = await recipient.open(ct, aad)` |
| **Ed25519 签名** | `try privateKey.signature(for: data)` | `crypto.sign(null, data, privateKey)` |
| **Ed25519 验签** | `publicKey.isValidSignature(sig, for: data)` | `crypto.verify(null, data, publicKey, sig)` |
| **私钥安全存储** | iOS Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) | 环境变量或安全密钥存储 (KMS / OS Keyring) |
