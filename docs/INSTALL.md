# 安装 SideVault

两种路线选一个。**没有 $99 开发者账号就走第一节**，能装能用，代价是 7 天续签一次。

前置条件（两种路线都要）：

- iPhone 运行 **iOS 17.0 或更高**。低于 17 装不了也跑不了——HPKE 是 iOS 17 才有的 CryptoKit API，包里的 `MinimumOSVersion` 就是 `17.0`。
- 手机设了锁屏密码（SideStore 要求）。
- 手机和电脑在**同一个 Wi-Fi**（手机不能用蜂窝网络）。

---

## 一、免费路线（Windows，SideStore 重签）

CI 出来的 IPA 是**未签名**的，双击装不了、iTunes / Apple Configurator 也装不了，只能用重签工具签了再装。整条链路是：CI 出 IPA → Windows 上一次性装好 SideStore → 以后 SideStore 用你的 Apple ID 重签并安装 → 每 7 天续签一次。

### 1. 下载未签名 IPA

GitHub → Actions → 最近一次绿色的 `ios` run → 页面最下方 Artifacts → 下载 `SideVault-unsigned-ipa` → 解压得到 `SideVault-unsigned.ipa`（约 132 KB）。

### 2. 手机：装 LocalDevVPN 并保持开启

App Store 搜 **LocalDevVPN**（`id6755608044`）装上，打开，允许它添加 VPN 配置。**之后每次安装、更新、续签都要让它开着**，它只是把流量引到手机本机，不走外网。

### 3. Windows：装 iloader，用它装 SideStore

1. 从 [iloader.app](https://iloader.app)（或 [github.com/nab138/iloader/releases](https://github.com/nab138/iloader/releases)）下 Windows 版并运行。
2. 手机用数据线连电脑，按向导操作：它会帮你生成配对文件、用你的 Apple ID 登录、把 SideStore 装到手机上。
3. 这就是**唯一需要电脑的一步**，装完就可以拔线。

### 4. 手机：SideStore 登录并刷新一次

打开 SideStore → 用同一个 Apple ID 登录 → 装完后**先刷新一次 SideStore 自己**（官方要求：首次登录后必须先 refresh，否则 app group ID 不对会导致应用列表消失）。

登录如果报 Anisette 相关错误，是 Anisette 服务器的问题，在 SideStore 设置里换一个 Anisette URL 再试。

### 5. 手机：用 SideStore 安装 SideVault

1. 把 `SideVault-unsigned.ipa` 传到手机上（AirDrop 不行就存 iCloud Drive / 微信文件传输助手，SideStore 能选任何文件）。
2. SideStore → `+` → 选中这个 IPA → 输入 Apple ID 密码 → 重签并安装。
3. 装完先在桌面上**打开一次 SideVault**，再去做 Shortcuts——App Intents 需要 app 被启动过一次，系统才会把动作索引进去。

### 6. 装完第一件事：导出密钥备份

打开 app → 「生成 / 覆盖密钥对」→ 记下两个 16 位指纹 → 在「防换号丢失：加密密钥备份」里设一个口令 → 「导出加密备份」→ 把那段 JSON 存到手机之外（密码管理器 / 电脑 / 云盘）。

**这一步不做，下次换 Apple ID 重签就永久丢失私钥。** 原因：私钥存在 Keychain，访问组跟着签名 team 走；免费账号换人重签，team 变了，旧条目就读不出来。

### 7. 7 天续签（唯一要记的日常动作）

免费开发者证书 **7 天过期**。到期前后：

1. 打开 **LocalDevVPN**（必须开着）。
2. 手机连上和当初装机同一个 Wi-Fi。
3. 打开 **SideStore → My Apps → Refresh All**（或单个 app 下拉刷新）。

**到期不续签会怎样**：SideVault 点开就闪退/提示无法验证，Shortcuts 里这 6 个动作执行时直接报错。**Keychain 里的私钥不会丢**，续签完 app 恢复正常，动作也能用——但 Shortcuts 里原来那条快捷指令需要重新跑一次（个别情况要关掉 Shortcuts 再打开才刷新）。

**额度限制**（Apple 免费账号的硬限制，不是 SideStore 的）：

- 同时最多 **3 个 app**（SideStore 自己算一个，所以只剩 2 个位置）。
- 每周最多 **10 个不同 App ID**。所以别折腾反复改 bundle id，改一次就消耗一个额度。
- 证书 7 天，过期必须续签。

### 8. 更新到新版本

CI 出了新 IPA 后：传进手机 → SideStore 选新 IPA 安装（bundle id 不变，覆盖安装）→ **Keychain 里的密钥保留**，前提是仍然用同一个 Apple ID 签名。装完打开一次 app。

---

## 二、TestFlight 路线（需要 $99/年 Apple Developer Program）

装一次管 90 天，不用每周续签，走的是正规签名。**必须先有付费开发者账号**。

### 1. 在 App Store Connect 建 app 记录

- bundle id 必须是 `dev.chuacx.sidevault`（跟 `project.yml` 里一致）。
- 名字随意（`SideVault`），SKU 随意。
- Team ID：developer.apple.com → Membership 页面能查到 10 位 ID。

### 2. 建 App Store Connect API key

App Store Connect → 用户和访问 → 集成 → App Store Connect API → 新建 key，角色选 **App Manager** → 下载 `.p8`（**只能下载一次**），记下 Key ID 和 Issuer ID。

### 3. 配 GitHub secrets / variables

| 类型 | 名称 | 内容 |
| :--- | :--- | :--- |
| secret | `ASC_KEY_P8` | `.p8` 文件的 base64：`base64 -w0 AuthKey_XXXX.p8`（PowerShell：`[Convert]::ToBase64String([IO.File]::ReadAllBytes("AuthKey_XXXX.p8"))`） |
| secret | `ASC_KEY_ID` | Key ID |
| secret | `ASC_ISSUER_ID` | Issuer ID |
| secret | `APPLE_TEAM_ID` | 10 位 Team ID（会被渲染进 `ExportOptions.plist`，不入库） |
| variable | `ENABLE_TESTFLIGHT` | `true` |

### 4. 手动跑一次并验收

Actions → `ios` → Run workflow。`testflight` job 会自动签名 archive、按 `method=app-store-connect` 导出、`fastlane pilot` 上传。

上传后到 App Store Connect → TestFlight → 内部测试，确认构建可用（内部测试员不需要 App Review）。手机上装 **TestFlight** app，用同一个 Apple 账号登录就能收到构建。

**有效期是 90 天**（TestFlight 构建的硬限制，不是 180 天——之前群里说的 180 天是错的）。过期前重新跑一次 workflow 上传新构建即可。

---

## 故障排查

| 现象 | 原因 / 处理 |
| :--- | :--- |
| SideStore 装到一半失败，报签名/验证错误 | LocalDevVPN 没开，或没连同一个 Wi-Fi，或免费账号的 app 名额用满了（3 个） |
| 装上了但点开闪退 | 证书过期（7 天到了），去 SideStore 刷新 |
| Shortcuts 里完全找不到 `SideVault:` 开头的动作 | 先手动启动一次 app；确认 iOS ≥ 17；还不行就重装一次 |
| 执行「混合加密」报公钥长度错 | 对端公钥必须是**原始 32 字节的 Base64**，不是 PEM/DER/带换行的长串 |
| 执行「混合解密」报解密失败 | 路径 / HTTP 方法 / 时间戳跟加密端不一致（它们都进了 AAD），三者必须完全一样 |
| 换了 Apple ID 重签后读不到私钥 | 预期行为。用「从备份文本恢复」+ 当初的口令恢复 |
| 提示无法验证开发者 / 需要信任 | 免费签名的正常表现，续签后正常；iOS 设置里「VPN与设备管理」可查看描述文件 |

---

## 这个 IPA 到底能装在哪

已核对过一次产物结构（CI 打出来的包）：

- `Payload/SideVault.app/` 下有 `SideVault`（arm64 主二进制）、`Info.plist`、`PkgInfo`、`Metadata.appintents/`。
- `MinimumOSVersion = 17.0`，`CFBundleIdentifier = dev.chuacx.sidevault`，`UIDeviceFamily = [1,2]`（iPhone + iPad）。
- 没有 `appex`、没有嵌入框架——重签时不需要处理任何嵌套 bundle，SideStore 一次签完。
- `Metadata.appintents/extract.actionsdata` 存在，说明编译期 App Intents 元数据提取成功，这是「动作会出现在 Shortcuts 里」的前提之一。

如果你在苹果芯片 Mac 上想直接跑模拟器版本，别用这个 IPA——它是 `platform IOS` 的 device build，只能真机装。
