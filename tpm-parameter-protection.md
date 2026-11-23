# TPM 会话参数保护分析：会话密钥如何决定参数加解密

分析对象：`github.com/google/go-tpm`（本仓库，分支 `task/311`，HEAD `c395998`），重点为 `tpm2` 包。
分析依据：仓库源码 + TPM 2.0 Library Specification Part 1（架构）/ Part 2（结构）/ Part 3（命令）。

**核心结论先行：TPM 会话的"建立成功"只代表授权通道存在，不代表任何参数获得了机密性。**
一个既不加盐（unsalted）也不绑定（unbound）、实体授权值为空的 HMAC 会话，其参数加密密钥可以由任何看到总线字节的人直接推导出来——线上密文等同于混淆，而不是机密。本仓库默认路径（`PasswordAuth` / 无加密属性的 HMAC 会话）正是把敏感参数以明文放上总线。

---

## 1. 会话密钥与参数加解密的代码级机制

### 1.1 会话密钥（sessionKey）的决定方式

会话在 `hmacSession.Init` / `policySession.Init`（`tpm2/sessions.go:399`、`tpm2/sessions.go:765`）中通过 `TPM2_StartAuthSession` 建立。sessionKey 仅在**加盐或绑定**时才被派生：

```go
// tpm2/sessions.go:444-449（hmacSession，policySession 在 811-820 行逻辑相同）
if s.bindHandle != TPMRHNull || len(salt) != 0 {
    var authSalt []byte
    authSalt = append(authSalt, s.bindAuth...)   // 绑定实体的 authValue
    authSalt = append(authSalt, salt...)         // 加盐会话的随机 salt
    s.sessionKey = KDFa(ha, authSalt, "ATH", s.nonceTPM.Buffer, s.nonceCaller.Buffer, ha.Size()*8)
}
```

由此得到三种会话密钥形态：

| 会话形态 | sessionKey | 总线可见的派生输入 | 监听者能否恢复 sessionKey |
|---|---|---|---|
| 不加盐、不绑定 | **nil（空）** | 两个 nonce 都是明文 | 不存在 sessionKey，无需恢复 |
| 加盐（`Salted(handle, pub)`） | `KDFa(hash, salt, "ATH", ...)` | 仅能看到用 EK/SRK 公钥封装后的 `EncryptedSalt`（`getEncryptedSalt`，`sessions.go:384`；底层为 labeled KEM，`create_salt.go`） | 不能，除非持有封装私钥 |
| 绑定（`Bound(handle, name, auth)`） | `KDFa(hash, bindAuth, "ATH", ...)` | nonce 明文，但 bindAuth 从不上线 | 不能，除非已知绑定实体的 authValue |

两个 nonce（`nonceCaller` 由 `crypto/rand` 生成，`nonceTPM` 由 TPM 生成）**在会话区中以明文传输**（`TPMSAuthCommand.Nonce`，`structures.go:1339`），它们只提供新鲜性/防重放，不提供机密性。

### 1.2 授权 HMAC 的密钥

授权 HMAC（`computeHMAC`，`sessions.go:506`）在命令侧对 `cpHash = H(CC ‖ names ‖ parms)` 计算，在响应侧对 `rpHash = H(RC ‖ CC ‖ parms)` 计算：

```go
// sessions.go:547-551（Authorize）；Validate 在 591-595 行逻辑相同
hmacKey = append(hmacKey, s.sessionKey...)
if /* 不是在给绑定目标本身授权 */ {
    hmacKey = append(hmacKey, hmacKeyFromAuthValue(s.auth)...)
}
```

即 HMAC 密钥 = `sessionKey ‖ 实体 authValue`（授权绑定目标时按规范去掉 authValue 部分）。注意：

- **authValue 本身从不在 HMAC/Policy 会话中上线**，线上只有 HMAC 输出；监听者无法直接读取，只能离线字典猜测（这也是 TPM 字典攻击防护 `NoDA` 的意义所在）。
- 密码伪会话（`pwSession`，`sessions.go:83`）走完全不同的路径：authValue 被**原样塞进授权区**（`sessions.go:110-118`），没有 nonce、没有 HMAC、没有响应校验。

### 1.3 参数加密密钥（CFB key/IV）

参数加密由会话属性 `TPMA_SESSION.decrypt/encrypt` 打开，本仓库通过 `AESEncryption(keySize, dir)`（`sessions.go:278`）设置，算法固定 AES-CFB。参数加解密在 `Encrypt`/`Decrypt`（`sessions.go:625`、`656`，policy 会话 `958`、`989` 行同构）中完成：

```go
// 命令方向（Decrypt 会话，sessions.go:636-649）
sessionValue = append(sessionValue, s.sessionKey...)
sessionValue = append(sessionValue, s.auth...)
keyIV := KDFa(ha, sessionValue, "CFB", s.nonceCaller.Buffer, s.nonceTPM.Buffer, ...)
// 响应方向（Encrypt 会话，sessions.go:668-681）：nonce 顺序对调
keyIV := KDFa(ha, sessionValue, "CFB", s.nonceTPM.Buffer, s.nonceCaller.Buffer, ...)
```

参数密钥的全部熵来自 `sessionKey` 与调用方传入的 `Auth(authValue)`，而 KDF 的上下文（两个 nonce）在总线上**完全可见**。因此：

> **不加盐 + 不绑定 + 空 authValue ⇒ `sessionValue` 为空，KDF 的所有输入均可从总线获取 ⇒ 任何监听者都能本地算出同一把 AES 密钥。** 这不是本实现的缺陷，而是 TPM 协议本身的边界（Part 1 对 unsalted/unbound 空授权会话只承诺 obfuscation，不承诺 confidentiality）。
> 反之，加盐（salt 不上线）、绑定（bindAuth 不上线）或实体具有强 authValue 三种情况中任一成立，监听者就缺少 KDF 输入，参数加密才具备真正的机密性。

### 1.4 哪些字节会被加密：只有"第一个 2B 参数"

反射层 `cmdParameters`（`reflect.go:1024`）和 `rspParameters`（`reflect.go:1266`）决定加密范围：

- 仅命令/响应参数区的**第一个参数**，且它必须是带 2 字节长度前缀的 TPM2B；只对 `[2:]` 的内容做 CFB，**2 字节长度前缀不加密**（`reflect.go:1047`）。
- 不是 2B 时直接报错（`reflect.go:1044-1045`）；最多一个 Decrypt、一个 Encrypt 会话（`reflect.go:1040`、`1079-1095`）。
- 其余参数、句柄区、会话区、命令码、全部头部，一律明文。
- HMAC 在加密**之后**对线上密文计算（`execute` 先 `cmdParameters` 后 `cmdSessions`，`reflect.go:49-64`）；响应侧先 `rspSessions` 校验 HMAC、后 `rspParameters` 解密（`reflect.go:110-115`）。顺序正确，CFB 可塑密文在解密前就会被 HMAC 拦截。

传输层本身不提供任何保护：`transport.TPM.Send` 是裸字节接口（`transport/tpm.go:11`）；Linux 字符设备是本地内核接口，而 `transport/tcp`（模拟器/远程 TPM）是**无 TLS 的明文 TCP**（`transport/tcp/tcp.go:143-182`，全仓 grep 不到任何 TLS）。所有总线防护都只能来自会话机制。

---

## 2. 敏感命令的数据流追踪

下表列出仓库中承载秘密的命令。"首参数"列决定该命令能否用会话参数加密；"默认调用暴露什么"基于仓库测试中实际出现的调用方式。

| 命令 | 首参数（可加密部分） | 同命令中**永远明文**的敏感/语义字段 | 仓库中的默认/测试调用方式 |
|---|---|---|---|
| `HierarchyChangeAuth` (`tpm2.go:1678`) | `NewAuth TPM2BAuth` —— 新层级授权值，**可 EncryptIn** | 句柄（改的是 owner/endorsement/lockout 哪一个） | 测试用 `PasswordAuth(authKey)` 与**无加密的** `HMAC(...)`（`test/hierarchy_change_auth_test.go:50,68`）→ 新 authValue 明文上线 |
| `NVChangeAuth` (`tpm2.go:2203`) | `NewAuth TPM2BAuth` —— NV 索引新授权值，**可 EncryptIn** | NV 索引句柄/Name | 测试同时覆盖明文变体与 `Salted(SRK)+AESEncryption(128,EncryptIn)` 变体（`test/nv_change_auth_test.go:151-155`），证明两种用法都被支持 |
| `ObjectChangeAuth` (`tpm2.go:426`) | `NewAuth TPM2BAuth`，**可 EncryptIn** | object/parent 句柄；响应 `OutPrivate` 是父密钥包装的（首参数，可 EncryptOut） | 测试全部用 `PasswordAuth`（`test/object_change_auth_test.go`） |
| `NVDefineSpace` (`tpm2.go:1964`) | `Auth TPM2BAuth` —— 新 NV 区域授权值，**可 EncryptIn** | `PublicInfo`（索引属性、大小、策略摘要） | 无加密示例 |
| `Create` (`tpm2.go:206`) / `CreateLoaded` (`455`) | `InSensitive TPM2BSensitiveCreate`，内含 `UserAuth`（新对象口令）与密封 `Data`，**可 EncryptIn** | `InPublic` 模板、`OutsideInfo`、PCR 选择；响应的 `OutPrivate` 已被父密钥包装（首参数可再 EncryptOut） | `sealing_test.go` 演示了加密/不加密两种；不加选项即明文 |
| `Unseal` (`tpm2.go:403`) | 命令无参数；响应首参数 `OutData TPM2BSensitiveData` —— 解封秘密，**需 EncryptOut 才受保护** | 句柄 | 不加 `AESEncryption(EncryptOut)` 时秘密明文返回 |
| `NVWrite` (`tpm2.go:2066`) | `Data TPM2BMaxNVBuffer` —— 写入 NV 的数据，**可 EncryptIn** | `Offset`、NV 句柄（写入位置与目标完全暴露） | 测试用普通 HMAC（`nv_change_auth_test.go:171`），数据明文 |
| `NVRead` (`tpm2.go:2143`) | 命令首参数是 `Size uint16`（非 2B，命令侧无可加密参数）；响应 `Data TPM2BMaxNVBuffer` **可 EncryptOut** | `Size`/`Offset`（读取范围暴露）；2B 长度前缀暴露实际数据长度 | — |
| `ActivateCredential` (`tpm2.go:341`) | `CredentialBlob`（EK 包装，首参数可再 EncryptIn）；响应 `CertInfo` 可 EncryptOut | `Secret`（封装种子，本就非对称加密） | — |
| `RSADecrypt` (`tpm2.go:551`) | `CipherText`（首参数可 EncryptIn）；响应 `Message` 可 EncryptOut | `Label`、`InScheme` 在后续参数中，**始终明文** | — |
| `ECDHZGen` (`tpm2.go:582`) | `InPoint`（对端公钥，首参数可加密，但其本身通常是公开值）；响应 `OutPoint`（共享秘密 Z）**可 EncryptOut，不加密则 Z 明文上线** | — | — |
| `EncryptDecrypt2` (`tpm2.go:489`) | `Message`（首参数可 EncryptIn/Out） | `IV TPM2BIV`、`Mode`、`Decrypt` 标志在后续参数中**始终明文**；IV 泄露 + CFB 语义可见 | `test/symmetric_encryption_test.go` 全程未用会话加密 |
| `Import` (`tpm2.go:1848`) | `EncryptionKey`（内层包装密钥，首参数，**可 EncryptIn**） | `ObjectPublic`、`Duplicate`、`InSymSeed`（后两者本就被包装/封装） | — |
| `Quote`/`Certify`/`NVCertify` | `QualifyingData`（首参数可加密，但通常非秘密） | 响应中的签名、attest 结构是公开可验证产物，**设计上即明文**，会话加密对其无安全增益 | — |
| `ContextSave`/`ContextLoad` (`tpm2.go:1705/1729`) | 不接受会话参数加密（context blob 由 TPM 自身完整性保护） | blob 整体上线，内含敏感区但带 TPM 内部 HMAC/加密 | — |

### 2.1 两个代表性数据流

**（A）`HierarchyChangeAuth` 改 owner 授权值，默认密码会话路径（对应测试第 46-61 行）：**

```
调用方 NewAuth="newAuthKey"
  → cmdAuths 发现裸 handle 没有 Auth 字段 → 自动补 PasswordAuth(nil)（reflect.go:801-803）
  → 授权区: [TPM_RS_PW][空nonce][属性=0][HMAC区原样=authValue 或空]   ← 明文
  → 参数区: [00 09][newAuthKey]                                      ← 明文
被动监听者: 直接读到新 owner 口令，随后即可离线冒充 owner。
```

**（B）`NVChangeAuth` 加盐加密路径（`nv_change_auth_test.go:151-164`）：**

```
Policy(..., Salted(SRK, srkPub), AESEncryption(128, EncryptIn))
  → salt 由 SRK 公钥 labeled-KEM 封装上线，监听者无 SRK 私钥 → 拿不到 salt
  → sessionKey = KDFa(..., salt, "ATH", nonceTPM, nonceCaller)      ← 监听者无法恢复
  → CFB key = KDFa(sessionKey‖auth, "CFB", nonceCaller, nonceTPM)   ← 监听者无法恢复
  → 参数区: [00 09][AES-CFB("newAuth")]                              ← 机密
  → cpHash HMAC 覆盖密文，篡改即 HMAC 失败
```

---

## 3. 被动监听者能从可见字节得到什么

### 3.1 任何会话形态下都可见的信息

- 命令码（在做什么操作）、全部句柄与 Name（对哪个对象操作）、命令/响应长度；
- 会话句柄、会话属性字节（`attrsToBytes`，`sessions.go:473`——是否 decrypt/encrypt/audit 一目了然）、两个 nonce；
- 加密参数的 **2 字节长度前缀与密文长度**——参数机密性不覆盖长度，可推断口令长度、NV 数据块大小；
- 第一个 2B 之外的所有参数（IV、offset、scheme、label、模板 InPublic 等）；
- 响应码（成功/失败，包括 `TPM_RC_BAD_AUTH` 这类可用于口令猜测侧信道的区分）。

### 3.2 按授权形态划分的边界

| 形态 | authValue 是否暴露 | 参数机密性 | 监听者实际可得 |
|---|---|---|---|
| **密码会话 `PasswordAuth`** | **直接明文**（`sessions.go:115`） | 不可能（`IsEncryption/IsDecryption` 恒 false，`sessions.go:140-144`） | 授权值本身 + 全部参数明文。总线上出现 `TPM_RS_PW` 即可识别 |
| **HMAC/Policy，unsalted+unbound，空 auth，无加密属性** | 不暴露（只有 HMAC） | 无参数加密 | 全部参数明文；HMAC 仅证明发送者知道空 auth（无意义） |
| **HMAC/Policy，unsalted+unbound，空 auth，带 AES 加密** | 不暴露 | **仅混淆**：监听者用可见 nonce 对空字符串跑 KDFa("CFB") 即得到密钥，可解密全部"密文" | 解密后的全部参数 |
| **HMAC/Policy，unsalted+unbound，强 auth，带 AES 加密** | 不直接暴露，可离线字典攻击 HMAC | 有效，直至 auth 被猜解 | 密文；auth 被猜解后全线失密 |
| **加盐（Salted）或绑定（Bound），带 AES 加密** | 不暴露 | **真正机密**：salt/bindAuth 从不上线，KDF 输入不可见 | 仅密文、长度、元数据 |
| **Policy + `Password(auth)` 选项** | **直接明文**（`sessions.go:864-865`，该选项已标注 Deprecated） | 无 | 同密码会话 |

**边界判定原则（对应任务要求）：未被参数加密覆盖的字段，不能因为命令"带了一个成功的会话"就被称为机密。** 例如 `EncryptDecrypt2` 即使挂了 EncryptIn 会话，其 IV、模式、操作方向仍是明文；`NVWrite` 加密了 Data，offset 与目标索引仍公开；`Quote` 的签名本就是公开产物。会话成功证明的是"发送者被授权且字节未被篡改"，仅此而已。

---

## 4. 主动篡改者能做什么

### 4.1 HMAC / Policy 会话：完整性覆盖范围与缺口

命令 HMAC 的输入 `cpHash = H(CC ‖ 所有 Name ‖ 线上参数)`（`sessions.go:162`），响应 HMAC 覆盖 `rpHash = H(RC ‖ CC ‖ 参数)`，且本仓库用 `hmac.Equal` 常量时间比较（`sessions.go:607`、`939`）。篡改以下任一字节都会导致 HMAC 失配而被拒：

- 任意参数（含密文：CFB 虽是可塑流密码，但 HMAC 在解密前校验，bit-flipping 不可达 TPM 逻辑层）；
- 命令码、会话属性字节（攻击者无法把 decrypt 位翻成 0 来做降级）、nonce；
- 响应参数与响应 HMAC 本身。

但存在三个协议/实现层面的缺口：

1. **错误响应不做会话认证。** `rspHeader` 一旦看到非零 RC 就直接返回（`reflect.go:79-92`），代码中留有 `// TODO: Authenticate the error code with sessions`（`reflect.go:104`）。主动攻击者可以注入伪造的 TPM 错误响应，造成拒绝服务、让调用方误判口令错误（`TPM_RC_BAD_AUTH`）或触发上层重试/状态机分支；对可续用会话还会造成 nonce 视图不同步。
2. **句柄值本身不在 cpHash 内，受保护的是 Name。** 替换为同 Name 的其他句柄不可行（Name 绑定实体），但句柄区的篡改语义仍由 TPM 侧 Name 校验兜住，而非 HMAC 直接覆盖。
3. **重放受 nonce 轮换约束**：每次执行都 `NewNonceCaller()`（`reflect.go:41`），TPM 每次返回新 nonceTPM，旧命令包无法通过新鲜性校验。攻击者能做的是阻断、延迟、重排（流量层面的 DoS），不能重放生效。

### 4.2 密码会话：零完整性

`pwSession.Validate` 只检查响应里 nonce/HMAC 是否为空（`sessions.go:122-136`），命令侧没有任何认证标签。主动攻击者可以任意改写 `NewAuth`、NV 数据、句柄，TPM 会当作合法请求执行（只要改写后的 authValue 字段与实体当前 auth 相符——而该字段本身也是明文可改的）。这是密码会话最危险的性质：它同时丧失机密性、完整性与防重放。

### 4.3 降级攻击面

- 本仓库会话属性由调用方在客户端选定，线上属性字节受 HMAC 保护，**中间人不能把加密会话降级为明文会话**；但应用层若根本没有请求加密（默认情况），总线不会自发提供任何保护——降级空间在客户端配置，而非线上翻转。
- 无 TLS 的 TCP 传输（`transport/tcp`）下，中间人还可替换整个响应；在错误响应路径上不会被任何机制发现（见 4.1.1）。

---

## 5. 加固方案（不破坏既有命令调用）与兼容代价

设计原则：所有改动以**新增可选 API / 可选包装 / 运行时告警**形式提供，既有 `cmd.Execute(tpm, sess...)` 签名与线上字节格式不变，老代码无需修改即可编译运行。

### H1. 提供"安全会话"构造器，把正确用法变成一行（推荐优先）

新增导出 helper（内部仍调用现有 `HMAC`/`Policy` + `Salted` + `AESEncryption`）：

```go
// 建议形态，非现有 API
func ConfidentialHMAC(tpm, hash, nonceSize, saltHandle, saltPub TPMTPublic, dir, opts...) Session
//  = HMAC(hash, nonceSize, Salted(saltHandle, saltPub), AESEncryption(128, dir), opts...)
```

- 效果：消除"开了 AES 却没加盐、auth 又为空"的伪加密配置；`nv_change_auth_test.go` 里手工组合两个选项的模式被固化。
- 兼容代价：**纯新增**，旧 API 不改动；代价是调用方需要持有一个可封装 salt 的加载密钥（EK/SRK），多一次 `StartAuthSession` 的封装计算（labeled KEM，毫秒级）与少量字节。

### H2. 敏感命令的策略化运行时检查（opt-in，默认关闭）

增加一个可选的执行包装或包级开关（例如 `tpm2.WithSecurityPolicy(...)` 或 wrapper `transport.TPM`），对第 2 节清单中的命令（`*ChangeAuth`、`NVDefineSpace`、`Create*`、`Unseal`、`NVRead/Write`、`Import`、`ECDHZGen` 等）校验会话区：

- 首参数为敏感 2B 时，要求存在方向匹配的 decrypt/encrypt 会话；
- 该会话必须 salted 或 bound，或实体 auth 非空（即 `sessionValue` 不为空），否则返回错误，拒绝发出命令；
- 对密码会话承载敏感命令发出告警/错误。
- 兼容代价：默认关闭时零影响；开启后**配置不达标的既有调用会被拒绝**（这是目的本身），需要调用方改造会话建立代码。不修改任何命令结构体与线上格式。

### H3. 收紧密码会话与 `Password()` 策略选项

- 在 `PasswordAuth` 与已 Deprecated 的 `Password()` 文档中明确"总线明文、无完整性、无防重放"，并在 H2 策略下对敏感命令禁用；
- 对 `cmdAuths` 自动补 `PasswordAuth(nil)` 的行为（`reflect.go:801`）增加可选日志，便于审计哪些命令在裸奔。
- 兼容代价：默认仅文档与日志，零行为变化；严格模式下需要把 `PasswordAuth` 替换为 `HMAC`/`Policy`（每命令多一次会话 JIT 建立，one-off 会话用后即 flush，资源开销小）。

### H4. 为远程传输补 TLS 包装（传输层，与 TPM 会话正交）

`transport/tcp` 新增 `OpenTLS(config, tlsConfig)` 或通用 `transport.NewTLS(inner, tlsConfig)` 包装器，在裸 `Send` 之外提供通道级机密性与双向认证。

- 效果：覆盖 TPM 会话机制管不到的字段——句柄、命令码、长度、IV、offset、会话属性、**错误响应码**；防中间人注入伪造响应。
- 兼容代价：**纯新增包装器**，老的 `Open` 保留；需要部署 PKI/预共享密钥与对端（软件 TPM 服务）支持，本地 `/dev/tpmrm` 场景不需要。注意 TLS 不替代会话 HMAC（TLS 止于代理，TPM 端到端授权仍靠会话），两者互补。

### H5. 认证错误响应（协议允许的范围内）

利用 HMAC 会话对错误响应也携带授权区的特性（TPM 规范允许 TPM 在错误响应中返回 session area），在客户端补全 `reflect.go:104` 的 TODO：当命令带会话且错误响应包含授权区时校验 rpHash。

- 兼容代价：取决于 TPM 是否在错误响应中返回授权区；不返回时无法校验，只能维持现状，因此该改进是**尽力而为**，不改变成功路径的任何字节。需要区分模拟器/实体 TPM 行为，测试矩阵成本是主要代价。

### H6. 修复响应解密的长度启发式（健壮性，非机密性）

`rspParameters` 用"前两字节解释成长度是否合理"决定是否解密（`reflect.go:1274-1288`，代码自带 `TODO: Make this nice using structure tagging`）。建议改为基于响应结构体首字段类型的显式判定（复用 `gotpm` tag 反射），避免构造异常长度时误入/误入不解密分支。

- 兼容代价：内部重构，线上格式零变化；风险在于反射边界 case，需要补齐现有 `sealing_test.go` 全模式回归。

### H7. 应用层缓解长度泄露与"首参数之外"的明文

TPM 协议只能加密第一个 2B、且不隐藏长度，这是规范硬限制，库层面无法突破。对有更高需求的字段：

- 固定长度/分块填充敏感 2B（在应用数据层把 `NewAuth`、NV Data 填充到定长），缓解长度侧信道；
- 对必须保护的非首参数字段（如 `EncryptDecrypt2.IV`、`RSADecrypt.Label`）在应用层先做封装再送入 TPM；
- 代价：占用 TPM 缓冲配额（`MAX_DIGEST_BUFFER` 1024，见 `symmetric_encryption_test.go:15` 的分块逻辑）、增加应用侧协议设计，与 TPM 会话无关。

### 兼容代价汇总

| 方案 | 线上字节变化 | 旧代码是否需改 | 主要成本 |
|---|---|---|---|
| H1 安全会话构造器 | 无（新 helper 产出标准会话） | 否 | 需加载盐密钥；每会话一次 KEM |
| H2 敏感命令策略检查 | 无 | 默认否；严格模式下不达标调用被拒 | 调用方会话改造 |
| H3 密码会话收紧 | 无 | 默认否 | 严格模式需替换 PW 会话 |
| H4 TLS 传输 | 无（传输层封装） | 否（新 Open 函数） | PKI 与对端支持 |
| H5 错误响应认证 | 无 | 否 | TPM 行为差异，测试矩阵 |
| H6 解密启发式修复 | 无 | 否 | 反射回归测试 |
| H7 应用层填充/封装 | 载荷变长 | 是（应用协议） | 缓冲配额与设计复杂度 |

---

## 6. 结论

1. **会话密钥的熵决定一切**：salt（不上线）、bindAuth（不上线）、实体 authValue（HMAC 会话不上线）三者至少有一个不为攻击者所知，参数加密才是机密；三者皆空时，AES-CFB 密钥可由总线可见的 nonce 直接复现，加密退化为混淆。代码位置：`sessions.go:444`（sessionKey 派生）、`sessions.go:636-643`（CFB 密钥派生）。
2. **保护面天然狭窄**：只有第一个 TPM2B 参数的内容（不含长度前缀）被加密；句柄、命令码、会话属性、nonce、后续参数、长度全部明文。密码会话连这一层都没有，且无完整性与防重放。
3. **被动监听**在 PW 会话下直接获得授权值与全部秘密；在空 auth 未加盐的"加密"会话下可自行推导密钥解密；仅在加盐/绑定/强 auth 会话下被挡在密文之外，但始终保有元数据与长度。
4. **主动篡改**对 HMAC/Policy 会话基本无效（cpHash/rpHash + 常量时间比较，且先验签后解密），但错误响应未经认证（`reflect.go:104` TODO）、PW 会话完全可篡改、无 TLS 传输可被整体替换。
5. **未保护的参数不能因会话成功就被称为机密**——这是调用方最容易误判的点。加固应优先以 H1（安全会话构造器）+ H2（敏感命令策略）把"加盐 + 方向正确的 AES 会话"变成默认，以 H4（TLS）补足元数据与错误响应保护，且全部可在不改变既有命令签名与线上格式的前提下落地。
