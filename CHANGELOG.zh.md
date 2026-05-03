# 更新日志

本文档记录 **sing-ewp** 的所有重要变更。本项目遵循
[语义化版本规范](https://semver.org/lang/zh-CN/)。

---

## v0.1.2 — 加固版本

本次发布在不改动密码学核心的前提下,针对三类真实威胁(基于重放的 DoS、
明文协议指纹、被恶意/时钟错乱的对端诱导)对 EWP/v2 握手做了系统性加固。

> **线协议变更说明**
>
> 4 字节的明文魔数 `EWP2` 已从 `ClientHello` 与 `ServerHello` 中删除。
> v0.1.2 的服务端与客户端 **与 v0.1.1 不兼容**,请同步升级。
> 密码学原语(X25519 + ML-KEM-768 hybrid、ChaCha20-Poly1305、
> HKDF-SHA-256、HMAC-SHA-256)保持不变。

### 新增

- **`ClientHello` 抗重放缓存**(`anti_replay.go`)
  - 新增 `ReplayCache` 类型,内部使用 sharded mutex + 投机式 GC
    (每 1024 次插入触发一次清理),无后台 goroutine。
  - 新增常量 `ReplayWindow = HandshakeTimestampWindow + 60s`
    (默认 180 秒),在原有时间窗口基础上预留时钟偏差余量。
  - 新增错误哨兵 `ErrReplay`:同一 `(uuid, nonce)` 在窗口内被再次观察到
    时返回。
- **`AcceptClientHelloWithReplay`** —— `AcceptClientHello` 的变体,
  接受可选的 `*ReplayCache`。传入 `nil` 时与旧版行为一致。
- **`Service.SetReplayCache`** —— 替换默认缓存(例如测试中禁用,或安装
  自定义大小的实现)。
- **`ServerTime` 客户端校验**:`ClientHandshakeState.ReadServerHello`
  现在与服务端对 `ClientHello.Timestamp` 的检查对称,如果
  `|ServerTime − now| > 120s`,在做任何 ECDH / ML-KEM 解封装之前直接
  返回 `ErrTimestamp`。

### 变更

- **`Service` 默认开启抗重放**:调用 `NewService` 会默认安装
  `ReplayCache(ReplayWindow)`。已有调用代码自动获益,无 API 变更。
- **线协议:删除 `Magic` / `MagicLen`**
  - `ClientHello` 现在直接以 12 字节高熵随机 nonce 开头。
  - `ServerHello` 现在直接以 echo 的 nonce 开头。
  - 前导字节的认证由原有的 outer HMAC-SHA-256/16(已覆盖整条消息)和
    `ClientHello` 的 AEAD AAD 绑定共同提供。
  - `MagicLen` 作为 `const = 0` 保留以保证源码兼容,但不再出现在线上。
  - `ErrMagic` 标记为 `Deprecated`:解码器不再返回它,前导字节被篡改时
    将返回 `ErrOuterMAC`。

### 安全收益

| 攻击向量 | v0.1.1 | v0.1.2 |
|---|---|---|
| DPI 通过固定 `EWP2` 4 字节做协议指纹 | 微不足道(偏移 0 处恒定模式) | 已消除 —— 前 12 字节为均匀随机的 nonce |
| 重放抓到的 `ClientHello` 烧服务端 X25519+ML-KEM-Encap CPU | 每次重放 1 次完整非对称运算,120s 内不限次 | 一次 `(uuid,nonce)` map 查找即拒,`O(1)` 成本 |
| 借重放做流量相关性分析 | "同字节被接受 N 次"暴露 EWP 身份 | 同字节在 `ReplayWindow` 内仅接受一次 |
| 客户端被诱导握手到持有过期 `ServerHello` 的对端 | 无时间戳校验,直接接受 | 时间窗口外即返回 `ErrTimestamp` |

会话密钥派生(`DeriveSessionKeys`)与帧层 AEAD 严格计数器有意保持不变。
前向保密仍由 X25519 + ML-KEM-768 一对临时密钥提供。

### 迁移

- **服务端与客户端必须同步升级**。v0.1.1 客户端会在 `ClientHello` 头部
  发送 `EWP2` 4 字节,v0.1.2 服务端会把这些字节当作 nonce 的一部分,
  导致 AEAD/MAC 验证失败并关闭连接。
- 无需修改任何配置;UUID 与配置 schema 保持不变。
- 如果你之前手工构造握手并校验旧的明文魔数,应改为校验 outer MAC。
  参见新的 `TestHandshake_TamperedLeadingBytesRejected`。

### 测试

- 新增 `anti_replay_test.go` 覆盖:首次接受、重复拒绝、不同 nonce /
  不同 UUID 的隔离性、过期后重新接受、并发竞态(高争用下精确 1 次接受)、
  持续负载下的 GC 上限。
- `TestHandshake_BadMagicRejected` 重命名为
  `TestHandshake_TamperedLeadingBytesRejected` 并重写:任何对前导字节
  的篡改都必须被 outer MAC 抓到(不再依赖 magic check)。
- 完整测试套件(含原有 `hardening_test.go` / `v2_test.go`)均通过
  `-race`。

---

## v0.1.1

EWP/v2 协议库首次公开发布。

- X25519 + ML-KEM-768 hybrid 握手(后量子前向保密)。
- ChaCha20-Poly1305 AEAD 帧封装,每方向严格计数。
- HKDF-SHA-256 派生会话密钥,绑定客户端 + 服务端 nonce。
- `ClientHello` 与 `ServerHello` 均带 HMAC-SHA-256/16 外层认证。
- 握手与帧填充,用于流量形态混淆。
- 预留 ping/pong、rekey、UDP 子会话等帧类型。
