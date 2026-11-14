# tls-handshake-policy-analyzer

Python TLS 握手策略分析库，处理版本协商、套件分类、降级标记和扩展冲突。

## 定位与边界

**本库只做离线握手记录分析，不建立真实连接。** 它不会打开 socket、
不会与任何对端通信、也不会执行真实的 TLS 握手。输入只能来自已经
采集到的握手记录（结构化字段或十六进制抓包），输出是引用具体消息
与字段的分析结论，用于回答“低版本协商是客户端本来如此，还是握手
在链路上被改写”这类问题。

## 输入模型

一次分析对应一条 `HandshakeRecord`：

- `ClientHello`：双方声明中的客户端一侧 —— `legacy_version`、
  `supported_versions`、`cipher_suites`、`signature_algorithms`、
  `supported_groups`、`extensions`。
- `ServerHello`：服务端选择 —— `version`、`cipher_suite`、`extensions`。
- `HandshakeEvent`：过程事件（alert、重传、中间设备备注等），以
  `kind` + 结构化 `detail` 记录。
- `server_max_version`：服务端声明的最高版本（如能从其他遥测获得）。

也可以直接从抓包十六进制解析：`parse_client_hello_hex` /
`parse_server_hello_hex`（截断记录抛出 `TruncatedRecordError`，
非法十六进制抛出 `RecordParseError`）。

## 检查项

每条 `Finding` 都带 `message_ref`（`client_hello` / `server_hello`）
和 `field`（如 `cipher_suites[1]`、`version`），指向触发判断的具体
消息与字段：

- `NO_COMMON_CIPHER_SUITE`：服务端选中了客户端从未提供的套件
  （或信令值），提示 ServerHello 可能被改写。
- `VERSION_ABOVE_ADVERTISED`：协商版本高于客户端或服务端声明的上限。
- `DOWNGRADE_SENTINEL_MISPLACED` / `DOWNGRADE_SENTINEL_UNNEEDED` /
  `UNGUARDED_DOWNGRADE`：`TLS_FALLBACK_SCSV` 未放在套件列表末尾、
  未降级却携带、或主动降级却未携带。
- `DUPLICATE_EXTENSION`：同一扩展在同一 hello 中出现多次。
- `UNKNOWN_CIPHER_SUITE`：套件不在内置注册表也不在配置的扩展注册表。
- `WEAK_CIPHER_SUITE`：命中配置提供的弱套件分类。
- `BELOW_MINIMUM_VERSION`：协商版本低于策略下限。

## 弱套件配置

弱套件分类完全由配置驱动（`PolicyConfig`），可从 JSON 加载：

```json
{
  "minimum_version": "0x0303",
  "weak_categories": {
    "rc4": ["TLS_RSA_WITH_RC4_128_SHA"],
    "cbc_mode": ["TLS_RSA_WITH_AES_128_CBC_SHA"]
  },
  "extra_known_suites": {"0x00a9": "TLS_PRIVATE_SUITE_X"}
}
```

```python
from tls_handshake_analyzer import PolicyConfig, analyze_record

policy = PolicyConfig.from_json_file("policy.json")
report = analyze_record(record, policy)
for finding in report.findings:
    print(finding)  # [severity] CODE (message.field): detail
```

## 测试

```
python -m unittest
```

测试全部使用合成握手：正常协商、客户端主动降级、篡改 ServerHello、
重复扩展、未知套件、截断十六进制记录。
