
## 配置选项

- `Secret`: 用于签名的密钥
- `Algorithm`: 签名算法，可选值：MD5, SHA1, SHA256, HMAC_MD5, HMAC_SHA1, HMAC_SHA256
- `SignatureKey`: 签名参数名，默认为 "sign"
- `IgnoreKeys`: 在签名计算中忽略的参数名列表
- `UpperCase`: 签名是否使用大写，默认为 false（小写）

## 签名过程

1. 移除签名参数和忽略的参数
2. 按键名字母顺序排序
3. 构建格式为 `key1=value1&key2=value2&...&keyN=valueN&key=secret` 的字符串
4. 使用指定的算法计算签名
5. 根据配置转换为大写或小写

