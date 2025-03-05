// Package signvalidator 提供签名验证功能
package signvalidator

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"
)

// SignAlgorithm 表示签名算法类型
type SignAlgorithm string

const (
	// MD5 算法
	MD5 SignAlgorithm = "md5"
	// SHA1 算法
	SHA1 SignAlgorithm = "sha1"
	// SHA256 算法
	SHA256 SignAlgorithm = "sha256"
	// HMAC_MD5 算法
	HMAC_MD5 SignAlgorithm = "hmac_md5"
	// HMAC_SHA1 算法
	HMAC_SHA1 SignAlgorithm = "hmac_sha1"
	// HMAC_SHA256 算法
	HMAC_SHA256 SignAlgorithm = "hmac_sha256"
)

// Validator 签名验证器接口
type Validator interface {
	// Validate 验证签名是否有效
	Validate(params map[string]interface{}, signature string) (bool, error)
	// GenerateSignature 生成签名
	GenerateSignature(params map[string]interface{}) (string, error)
}

// Config 签名验证器配置
type Config struct {
	// Secret 密钥
	Secret string
	// Algorithm 签名算法
	Algorithm SignAlgorithm
	// SignatureKey 签名参数名
	SignatureKey string
	// IgnoreKeys 在签名计算中忽略的参数名列表
	IgnoreKeys []string
	// UpperCase 签名是否使用大写
	UpperCase bool
}

// SignValidator 签名验证器实现
type SignValidator struct {
	config Config
}

// NewSignValidator 创建新的签名验证器
func NewSignValidator(config Config) *SignValidator {
	// 如果没有指定签名参数名，默认为 "sign"
	if config.SignatureKey == "" {
		config.SignatureKey = "sign"
	}

	// 如果没有指定算法，默认为 MD5
	if config.Algorithm == "" {
		config.Algorithm = SHA256
	}

	return &SignValidator{
		config: config,
	}
}

// Validate 验证签名是否有效
func (v *SignValidator) Validate(params map[string]interface{}, signature string) (bool, error) {
	expectedSign, err := v.GenerateSignature(params)
	if err != nil {
		return false, err
	}

	return expectedSign == signature, nil
}

// GenerateSignature 生成签名
func (v *SignValidator) GenerateSignature(params map[string]interface{}) (string, error) {
	// 创建参数副本，避免修改原始参数
	paramsCopy := make(map[string]interface{})
	for k, v := range params {
		paramsCopy[k] = v
	}

	// 移除签名参数和忽略的参数
	delete(paramsCopy, v.config.SignatureKey)
	for _, key := range v.config.IgnoreKeys {
		delete(paramsCopy, key)
	}

	// 按键排序
	keys := make([]string, 0, len(paramsCopy))
	for k := range paramsCopy {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// 构建待签名字符串
	var builder strings.Builder
	for i, key := range keys {
		if i > 0 {
			builder.WriteString("&")
		}
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(convertToString(paramsCopy[key]))
	}

	// 如果有密钥，添加到字符串末尾
	if v.config.Secret != "" {
		builder.WriteString("&key=")
		builder.WriteString(v.config.Secret)
	}

	stringToSign := builder.String()

	// 根据算法计算签名
	var signBytes []byte
	var err error

	switch v.config.Algorithm {
	case MD5:
		signBytes, err = calculateHash(md5.New(), stringToSign)
	case SHA1:
		signBytes, err = calculateHash(sha1.New(), stringToSign)
	case SHA256:
		signBytes, err = calculateHash(sha256.New(), stringToSign)
	case HMAC_MD5:
		signBytes, err = calculateHMAC(md5.New, []byte(v.config.Secret), stringToSign)
	case HMAC_SHA1:
		signBytes, err = calculateHMAC(sha1.New, []byte(v.config.Secret), stringToSign)
	case HMAC_SHA256:
		signBytes, err = calculateHMAC(sha256.New, []byte(v.config.Secret), stringToSign)
	default:
		return "", fmt.Errorf("不支持的签名算法: %s", v.config.Algorithm)
	}

	if err != nil {
		return "", err
	}

	// 转换为十六进制字符串
	signature := hex.EncodeToString(signBytes)

	// 根据配置转换大小写
	if v.config.UpperCase {
		signature = strings.ToUpper(signature)
	} else {
		signature = strings.ToLower(signature)
	}

	return signature, nil
}

// ValidateWithSignInParams 从参数中提取签名并验证
func (v *SignValidator) ValidateWithSignInParams(params map[string]interface{}) (bool, error) {
	signValue, exists := params[v.config.SignatureKey]
	if !exists {
		return false, errors.New("签名参数不存在")
	}

	signature, ok := signValue.(string)
	if !ok {
		return false, errors.New("签名参数不是字符串类型")
	}

	return v.Validate(params, signature)
}

// 计算哈希值
func calculateHash(h hash.Hash, data string) ([]byte, error) {
	_, err := h.Write([]byte(data))
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// 计算HMAC值
func calculateHMAC(hashFunc func() hash.Hash, key []byte, data string) ([]byte, error) {
	h := hmac.New(hashFunc, key)
	_, err := h.Write([]byte(data))
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// convertToString 将任意类型转换为字符串
func convertToString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%.6f", v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	case nil:
		return ""
	default:
		// 尝试使用 JSON 序列化复杂类型
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(jsonBytes)
	}
}
