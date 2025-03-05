package signvalidator

import (
	"testing"
)

func TestSignValidator_MD5(t *testing.T) {
	config := Config{
		Secret:       "testSecret",
		Algorithm:    MD5,
		SignatureKey: "sign",
	}

	validator := NewSignValidator(config)

	params := map[string]interface{}{
		"id":     123,
		"name":   "test",
		"amount": 100.50,
	}

	signature, err := validator.GenerateSignature(params)
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	// 验证签名
	valid, err := validator.Validate(params, signature)
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	if !valid {
		t.Errorf("签名验证失败")
	}

	// 测试无效签名
	valid, err = validator.Validate(params, signature+"invalid")
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	if valid {
		t.Errorf("无效签名验证应该失败，但通过了")
	}
}

func TestSignValidator_HMAC_SHA256(t *testing.T) {
	config := Config{
		Secret:       "testSecret",
		Algorithm:    HMAC_SHA256,
		SignatureKey: "sign",
		UpperCase:    true,
	}

	validator := NewSignValidator(config)

	params := map[string]interface{}{
		"id":     123,
		"name":   "test",
		"amount": 100.50,
		"sign":   "should_be_ignored",
	}

	signature, err := validator.GenerateSignature(params)
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	// 验证签名
	paramsWithSign := make(map[string]interface{})
	for k, v := range params {
		paramsWithSign[k] = v
	}
	paramsWithSign["sign"] = signature

	valid, err := validator.ValidateWithSignInParams(paramsWithSign)
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	if !valid {
		t.Errorf("签名验证失败")
	}
}

func TestSignValidator_IgnoreKeys(t *testing.T) {
	config := Config{
		Secret:       "testSecret",
		Algorithm:    SHA1,
		SignatureKey: "sign",
		IgnoreKeys:   []string{"timestamp", "nonce"},
	}

	validator := NewSignValidator(config)

	params := map[string]interface{}{
		"id":        123,
		"name":      "test",
		"amount":    100.50,
		"timestamp": "1634567890",
		"nonce":     "random_string",
	}

	signature, err := validator.GenerateSignature(params)
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	// 修改被忽略的参数不应影响签名验证
	paramsModified := make(map[string]interface{})
	for k, v := range params {
		paramsModified[k] = v
	}
	paramsModified["timestamp"] = "9999999999"
	paramsModified["nonce"] = "different_random_string"

	valid, err := validator.Validate(paramsModified, signature)
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	if !valid {
		t.Errorf("签名验证失败")
	}

	// 修改非忽略参数应导致验证失败
	paramsModified["amount"] = 200.00

	valid, err = validator.Validate(paramsModified, signature)
	if err != nil {
		t.Fatalf("生成签名失败: %v", err)
	}

	if valid {
		t.Errorf("签名验证应该失败，但通过了")
	}
}

func TestConvertToString(t *testing.T) {
	testCases := []struct {
		input    interface{}
		expected string
	}{
		{123, "123"},
		{123.456, "123.456000"},
		{"test", "test"},
		{true, "true"},
		{false, "false"},
		{nil, ""},
		{[]string{"a", "b"}, `["a","b"]`},
		{map[string]int{"a": 1, "b": 2}, `{"a":1,"b":2}`},
	}

	for _, tc := range testCases {
		result := convertToString(tc.input)
		if result != tc.expected {
			t.Errorf("convertToString(%v) = %s, 期望 %s", tc.input, result, tc.expected)
		}
	}
}
