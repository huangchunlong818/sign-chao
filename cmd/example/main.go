package main

import (
	"fmt"

	"github.com/yourusername/signature-validator/pkg/signvalidator"
)

func main() {
	// 创建签名验证器配置
	config := signvalidator.Config{
		Secret:       "mySecretKey",
		Algorithm:    signvalidator.MD5,
		SignatureKey: "sign",
		IgnoreKeys:   []string{"timestamp"},
		UpperCase:    true,
	}

	// 创建签名验证器
	validator := signvalidator.NewSignValidator(config)

	// 模拟请求参数 - 使用不同类型的值
	params := map[string]interface{}{
		"user_id":    12345,
		"product_id": "67890",
		"amount":     99.99,
		"is_vip":     true,
		"items":      []string{"item1", "item2"},
		"timestamp":  "1634567890",
	}

	// 生成签名
	signature, err := validator.GenerateSignature(params)
	if err != nil {
		fmt.Printf("生成签名失败: %v\n", err)
		return
	}

	fmt.Printf("生成的签名: %s\n", signature)

	// 添加签名到参数中
	params["sign"] = signature

	// 验证签名
	valid, err := validator.ValidateWithSignInParams(params)
	if err != nil {
		fmt.Printf("验证签名失败: %v\n", err)
		return
	}

	if valid {
		fmt.Println("签名验证成功!")
	} else {
		fmt.Println("签名验证失败!")
	}

	// 修改参数后再次验证
	params["amount"] = 100.00
	valid, err = validator.ValidateWithSignInParams(params)
	if err != nil {
		fmt.Printf("验证签名失败: %v\n", err)
		return
	}

	if valid {
		fmt.Println("修改参数后签名验证成功 (这不应该发生)")
	} else {
		fmt.Println("修改参数后签名验证失败 (这是预期的)")
	}
}
