// Package wardn 为应用提供 Wardn OIDC 登录及一致的身份资料规则。
// 本包不创建本地业务账号，不存储密码，不根据邮箱合并身份。
package wardn

import (
	"crypto/sha256"
	"encoding/hex"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
)

var opaqueID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Claims 兼容 Wardn 原生和标准 OIDC 字段；必须来自已经验证的令牌。
type Claims struct {
	Subject           string `json:"sub"`
	Name              string `json:"name"`
	DisplayName       string `json:"displayName"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	NativeVerified    *bool  `json:"emailVerified"`
	Owner             string `json:"owner"`
	AuthorizedParty   string `json:"azp"`
	NotBefore         int64  `json:"nbf"`
}

// VerifiedEmail 只返回明确验证且格式合法的邮箱；两种验证字段冲突时拒绝。
func (c Claims) VerifiedEmail() string {
	if c.EmailVerified != nil && c.NativeVerified != nil && *c.EmailVerified != *c.NativeVerified {
		return ""
	}
	verified := c.EmailVerified != nil && *c.EmailVerified || c.NativeVerified != nil && *c.NativeVerified
	if !verified {
		return ""
	}
	email := strings.TrimSpace(c.Email)
	a, err := mail.ParseAddress(email)
	if err != nil || a.Address != email || !validLabel(email) {
		return ""
	}
	return email
}

// AccountName 返回私有账号名称。UUID、sub、邮箱形状的未验证 name 不作昵称。
// 没有可读昵称或已验证邮箱时返回空，由应用提供本地化的通用名称。
func (c Claims) AccountName() string {
	for _, raw := range []string{c.DisplayName, c.Name, c.PreferredUsername} {
		name := strings.TrimSpace(raw)
		if validLabel(name) && !IsOpaqueName(name, c.Subject) && !strings.Contains(name, "@") {
			return name
		}
	}
	return c.VerifiedEmail()
}

// PublicName 只返回可读昵称，不自动公开完整邮箱或邮箱本地部分。
func (c Claims) PublicName() string {
	name := c.AccountName()
	if strings.Contains(name, "@") {
		return ""
	}
	return name
}

// IsOpaqueName 判断展示名是否为空、UUID 或当前身份的内部 subject。
func IsOpaqueName(name, subject string) bool {
	name = strings.TrimSpace(name)
	return name == "" || opaqueID.MatchString(name) || subject != "" && name == subject
}

func validLabel(name string) bool {
	return name != "" && len(name) <= 100 && !strings.ContainsFunc(name, unicode.IsControl)
}

// Identity 是受验证的不可变身份；应用必须按 Issuer 和 Subject 一起查找绑定。
type Identity struct {
	Issuer  string
	Subject string
	Profile Claims
}

// Key 返回 issuer/sub 的 SHA-256。接入已有应用时必须保留原有键编码与前缀。
func (i Identity) Key() string {
	sum := sha256.Sum256([]byte(i.Issuer + "\x00" + i.Subject))
	return hex.EncodeToString(sum[:])
}
