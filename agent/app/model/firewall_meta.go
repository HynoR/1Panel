package model

import "time"

// FirewallRuleMeta 按指纹关联规则的元数据（描述/来源），替代 firewalls 表"按元组裸匹配"的脆弱方式（修 C3）。
// 同一条语义规则在重启前后、在 DB 与系统间指纹恒定，描述不再随规则漂移而丢失，更不会被自动删除。
type FirewallRuleMeta struct {
	BaseModel
	Fingerprint string `gorm:"uniqueIndex;not null" json:"fingerprint"`
	Kind        string `json:"kind"`                       // port | address | forward | filter | docker
	Family      string `gorm:"default:ipv4" json:"family"` // ipv4 | ipv6 | both
	Description string `json:"description"`
	Source      string `gorm:"default:panel" json:"source"` // panel | system | legacy
}

// FirewallState 单行状态表：记录最近一次开机自检与一致性校验结果，供 /firewall/base 横幅展示。
type FirewallState struct {
	BaseModel
	Mode           string    `json:"mode"`
	Provider       string    `json:"provider"`
	LastBootStatus string    `json:"lastBootStatus"` // ok | degraded:<reason> | failed:<reason>
	LastBootAt     time.Time `json:"lastBootAt"`
	Consistent     bool      `json:"consistent"`
	LastCheckAt    time.Time `json:"lastCheckAt"`
}
