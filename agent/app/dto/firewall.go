package dto

type FirewallBaseInfo struct {
	Name       string `json:"name"`
	Mode       string `json:"mode"` // managed | external
	IsExist    bool   `json:"isExist"`
	IsActive   bool   `json:"isActive"`
	IsInit     bool   `json:"isInit"`
	IsBind     bool   `json:"isBind"`
	Version    string `json:"version"`
	PingStatus string `json:"pingStatus"`

	Capabilities FirewallCapabilities `json:"capabilities"`
	Conflict     FirewallConflict     `json:"conflict"`

	BootStatus string `json:"bootStatus"` // ok | degraded:<reason> | failed:<reason>
	Consistent bool   `json:"consistent"`

	StrictMode bool `json:"strictMode"` // 白名单（严格）模式：未列出端口默认拒绝（AFTER 链已注入 DROP）
}

type FirewallCapabilities struct {
	Rules       bool   `json:"rules"`
	Forward     bool   `json:"forward"`
	ForwardImpl string `json:"forwardImpl"`
	Filter      bool   `json:"filter"`
	Baseline    bool   `json:"baseline"`
	Snapshot    string `json:"snapshot"`
	IPv6Rules   bool   `json:"ipv6Rules"`
	DefaultDrop bool   `json:"defaultDrop"`
}

type FirewallConflict struct {
	HasConflict bool     `json:"hasConflict"`
	Providers   []string `json:"providers"`
	Message     string   `json:"message"`
}

type RuleSearch struct {
	PageInfo
	Info     string `json:"info"`
	Status   string `json:"status"`
	Strategy string `json:"strategy"`
	Type     string `json:"type" validate:"required"`
}

type FirewallOperation struct {
	Operation         string `json:"operation" validate:"required,oneof=start stop restart disableBanPing enableBanPing"`
	WithDockerRestart bool   `json:"withDockerRestart"`
}

type PortRuleOperate struct {
	ID        uint   `json:"id"`
	Operation string `json:"operation" validate:"required,oneof=add remove"`
	Chain     string `json:"chain"`
	Address   string `json:"address"`
	Port      string `json:"port" validate:"required"`
	Protocol  string `json:"protocol" validate:"required,oneof=tcp udp tcp/udp"`
	Strategy  string `json:"strategy" validate:"required,oneof=accept drop"`
	Family    string `json:"family"` // ipv4 | ipv6 | both（空=both，端口规则默认双栈；修 C7）

	Description   string `json:"description"`
	ApplyToDocker bool   `json:"applyToDocker"` // PR-6：同时拦截 Docker 端口流量
}

type ForwardRuleOperate struct {
	ForceDelete bool `json:"forceDelete"`
	Rules       []struct {
		Operation  string `json:"operation" validate:"required,oneof=add remove"`
		Num        string `json:"num"`
		Protocol   string `json:"protocol" validate:"required,oneof=tcp udp tcp/udp"`
		Interface  string `json:"interface"`
		Port       string `json:"port" validate:"required"`
		TargetIP   string `json:"targetIP"`
		TargetPort string `json:"targetPort" validate:"required"`
	} `json:"rules"`
}

type UpdateFirewallDescription struct {
	Type     string `json:"type"`
	Chain    string `json:"chain"`
	SrcIP    string `json:"srcIP"`
	DstIP    string `json:"dstIP"`
	SrcPort  string `json:"srcPort"`
	DstPort  string `json:"dstPort"`
	Protocol string `json:"protocol"`
	Strategy string `json:"strategy" validate:"required,oneof=accept drop"`
	Family   string `json:"family"` // item1：保留真实 family，避免描述指纹错位（空=ipv4）

	Description string `json:"description"`
}

type AddrRuleOperate struct {
	ID        uint   `json:"id"`
	Operation string `json:"operation" validate:"required,oneof=add remove"`
	Address   string `json:"address"  validate:"required"`
	Strategy  string `json:"strategy" validate:"required,oneof=accept drop"`
	Family    string `json:"family"` // 空=按地址自动判定族（修 C7）

	Description   string `json:"description"`
	ApplyToDocker bool   `json:"applyToDocker"` // PR-6：同时拦截 Docker 端口流量
}

type PortRuleUpdate struct {
	OldRule PortRuleOperate `json:"oldRule"`
	NewRule PortRuleOperate `json:"newRule"`
}

type AddrRuleUpdate struct {
	OldRule AddrRuleOperate `json:"oldRule"`
	NewRule AddrRuleOperate `json:"newRule"`
}

type BatchRuleOperate struct {
	Type  string            `json:"type" validate:"required"`
	Rules []PortRuleOperate `json:"rules"`
}

type IptablesOp struct {
	Name    string `json:"name" validate:"required,oneof=1PANEL_INPUT 1PANEL_OUTPUT 1PANEL_BASIC 1PANEL_FORWARD"`
	Operate string `json:"operate" validate:"required,oneof=init-base init-forward init-advance bind-base unbind-base bind unbind enable-strict disable-strict"`
}

type IptablesRuleOp struct {
	Operation   string `json:"operation" validate:"required,oneof=add remove"`
	ID          uint   `json:"id"`
	Chain       string `json:"chain" validate:"required,oneof=1PANEL_BASIC 1PANEL_BASIC_BEFORE 1PANEL_INPUT 1PANEL_OUTPUT"`
	Protocol    string `json:"protocol"`
	SrcIP       string `json:"srcIP"`
	SrcPort     uint   `json:"srcPort"`
	DstIP       string `json:"dstIP"`
	DstPort     uint   `json:"dstPort"`
	Strategy    string `json:"strategy" validate:"required,oneof=accept drop reject"`
	Description string `json:"description"`
}

type IptablesBatchOperate struct {
	Rules []IptablesRuleOp `json:"rules"`
}

type IptablesChainStatus struct {
	IsBind          bool   `json:"isBind"`
	DefaultStrategy string `json:"defaultStrategy"`
}

type FirewallSessionChange struct {
	Summary string `json:"summary"`
	At      string `json:"at"`
}

type FirewallSessionInfo struct {
	Active        bool                    `json:"active"`
	Changes       []FirewallSessionChange `json:"changes"`
	RemainSeconds int                     `json:"remainSeconds"`
	Since         string                  `json:"since"`
	Snapshot      string                  `json:"snapshot"`
}

type FirewallSnapshot struct {
	Name      string `json:"name"`
	Tag       string `json:"tag"`
	CreatedAt string `json:"createdAt"`
	HasV6     bool   `json:"hasV6"`
	Size      int64  `json:"size"`
}

type FirewallSnapshotRestore struct {
	Name string `json:"name" validate:"required"`
}

type FirewallDockerRule struct {
	Address  string `json:"address"`
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
	Strategy string `json:"strategy"`
}

type FirewallDockerStatus struct {
	Available bool                 `json:"available"`
	Rules     []FirewallDockerRule `json:"rules"`
}

// PanelPortUpdate 面板端口变更（PR-8 单写者）：core 委托 agent 放行新端口，只增不删（修 C2）。
type PanelPortUpdate struct {
	Port string `json:"port" validate:"required"`
}
