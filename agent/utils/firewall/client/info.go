package client

type FireInfo struct {
	ID       uint   `json:"id"`
	Chain    string `json:"chain"`
	Family   string `json:"family"`  // ipv4 ipv6
	Address  string `json:"address"` // Anywhere
	Port     string `json:"port"`
	Protocol string `json:"protocol"` // tcp udp tcp/udp
	Strategy string `json:"strategy"` // accept drop

	Num        string `json:"num"`
	TargetIP   string `json:"targetIP"`
	TargetPort string `json:"targetPort"`
	Interface  string `json:"interface"`

	UsedStatus    string `json:"usedStatus"`
	Description   string `json:"description"`
	ApplyToDocker bool   `json:"applyToDocker"` // 该规则是否已落地到 1PANEL_DOCKER（列表回显，由 SearchWithPage 计算）
}

type Forward struct {
	Num        string `json:"num"`
	Protocol   string `json:"protocol"`
	Port       string `json:"port"`
	TargetIP   string `json:"targetIP"`
	TargetPort string `json:"targetPort"`
	Interface  string `json:"interface"`
}
