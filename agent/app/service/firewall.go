package service

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/buserr"
	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/common"
	"github.com/1Panel-dev/1Panel/agent/utils/controller"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	fireClient "github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
	"github.com/jinzhu/copier"
)

type FirewallService struct{}

type IFirewallService interface {
	LoadBaseInfo(tab string) (dto.FirewallBaseInfo, error)
	SearchWithPage(search dto.RuleSearch) (int64, interface{}, error)
	OperateFirewall(req dto.FirewallOperation) error
	OperatePortRule(req dto.PortRuleOperate, reload bool) error
	OperateForwardRule(req dto.ForwardRuleOperate) error
	OperateAddressRule(req dto.AddrRuleOperate, reload bool) error
	UpdatePortRule(req dto.PortRuleUpdate) error
	UpdateAddrRule(req dto.AddrRuleUpdate) error
	UpdateDescription(req dto.UpdateFirewallDescription) error
	BatchOperateRule(req dto.BatchRuleOperate) error
	CleanOrphanFirewallRecords() error
	UpdatePanelPort(req dto.PanelPortUpdate) error

	SessionStatus() dto.FirewallSessionInfo
	ConfirmSession() error
	RevertSession() error
	ListSnapshots() ([]dto.FirewallSnapshot, error)
	RestoreSnapshot(req dto.FirewallSnapshotRestore) error
	DockerStatus() dto.FirewallDockerStatus
}

func NewIFirewallService() IFirewallService {
	return &FirewallService{}
}

func (u *FirewallService) LoadBaseInfo(tab string) (dto.FirewallBaseInfo, error) {
	var baseInfo dto.FirewallBaseInfo
	baseInfo.Version = "-"
	baseInfo.Name = "-"
	// 用 Detect()（带缓存）而非 NewFirewallClient：即便 ufw+firewalld 冲突也能返回基础信息（修 C11/C12）。
	provider, err := firewall.Detect()
	if err != nil {
		global.LOG.Errorf("load firewall failed, err: %v", err)
		baseInfo.IsExist = false
		return baseInfo, nil
	}
	baseInfo.IsExist = true
	baseInfo.Name = provider.Name()
	baseInfo.Mode = string(provider.Mode())
	baseInfo.Capabilities = toDtoCapabilities(provider.Capabilities())
	baseInfo.Conflict = toDtoConflict(provider.Conflict())
	if state, stateErr := hostRepo.GetFirewallState(); stateErr == nil {
		baseInfo.BootStatus = state.LastBootStatus
		baseInfo.Consistent = state.Consistent
	}
	client := provider.Client()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		baseInfo.PingStatus = firewall.LoadPingStatus()
		baseInfo.Version, _ = client.Version()
	}()
	go func() {
		defer wg.Done()
		baseInfo.IsActive, _ = client.Status()
		// 修 C4：init/bind 状态只在 managed（iptables 私有链）下才有意义。
		// 例外：ufw 的端口转发用面板 NAT 链实现（forwardImpl=panel-nat），forward tab 仍要按
		// LoadInitStatus 暴露 init/bind——否则新机上 1PANEL_PREROUTING/1PANEL_FORWARD 尚未建立，
		// 却误报已初始化、隐藏了初始化入口，导致转发列表/新建失败（评审 P2）。
		if provider.Mode() == firewall.ModeManaged ||
			(tab == "forward" && provider.Capabilities().ForwardImpl == "panel-nat") {
			baseInfo.IsInit, baseInfo.IsBind = iptables.LoadInitStatus(baseInfo.Name, tab)
		} else {
			baseInfo.IsInit, baseInfo.IsBind = true, true
		}
		// 白名单（严格）模式：仅 managed 下读 AFTER 链是否已注入 DROP（真实状态，替代旧的读 1PANEL_INPUT）。
		if provider.Mode() == firewall.ModeManaged {
			baseInfo.StrictMode = isStrictMode()
		}
	}()
	wg.Wait()
	return baseInfo, nil
}

func toDtoCapabilities(c firewall.Capabilities) dto.FirewallCapabilities {
	return dto.FirewallCapabilities{
		Rules:       c.Rules,
		Forward:     c.Forward,
		ForwardImpl: c.ForwardImpl,
		Filter:      c.Filter,
		Baseline:    c.Baseline,
		Snapshot:    c.Snapshot,
		IPv6Rules:   c.IPv6Rules,
		DefaultDrop: c.DefaultDrop,
	}
}

func toDtoConflict(c firewall.ConflictState) dto.FirewallConflict {
	return dto.FirewallConflict{
		HasConflict: c.HasConflict,
		Providers:   c.Providers,
		Message:     c.Message,
	}
}

func (u *FirewallService) SearchWithPage(req dto.RuleSearch) (int64, interface{}, error) {
	var (
		datas     []fireClient.FireInfo
		backDatas []fireClient.FireInfo
	)

	client, err := firewall.NewFirewallClient()
	if err != nil {
		return 0, nil, err
	}

	var rules []fireClient.FireInfo
	switch req.Type {
	case "port":
		rules, err = client.ListPort()
	case "forward":
		rules, err = client.ListForward()
	case "address":
		rules, err = client.ListAddress()
	}
	if err != nil {
		return 0, nil, err
	}

	if len(req.Info) != 0 {
		for _, addr := range rules {
			if strings.Contains(addr.Address, req.Info) ||
				strings.Contains(addr.Port, req.Info) ||
				strings.Contains(addr.TargetPort, req.Info) ||
				strings.Contains(addr.TargetIP, req.Info) {
				datas = append(datas, addr)
			}
		}
	} else {
		datas = rules
	}
	if req.Type == "port" {
		apps := u.loadPortByApp()
		for i := 0; i < len(datas); i++ {
			datas[i].UsedStatus = checkPortUsed(datas[i].Port, datas[i].Protocol, apps)
		}
	}

	var datasFilterStrategy []fireClient.FireInfo
	if len(req.Strategy) != 0 {
		for _, data := range datas {
			if req.Strategy == data.Strategy {
				datasFilterStrategy = append(datasFilterStrategy, data)
			}
		}
	} else {
		datasFilterStrategy = datas
	}

	total, start, end := len(datasFilterStrategy), (req.Page-1)*req.PageSize, req.Page*req.PageSize
	if start > total {
		backDatas = make([]fireClient.FireInfo, 0)
	} else {
		if end >= total {
			end = total
		}
		backDatas = datasFilterStrategy[start:end]
	}

	datasFromDB, _ := hostRepo.ListFirewallRecord()
	for i := 0; i < len(backDatas); i++ {
		for _, des := range datasFromDB {
			if req.Type != des.Type {
				continue
			}
			if backDatas[i].Port == des.DstPort &&
				req.Type == "port" &&
				backDatas[i].Protocol == des.Protocol &&
				backDatas[i].Strategy == des.Strategy &&
				backDatas[i].Address == des.SrcIP {
				backDatas[i].ID = des.ID
				backDatas[i].Description = des.Description
				break
			}
			if req.Type == "address" && backDatas[i].Strategy == des.Strategy && backDatas[i].Address == des.SrcIP {
				backDatas[i].ID = des.ID
				backDatas[i].Description = des.Description
				break
			}
		}
	}

	// 补充：对仍缺描述的项，按指纹从 meta 表回填（比元组裸匹配更稳健）。
	// 注意：不再异步静默删除任何"漂移"记录——这正是 C3 的索引 bug + 描述丢失根源。
	if req.Type == "port" || req.Type == "address" {
		metaMap := u.loadFirewallMetaMap()
		for i := 0; i < len(backDatas); i++ {
			if backDatas[i].Description != "" {
				continue
			}
			fp := firewall.Fingerprint(firewallRuleKeyFromInfo(req.Type, backDatas[i]))
			if desc, ok := metaMap[fp]; ok {
				backDatas[i].Description = desc
			}
		}
		// item1：回显 applyToDocker——复用 1PANEL_DOCKER 的匹配逻辑（port: port+protocol+strategy+归一化地址；address: address+strategy）。
		_, dockerRules := firewall.DockerStatus()
		for i := 0; i < len(backDatas); i++ {
			backDatas[i].ApplyToDocker = firewall.IsDockerProtected(req.Type, backDatas[i].Port, backDatas[i].Protocol, backDatas[i].Strategy, backDatas[i].Address, dockerRules)
		}
	}

	return int64(total), backDatas, nil
}

func (u *FirewallService) loadFirewallMetaMap() map[string]string {
	metas, _ := hostRepo.ListFirewallMeta()
	result := make(map[string]string, len(metas))
	for _, item := range metas {
		if item.Description != "" {
			result[item.Fingerprint] = item.Description
		}
	}
	return result
}

func firewallRuleKeyFromInfo(ruleType string, info fireClient.FireInfo) firewall.RuleKey {
	family := info.Family
	if family == "" {
		family = "ipv4"
	}
	if ruleType == "address" {
		return firewall.RuleKey{Family: family, Scope: "input", Kind: "address", Action: info.Strategy, SrcIP: info.Address}
	}
	return firewall.RuleKey{Family: family, Scope: "input", Kind: "port", Action: info.Strategy, Protocol: info.Protocol, SrcIP: info.Address, DstPort: info.Port}
}

// fingerprintFamily 计算写入指纹用的 family，须与列表回读（firewallRuleKeyFromInfo 用 info.Family）一致。
// iptables managed 模式下端口规则按用户选择的 family（默认 both）落盘并双栈镜像写；地址规则族由地址本身决定（RichRules 按地址覆写）。
// 外部模式（ufw/firewalld）列表回读 family 固定 ipv4，故写指纹亦用 ipv4，避免读写错位致描述丢失（item1）。
func fingerprintFamily(clientName, kind, reqFamily, address string) string {
	if clientName == "iptables" {
		if kind == "address" {
			if strings.Contains(address, ":") {
				return "ipv6"
			}
			return "ipv4"
		}
		f := strings.ToLower(strings.TrimSpace(reqFamily))
		if f == "ipv4" || f == "ipv6" || f == "both" {
			return f
		}
		return "both"
	}
	return "ipv4"
}

// familyOrDefault 用于描述更新指纹：前端传入的即列表行真实 family（= info.Family），空则回退 ipv4。
func familyOrDefault(f string) string {
	f = strings.ToLower(strings.TrimSpace(f))
	if f == "ipv4" || f == "ipv6" || f == "both" {
		return f
	}
	return "ipv4"
}

func (u *FirewallService) OperateFirewall(req dto.FirewallOperation) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	needRestartDocker := false
	switch req.Operation {
	case "start":
		if err := client.Start(); err != nil {
			return err
		}
		firewall.InvalidateProbe()
		if err := u.addPortsBeforeStart(client); err != nil {
			_ = client.Stop()
			return err
		}
		needRestartDocker = true
	case "stop":
		if err := client.Stop(); err != nil {
			return err
		}
		firewall.InvalidateProbe()
		needRestartDocker = true
	case "restart":
		if err := client.Restart(); err != nil {
			return err
		}
		firewall.InvalidateProbe()
		if err := u.addPortsBeforeStart(client); err != nil {
			return err
		}
		needRestartDocker = true
	case "disableBanPing":
		if err := firewall.UpdatePingStatus("0"); err != nil {
			return err
		}
		_ = settingRepo.Update("BanPing", constant.StatusDisable)
		return nil
	case "enableBanPing":
		if err := firewall.UpdatePingStatus("1"); err != nil {
			return err
		}
		_ = settingRepo.Update("BanPing", constant.StatusEnable)
		return nil
	default:
		return fmt.Errorf("not supported operation: %s", req.Operation)
	}
	if needRestartDocker && req.WithDockerRestart {
		if err := controller.HandleRestart("docker"); err != nil {
			return fmt.Errorf("failed to restart Docker: %v", err)
		}
	}
	return nil
}

func (u *FirewallService) OperatePortRule(req dto.PortRuleOperate, reload bool) (retErr error) {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	mode := firewallMode()
	if len(req.Chain) == 0 && client.Name() == "iptables" {
		// accept → ALLOW；drop → DENY（黑名单先于放行，修 C6/#12897）。
		req.Chain = iptables.Chain1PanelAllow
		if req.Strategy == "drop" {
			req.Chain = iptables.Chain1PanelDeny
		}
	}
	// L1 红线预检 + L3 提交-确认会话（设计稿 §3.5）。
	if err := precheckPortRule(req); err != nil {
		return err
	}
	needsConfirm := portChangeNeedsConfirm(req)
	if mode == firewall.ModeExternal && needsConfirm {
		return buserr.New("ErrFirewallBlockRescue")
	}
	sessionWasActive := false
	sessionArmed := false
	applied := false
	if mode == firewall.ModeManaged && needsConfirm {
		sessionWasActive = firewall.SessionStatus().Active
		if err := firewall.BeginSession(fmt.Sprintf("port %s %s/%s %s", req.Operation, req.Port, req.Protocol, req.Strategy)); err != nil {
			return err
		}
		sessionArmed = true
		defer func() {
			if retErr != nil && sessionArmed && !sessionWasActive && !applied {
				firewall.CancelSession(fmt.Sprintf("port %s %s/%s failed before any rule was applied: %v", req.Operation, req.Port, req.Protocol, retErr))
			}
		}()
	}
	// PR-6：Docker 端口防护与防火墙模式正交，按勾选同步到 1PANEL_DOCKER（用 conntrack 还原原始目的端口）。
	// 删除时不依赖 applyToDocker（列表行不携带该标记），也不依赖 Docker 当前是否就绪（DOCKER-USER 可能因
	// Docker 临时停机而缺失）：一律尝试清理镜像规则并重写持久化文件，避免 Docker 恢复后 LoadDockerRules
	// 重放陈旧 DROP 致已发布端口持续被封（评审 P2）。Apply* 内部对"链不存在"幂等 no-op。
	if req.Strategy == "drop" && (req.Operation == "remove" || (req.ApplyToDocker && firewall.DockerProtectionAvailable())) {
		for _, proto := range strings.Split(req.Protocol, "/") {
			for _, port := range strings.Split(req.Port, ",") {
				port = strings.TrimSpace(strings.ReplaceAll(port, "-", ":"))
				if port == "" {
					continue
				}
				for _, addr := range strings.Split(strings.TrimSuffix(req.Address, ","), ",") {
					addr = strings.TrimSpace(addr)
					// ufw 任意源端口行在列表里地址显示为 "Anywhere"/"Anywhere (v6)"，而创建时镜像的
					// 1PANEL_DOCKER 规则用的是空源；删除若把 "Anywhere" 当 -s 源会匹配不上 →
					// 残留 Docker DROP 致已发布端口持续被封（评审 P2）。归一化为空源再清理。
					if strings.HasPrefix(addr, "Anywhere") {
						addr = ""
					}
					if err := firewall.ApplyDockerPortRule(port, proto, addr, req.Operation); err != nil {
						global.LOG.Warnf("apply docker port rule %s/%s failed: %v", port, proto, err)
					} else {
						applied = true
					}
				}
			}
		}
	}
	protos := strings.Split(req.Protocol, "/")
	itemAddress := strings.Split(strings.TrimSuffix(req.Address, ","), ",")

	if client.Name() == "ufw" {
		if strings.Contains(req.Port, ",") || strings.Contains(req.Port, "-") {
			for _, proto := range protos {
				for _, addr := range itemAddress {
					if len(addr) == 0 {
						addr = "Anywhere"
					}
					req.Address = addr
					req.Port = strings.ReplaceAll(req.Port, "-", ":")
					req.Protocol = proto
					if err := u.operatePort(client, req); err != nil {
						return err
					}
					applied = true
					req.Port = strings.ReplaceAll(req.Port, ":", "-")
					if err := u.addPortRecord(client.Name(), req); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for _, addr := range itemAddress {
			if len(addr) == 0 {
				addr = "Anywhere"
			}
			if req.Protocol == "tcp/udp" {
				req.Protocol = ""
			}
			req.Address = addr
			if err := u.operatePort(client, req); err != nil {
				return err
			}
			applied = true
			if len(req.Protocol) == 0 {
				req.Protocol = "tcp/udp"
			}
			if err := u.addPortRecord(client.Name(), req); err != nil {
				return err
			}
		}
		return nil
	}

	itemPorts := req.Port
	for _, proto := range protos {
		if strings.Contains(req.Port, "-") {
			for _, addr := range itemAddress {
				req.Protocol = proto
				req.Address = addr
				if err := u.operatePort(client, req); err != nil {
					return err
				}
				applied = true
				if err := u.addPortRecord(client.Name(), req); err != nil {
					return err
				}
			}
		} else {
			ports := strings.Split(itemPorts, ",")
			for _, port := range ports {
				if len(port) == 0 {
					continue
				}
				for _, addr := range itemAddress {
					req.Address = addr
					req.Port = port
					req.Protocol = proto
					if err := u.operatePort(client, req); err != nil {
						return err
					}
					applied = true
					if err := u.addPortRecord(client.Name(), req); err != nil {
						return err
					}
				}
			}
		}
	}

	if reload {
		return client.Reload()
	}
	return nil
}

// normalizeForwardInterface 规整转发规则的入站接口："*" 与空串语义相同（均表示"所有接口"）。
// iptables -nvL 对未指定 -i 的规则回显 "*"，而前端/请求侧用空串表示"所有接口"；
// 判重与删除比对前统一映射为空串，避免同一"所有接口"规则因取值不一致而漏判。
func normalizeForwardInterface(iface string) string {
	if iface == "*" {
		return ""
	}
	return iface
}

func (u *FirewallService) OperateForwardRule(req dto.ForwardRuleOperate) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}

	rules, _ := client.ListForward()
	i := 0
	for _, rule := range rules {
		shouldKeep := true
		for i := range req.Rules {
			reqRule := &req.Rules[i]
			if reqRule.TargetIP == "" {
				reqRule.TargetIP = "127.0.0.1"
			}

			if reqRule.Operation == "remove" {
				for _, proto := range strings.Split(reqRule.Protocol, "/") {
					if reqRule.Port == rule.Port &&
						reqRule.TargetPort == rule.TargetPort &&
						reqRule.TargetIP == rule.TargetIP &&
						proto == rule.Protocol &&
						normalizeForwardInterface(reqRule.Interface) == normalizeForwardInterface(rule.Interface) {
						shouldKeep = false
						break
					}
				}
			}
		}
		if shouldKeep {
			rules[i] = rule
			i++
		}
	}
	rules = rules[:i]

	for _, rule := range rules {
		for _, reqRule := range req.Rules {
			if reqRule.Operation == "remove" {
				continue
			}

			for _, proto := range strings.Split(reqRule.Protocol, "/") {
				if reqRule.Port == rule.Port &&
					reqRule.TargetPort == rule.TargetPort &&
					reqRule.TargetIP == rule.TargetIP &&
					proto == rule.Protocol &&
					normalizeForwardInterface(reqRule.Interface) == normalizeForwardInterface(rule.Interface) {
					return buserr.New("ErrRecordExist")
				}
			}
		}
	}

	sort.SliceStable(req.Rules, func(i, j int) bool {
		if req.Rules[i].Operation == "remove" && req.Rules[j].Operation != "remove" {
			return true
		}
		if req.Rules[i].Operation != "remove" && req.Rules[j].Operation == "remove" {
			return false
		}
		n1, _ := strconv.Atoi(req.Rules[i].Num)
		n2, _ := strconv.Atoi(req.Rules[j].Num)
		return n1 > n2
	})

	for _, r := range req.Rules {
		for _, p := range strings.Split(r.Protocol, "/") {
			if r.TargetIP == "" {
				r.TargetIP = "127.0.0.1"
			}
			if err = client.PortForward(fireClient.Forward{
				Num:        r.Num,
				Protocol:   p,
				Port:       r.Port,
				TargetIP:   r.TargetIP,
				TargetPort: r.TargetPort,
				Interface:  r.Interface,
			}, r.Operation); err != nil {
				if req.ForceDelete {
					global.LOG.Error(err)
					continue
				}
				return err
			}
		}
	}
	return nil
}

func (u *FirewallService) OperateAddressRule(req dto.AddrRuleOperate, reload bool) (retErr error) {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	mode := firewallMode()
	chain := ""
	if client.Name() == "iptables" {
		// accept → ALLOW；drop → DENY（黑名单先于放行，修 C6/#12897）。
		chain = iptables.Chain1PanelAllow
		if req.Strategy == "drop" {
			chain = iptables.Chain1PanelDeny
		}
	}
	// L1 红线预检 + L3 提交-确认会话（设计稿 §3.5）。
	if err := precheckAddressRule(req); err != nil {
		return err
	}
	needsConfirm := addressChangeNeedsConfirm(req)
	if mode == firewall.ModeExternal && needsConfirm {
		return buserr.New("ErrFirewallBlockSelf")
	}
	sessionWasActive := false
	sessionArmed := false
	applied := false
	if mode == firewall.ModeManaged && needsConfirm {
		sessionWasActive = firewall.SessionStatus().Active
		if err := firewall.BeginSession(fmt.Sprintf("ip %s %s %s", req.Operation, req.Address, req.Strategy)); err != nil {
			return err
		}
		sessionArmed = true
		defer func() {
			if retErr != nil && sessionArmed && !sessionWasActive && !applied {
				firewall.CancelSession(fmt.Sprintf("ip %s %s failed before any rule was applied: %v", req.Operation, req.Address, retErr))
			}
		}()
	}
	var fireInfo fireClient.FireInfo
	if err := copier.Copy(&fireInfo, &req); err != nil {
		return err
	}

	addressList := strings.Split(req.Address, ",")
	for i := 0; i < len(addressList); i++ {
		if len(addressList[i]) == 0 {
			continue
		}
		fireInfo.Address = addressList[i]
		if err := client.RichRules(fireInfo, req.Operation); err != nil {
			return err
		}
		applied = true
		req.Address = addressList[i]
		if err := u.addAddressRecord(client.Name(), chain, req); err != nil {
			return err
		}
		// PR-6：勾选时把 IP 封禁同步到 Docker（"封掉这个 IP"不应因业务跑在容器里就失效）。
		// 删除时不依赖 applyToDocker（列表行不携带该标记），也不依赖 Docker 当前是否就绪：一律尝试清理
		// 镜像规则并重写持久化文件，避免 Docker 恢复后重放陈旧 DROP（评审 P2）。内部对"链不存在"幂等 no-op。
		if req.Strategy == "drop" && (req.Operation == "remove" || (req.ApplyToDocker && firewall.DockerProtectionAvailable())) {
			if err := firewall.ApplyDockerIPRule(addressList[i], req.Operation); err != nil {
				global.LOG.Warnf("apply docker ip rule %s failed: %v", addressList[i], err)
			} else {
				applied = true
			}
		}
	}
	if reload {
		return client.Reload()
	}
	return nil
}

func (u *FirewallService) UpdatePortRule(req dto.PortRuleUpdate) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	if err := u.OperatePortRule(req.OldRule, false); err != nil {
		return err
	}
	if err := u.OperatePortRule(req.NewRule, false); err != nil {
		return err
	}
	return client.Reload()
}

func (u *FirewallService) UpdateAddrRule(req dto.AddrRuleUpdate) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	if err := u.OperateAddressRule(req.OldRule, false); err != nil {
		return err
	}
	if err := u.OperateAddressRule(req.NewRule, false); err != nil {
		return err
	}
	return client.Reload()
}

func (u *FirewallService) UpdateDescription(req dto.UpdateFirewallDescription) error {
	record := model.Firewall{
		Type:        req.Type,
		Chain:       req.Chain,
		SrcIP:       req.SrcIP,
		DstIP:       req.DstIP,
		SrcPort:     req.SrcPort,
		DstPort:     req.DstPort,
		Protocol:    req.Protocol,
		Strategy:    req.Strategy,
		Description: req.Description,
	}

	if err := hostRepo.SaveFirewallRecord(&record); err != nil {
		return err
	}
	saveFirewallMeta(firewallRuleKeyFromDescription(req), req.Description)
	return nil
}

func firewallRuleKeyFromDescription(req dto.UpdateFirewallDescription) firewall.RuleKey {
	switch req.Type {
	case "address":
		return firewall.RuleKey{Family: familyOrDefault(req.Family), Scope: "input", Kind: "address", Action: req.Strategy, SrcIP: req.SrcIP}
	case "port":
		return firewall.RuleKey{Family: familyOrDefault(req.Family), Scope: "input", Kind: "port", Action: req.Strategy, Protocol: req.Protocol, SrcIP: req.SrcIP, DstPort: req.DstPort}
	default:
		scope := "input"
		if strings.Contains(strings.ToUpper(req.Chain), "OUTPUT") {
			scope = "output"
		}
		return firewall.RuleKey{Family: "ipv4", Scope: scope, Kind: "filter", Action: req.Strategy, Protocol: req.Protocol, SrcIP: req.SrcIP, SrcPort: req.SrcPort, DstIP: req.DstIP, DstPort: req.DstPort}
	}
}

func (u *FirewallService) BatchOperateRule(req dto.BatchRuleOperate) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	success := 0
	var firstErr error
	for _, rule := range req.Rules {
		var opErr error
		if req.Type == "port" {
			opErr = u.OperatePortRule(rule, false)
		} else {
			itemRule := dto.AddrRuleOperate{Operation: rule.Operation, Address: rule.Address, Strategy: rule.Strategy, Family: rule.Family, ApplyToDocker: rule.ApplyToDocker, CallerIP: req.CallerIP}
			opErr = u.OperateAddressRule(itemRule, false)
		}
		if opErr != nil {
			if firstErr == nil {
				firstErr = opErr
			}
			continue
		}
		success++
	}
	// 存在成功的规则时仍需 Reload 持久化，Reload 失败优先返回其错误。
	if success > 0 {
		if err := client.Reload(); err != nil {
			return err
		}
	}
	if firstErr != nil {
		return buserr.WithMap("ErrFirewallBatchPartial", map[string]interface{}{
			"success": success,
			"failed":  len(req.Rules) - success,
			"reason":  firstErr.Error(),
		}, firstErr)
	}
	return nil
}

func OperateFirewallPort(oldPorts, newPorts []int) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	for _, port := range newPorts {
		if err := client.Port(fireClient.FireInfo{Port: strconv.Itoa(port), Protocol: "tcp", Strategy: "accept"}, "add"); err != nil {
			return err
		}
	}
	for _, port := range oldPorts {
		if err := client.Port(fireClient.FireInfo{Port: strconv.Itoa(port), Protocol: "tcp", Strategy: "accept"}, "remove"); err != nil {
			return err
		}
	}
	return client.Reload()
}

func (u *FirewallService) operatePort(client firewall.FirewallClient, req dto.PortRuleOperate) error {
	var fireInfo fireClient.FireInfo
	if err := copier.Copy(&fireInfo, &req); err != nil {
		return err
	}

	if client.Name() == "ufw" {
		if len(fireInfo.Address) != 0 && !strings.EqualFold(fireInfo.Address, "Anywhere") {
			return client.RichRules(fireInfo, req.Operation)
		}
		return client.Port(fireInfo, req.Operation)
	}

	if len(fireInfo.Address) != 0 || fireInfo.Strategy == "drop" {
		return client.RichRules(fireInfo, req.Operation)
	}
	return client.Port(fireInfo, req.Operation)
}

type portOfApp struct {
	AppName   string
	HttpPort  string
	HttpsPort string
}

func (u *FirewallService) loadPortByApp() []portOfApp {
	var datas []portOfApp
	apps, err := appInstallRepo.ListBy(context.Background())
	if err != nil {
		return datas
	}
	for i := 0; i < len(apps); i++ {
		datas = append(datas, portOfApp{
			AppName:   apps[i].App.Key,
			HttpPort:  strconv.Itoa(apps[i].HttpPort),
			HttpsPort: strconv.Itoa(apps[i].HttpsPort),
		})
	}
	systemPort, err := settingRepo.Get(settingRepo.WithByKey("ServerPort"))
	if err != nil {
		return datas
	}
	datas = append(datas, portOfApp{AppName: "1panel", HttpPort: systemPort.Value})

	return datas
}

func (u *FirewallService) SessionStatus() dto.FirewallSessionInfo {
	info := firewall.SessionStatus()
	result := dto.FirewallSessionInfo{
		Active:        info.Active,
		RemainSeconds: info.RemainSeconds,
		Since:         info.Since,
		Snapshot:      info.Snapshot,
	}
	for _, c := range info.Changes {
		result.Changes = append(result.Changes, dto.FirewallSessionChange{Summary: c.Summary, At: c.At})
	}
	return result
}

func (u *FirewallService) ConfirmSession() error {
	return firewall.ConfirmSession()
}

func (u *FirewallService) RevertSession() error {
	return firewall.RevertSession()
}

// UpdatePanelPort 单写者入口（PR-8）：core 改面板端口时委托 agent 放行新端口，**只增不删**。
// 旧端口的关闭交由后续白名单同步/确认流程处理，消灭"开新失败+删旧成功"的双失联窗口（修 C2）。
func (u *FirewallService) UpdatePanelPort(req dto.PanelPortUpdate) error {
	port := strings.TrimSpace(req.Port)
	if port == "" {
		return fmt.Errorf("panel port is required")
	}
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	if client.Name() == "iptables" {
		isInit, _ := iptables.LoadInitStatus("iptables", "base")
		if !isInit {
			// 未启用 managed 过滤（INPUT 默认 ACCEPT）→ 无需放行。
			return nil
		}
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", "tcp", "-m", "tcp", "--dport", port, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelBaseline, iptables.BaselineFileName); err != nil {
			return err
		}
		if iptables.HasIP6tables() {
			_ = iptables.AddRule6(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", "tcp", "-m", "tcp", "--dport", port, "-j", "ACCEPT")
			_ = iptables.SaveRulesToFile6(iptables.FilterTab, iptables.Chain1PanelBaseline, iptables.BaselineFileName)
		}
		return nil
	}
	// external（ufw/firewalld）：原生放行新端口 + reload，只增不删。
	// 防火墙已安装但未运行时跳过：没有活动规则集需要放行，且 firewall-cmd --reload 会因服务停止而报错，
	// 反而阻断面板端口（ServerPort）的更新（评审 P2，与 syncFirewallPortWhiteListAfterUpdate 的处理一致）。
	if isActive, _ := client.Status(); !isActive {
		return nil
	}
	if err := client.Port(fireClient.FireInfo{Port: port, Protocol: "tcp", Strategy: "accept"}, "add"); err != nil {
		return err
	}
	return client.Reload()
}

func (u *FirewallService) DockerStatus() dto.FirewallDockerStatus {
	available, rules := firewall.DockerStatus()
	result := dto.FirewallDockerStatus{Available: available}
	for _, r := range rules {
		result.Rules = append(result.Rules, dto.FirewallDockerRule{
			Address:  r.Address,
			Port:     r.Port,
			Protocol: r.Protocol,
			Strategy: r.Strategy,
		})
	}
	return result
}

func (u *FirewallService) ListSnapshots() ([]dto.FirewallSnapshot, error) {
	list, err := firewall.ListSnapshots()
	if err != nil {
		return nil, err
	}
	result := make([]dto.FirewallSnapshot, 0, len(list))
	for _, item := range list {
		result = append(result, dto.FirewallSnapshot{
			Name:      item.Name,
			Tag:       item.Tag,
			CreatedAt: item.CreatedAt,
			HasV6:     item.HasV6,
			Size:      item.Size,
		})
	}
	return result, nil
}

// RestoreSnapshot 高危操作：先 BeginSession（拍下恢复前状态作为还原点）再应用恢复；
// 若恢复后把自己锁外，确认窗口超时会自动回到恢复前（设计稿 §3.5 L3）。
func (u *FirewallService) RestoreSnapshot(req dto.FirewallSnapshotRestore) error {
	if err := firewall.BeginSession("restore snapshot " + req.Name); err != nil {
		return err
	}
	return firewall.RestoreSnapshot(req.Name)
}

// CleanOrphanFirewallRecords 替代被删除的 cleanUnUsedData 自动行为：
// 只在用户显式点击"清理失效描述"时执行，且用 keep-set 一次性删除，杜绝原先"遍历中删元素"的索引 bug（修 C3）。
func (u *FirewallService) CleanOrphanFirewallRecords() error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	ports, _ := client.ListPort()
	addresses, _ := client.ListAddress()
	live := append(ports, addresses...)

	records, _ := hostRepo.ListFirewallRecord()
	keep := make(map[uint]struct{})
	for _, item := range live {
		for _, rec := range records {
			if rec.DstPort == item.Port && rec.Protocol == item.Protocol && rec.Strategy == item.Strategy && rec.SrcIP == item.Address {
				keep[rec.ID] = struct{}{}
			}
		}
	}
	for _, rec := range records {
		// 只清理本函数能验证存活性的 port/address 记录；advance(1PANEL_INPUT/OUTPUT, Type="") 与 forward 记录
		// 不在 keep 计算范围内，绝不能被它们的存活集误删（否则会抹掉高级规则的描述）。
		if rec.Type != "port" && rec.Type != "address" {
			continue
		}
		if _, ok := keep[rec.ID]; ok {
			continue
		}
		if err := hostRepo.DeleteFirewallRecordByID(rec.ID); err != nil {
			global.LOG.Warnf("clean orphan firewall record %d failed: %v", rec.ID, err)
		}
	}
	return nil
}

func (u *FirewallService) addPortsBeforeStart(client firewall.FirewallClient) error {
	if client.Name() == "iptables" {
		isInit, _ := iptables.LoadInitStatus("iptables", "base")
		if !isInit {
			return nil
		}
		return syncIptablesFirewallPortWhiteList(true)
	}
	portWhiteList, err := loadFirewallPortWhiteList()
	if err != nil {
		return err
	}
	for _, item := range portWhiteList {
		if err := client.Port(fireClient.FireInfo{Port: item.Port, Protocol: item.Protocol, Strategy: "accept"}, "add"); err != nil {
			return err
		}
	}

	return client.Reload()
}

func (u *FirewallService) addPortRecord(clientName string, req dto.PortRuleOperate) error {
	portKey := firewall.RuleKey{Family: fingerprintFamily(clientName, "port", req.Family, req.Address), Scope: "input", Kind: "port", Action: req.Strategy, Protocol: req.Protocol, SrcIP: req.Address, DstPort: req.Port}
	if req.Operation == "remove" {
		_ = hostRepo.DeleteFirewallMeta(firewall.Fingerprint(portKey))
		if req.ID != 0 {
			return hostRepo.DeleteFirewallRecordByID(req.ID)
		}
		// 删除请求不携带 id（列表/批量删除均不传），按元组删除，避免残留行复活旧描述。
		return hostRepo.DeleteFirewallRecordByTuple(model.Firewall{Type: "port", DstPort: req.Port, Protocol: req.Protocol, SrcIP: req.Address, Strategy: req.Strategy})
	}

	if len(req.Description) == 0 {
		return nil
	}
	if err := hostRepo.SaveFirewallRecord(&model.Firewall{
		Type:        "port",
		Chain:       req.Chain,
		DstPort:     req.Port,
		Protocol:    req.Protocol,
		SrcIP:       req.Address,
		Strategy:    req.Strategy,
		Description: req.Description,
	}); err != nil {
		return fmt.Errorf("add record %s/%s failed (strategy: %s, address: %s), err: %v", req.Port, req.Protocol, req.Strategy, req.Address, err)
	}
	saveFirewallMeta(portKey, req.Description)

	return nil
}

func (u *FirewallService) addAddressRecord(clientName, chain string, req dto.AddrRuleOperate) error {
	addrKey := firewall.RuleKey{Family: fingerprintFamily(clientName, "address", req.Family, req.Address), Scope: "input", Kind: "address", Action: req.Strategy, SrcIP: req.Address}
	if req.Operation == "remove" {
		_ = hostRepo.DeleteFirewallMeta(firewall.Fingerprint(addrKey))
		if req.ID != 0 {
			return hostRepo.DeleteFirewallRecordByID(req.ID)
		}
		// 删除请求不携带 id（列表/批量删除均不传），按元组删除，避免残留行复活旧描述。
		return hostRepo.DeleteFirewallRecordByTuple(model.Firewall{Type: "address", SrcIP: req.Address, Strategy: req.Strategy})
	}

	if err := hostRepo.SaveFirewallRecord(&model.Firewall{
		Type:        "address",
		Chain:       chain,
		SrcIP:       req.Address,
		Strategy:    req.Strategy,
		Description: req.Description,
	}); err != nil {
		return fmt.Errorf("add record failed (strategy: %s, address: %s), err: %v", req.Strategy, req.Address, err)
	}
	saveFirewallMeta(addrKey, req.Description)
	return nil
}

// lowersReachability 判定一笔变更是否"降低可达性"（需走提交-确认事务）。
// 纯增加可达性（加 accept、删 deny）不进事务，避免确认疲劳（设计稿 §3.5.1 第 2 点）。
func lowersReachability(operation, strategy string) bool {
	if operation == "add" && (strategy == "drop" || strategy == "reject") {
		return true
	}
	if operation == "remove" && strategy == "accept" {
		return true
	}
	return false
}

// portChangeNeedsConfirm 判断端口变更是否需要 L3 提交-确认窗口（设计稿 §3.5.1）。
// 仅当变更降低可达性「且」触及管理通道（SSH/面板/端口白名单等保底端口）时才武装：封禁/删除
// 普通业务端口不会把管理员锁外（保底链始终放行 SSH/面板，L2 紧急 ACCEPT 另保当前连接），无需
// 自动回滚，避免打扰以小白用户为主的常用操作。
func portChangeNeedsConfirm(req dto.PortRuleOperate) bool {
	if !lowersReachability(req.Operation, req.Strategy) {
		return false
	}
	return touchesRescuePort(req.Port)
}

// addressChangeNeedsConfirm 判断 IP 变更是否需要 L3 提交-确认窗口。
// CIDR 段可能误伤管理员来源；单 IP 若正好命中当前请求来源，也必须武装，避免把自己封掉。
func addressChangeNeedsConfirm(req dto.AddrRuleOperate) bool {
	if !lowersReachability(req.Operation, req.Strategy) {
		return false
	}
	for _, addr := range strings.Split(req.Address, ",") {
		if isCIDRRange(addr) || addressCoversCallerIP(addr, req.CallerIP) {
			return true
		}
	}
	return false
}

// touchesRescuePort 判断端口表达式是否覆盖任一管理/保底端口（SSH、面板、已配置端口白名单）。
func touchesRescuePort(portSpec string) bool {
	if portSpecContains(portSpec, loadSSHPort()) || portSpecContains(portSpec, LoadPanelPort()) {
		return true
	}
	if list, err := loadFirewallPortWhiteList(); err == nil {
		for _, item := range list {
			if portSpecContains(portSpec, item.Port) {
				return true
			}
		}
	}
	return false
}

// isCIDRRange 判断地址是否为覆盖多个主机的 IP 段（带 / 前缀且非 /32、/128 单主机）。
func isCIDRRange(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || !strings.Contains(addr, "/") {
		return false
	}
	_, ipNet, err := net.ParseCIDR(addr)
	if err != nil {
		return false
	}
	ones, bits := ipNet.Mask.Size()
	return ones < bits
}

func addressCoversCallerIP(addr, callerIP string) bool {
	addr = strings.TrimSpace(addr)
	if isAnySource(addr) {
		return true
	}
	caller := net.ParseIP(strings.TrimSpace(callerIP))
	if caller == nil {
		return false
	}
	if strings.Contains(addr, "/") {
		_, ipNet, err := net.ParseCIDR(addr)
		return err == nil && ipNet.Contains(caller)
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.Equal(caller)
}

func firewallMode() firewall.Mode {
	p, err := firewall.Detect()
	if err != nil {
		return ""
	}
	return p.Mode()
}

// precheckAddressRule 实现 I1/I2 红线对 IP 规则的部分（设计稿 §3.5.2）。
func precheckAddressRule(req dto.AddrRuleOperate) error {
	if req.Operation != "add" || req.Strategy != "drop" {
		return nil
	}
	for _, addr := range strings.Split(req.Address, ",") {
		if isAnySource(addr) {
			// I1：1Panel 永不制造无条件 DROP（封所有来源）。
			return buserr.New("ErrFirewallUnconditionalDrop")
		}
	}
	return nil
}

// precheckPortRule 实现 I1/I2 红线对端口规则的部分（设计稿 §3.5.2）。
func precheckPortRule(req dto.PortRuleOperate) error {
	if req.Operation != "add" || req.Strategy != "drop" {
		return nil
	}
	hasSource := false
	for _, addr := range strings.Split(req.Address, ",") {
		if !isAnySource(addr) {
			hasSource = true
		}
	}
	if hasSource {
		return nil
	}
	// I2：无源限定地封禁 SSH/面板端口会阻断所有人 → 抢救通道红线。
	if portSpecContains(req.Port, LoadPanelPort()) || portSpecContains(req.Port, loadSSHPort()) {
		return buserr.New("ErrFirewallBlockRescue")
	}
	return nil
}

func isAnySource(addr string) bool {
	addr = strings.TrimSpace(addr)
	return addr == "" ||
		addr == "0.0.0.0/0" ||
		addr == "::/0" ||
		strings.EqualFold(addr, "anywhere") ||
		strings.EqualFold(addr, "anywhere (v6)")
}

// portSpecContains 判断端口表达式（单端口/逗号列表/区间 a-b 或 a:b）是否覆盖 target。
func portSpecContains(spec, target string) bool {
	spec = strings.TrimSpace(spec)
	target = strings.TrimSpace(target)
	if spec == "" || target == "" {
		return false
	}
	t, err := strconv.Atoi(target)
	if err != nil {
		return false
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		sep := ""
		if strings.Contains(part, "-") {
			sep = "-"
		} else if strings.Contains(part, ":") {
			sep = ":"
		}
		if sep == "" {
			if v, err := strconv.Atoi(part); err == nil && v == t {
				return true
			}
			continue
		}
		bounds := strings.SplitN(part, sep, 2)
		lo, e1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
		hi, e2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
		if e1 == nil && e2 == nil && t >= lo && t <= hi {
			return true
		}
	}
	return false
}

// saveFirewallMeta 按指纹幂等写入规则描述元数据（best-effort，不阻断主流程）。
func saveFirewallMeta(key firewall.RuleKey, description string) {
	if strings.TrimSpace(description) == "" {
		return
	}
	family := key.Family
	if family == "" {
		family = "ipv4"
	}
	if err := hostRepo.SaveFirewallMeta(&model.FirewallRuleMeta{
		Fingerprint: firewall.Fingerprint(key),
		Kind:        key.Kind,
		Family:      family,
		Description: description,
		Source:      "panel",
	}); err != nil {
		global.LOG.Warnf("save firewall meta failed: %v", err)
	}
}

func checkPortUsed(ports, proto string, apps []portOfApp) string {
	var portList []int
	rangeSplit := ""
	if strings.Contains(ports, "-") {
		rangeSplit = "-"
	}
	if strings.Contains(ports, ":") {
		rangeSplit = ":"
	}
	if len(rangeSplit) != 0 {
		port1, err := strconv.Atoi(strings.Split(ports, rangeSplit)[0])
		if err != nil {
			global.LOG.Errorf(" convert string %s to int failed, err: %v", strings.Split(ports, rangeSplit)[0], err)
			return ""
		}
		port2, err := strconv.Atoi(strings.Split(ports, rangeSplit)[1])
		if err != nil {
			global.LOG.Errorf(" convert string %s to int failed, err: %v", strings.Split(ports, rangeSplit)[1], err)
			return ""
		}
		for i := port1; i <= port2; i++ {
			portList = append(portList, i)
		}
	}
	if strings.Contains(ports, ",") {
		portLists := strings.Split(ports, ",")
		for _, item := range portLists {
			portItem, _ := strconv.Atoi(item)
			portList = append(portList, portItem)
		}
	}
	if len(portList) != 0 {
		var usedPorts []string
		for _, port := range portList {
			portItem := fmt.Sprintf("%v", port)
			isUsedByApp := false
			for _, app := range apps {
				if app.HttpPort == portItem || app.HttpsPort == portItem {
					isUsedByApp = true
					usedPorts = append(usedPorts, fmt.Sprintf("%s (%s)", portItem, app.AppName))
					break
				}
			}
			if !isUsedByApp && common.ScanPortWithProto(port, proto) {
				usedPorts = append(usedPorts, fmt.Sprintf("%v", port))
			}
		}
		return strings.Join(usedPorts, ",")
	}

	for _, app := range apps {
		if app.HttpPort == ports || app.HttpsPort == ports {
			return app.AppName
		}
	}

	return ""
}
