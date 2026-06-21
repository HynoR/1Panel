package service

import (
	"context"
	"fmt"
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
		if provider.Mode() == firewall.ModeManaged {
			baseInfo.IsInit, baseInfo.IsBind = iptables.LoadInitStatus(baseInfo.Name, tab)
		} else {
			baseInfo.IsInit, baseInfo.IsBind = true, true
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

func (u *FirewallService) OperatePortRule(req dto.PortRuleOperate, reload bool) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	if len(req.Chain) == 0 && client.Name() == "iptables" {
		req.Chain = iptables.Chain1PanelBasic
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
					req.Port = strings.ReplaceAll(req.Port, ":", "-")
					if err := u.addPortRecord(req); err != nil {
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
			if len(req.Protocol) == 0 {
				req.Protocol = "tcp/udp"
			}
			if err := u.addPortRecord(req); err != nil {
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
				if err := u.addPortRecord(req); err != nil {
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
					if err := u.addPortRecord(req); err != nil {
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
						reqRule.Interface == rule.Interface {
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
					reqRule.Interface == rule.Interface {
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

func (u *FirewallService) OperateAddressRule(req dto.AddrRuleOperate, reload bool) error {
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return err
	}
	chain := ""
	if client.Name() == "iptables" {
		chain = iptables.Chain1PanelBasic
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
		req.Address = addressList[i]
		if err := u.addAddressRecord(chain, req); err != nil {
			return err
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
		return firewall.RuleKey{Family: "ipv4", Scope: "input", Kind: "address", Action: req.Strategy, SrcIP: req.SrcIP}
	case "port":
		return firewall.RuleKey{Family: "ipv4", Scope: "input", Kind: "port", Action: req.Strategy, Protocol: req.Protocol, SrcIP: req.SrcIP, DstPort: req.DstPort}
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
	if req.Type == "port" {
		for _, rule := range req.Rules {
			_ = u.OperatePortRule(rule, false)
		}
		return client.Reload()
	}
	for _, rule := range req.Rules {
		itemRule := dto.AddrRuleOperate{Operation: rule.Operation, Address: rule.Address, Strategy: rule.Strategy}
		_ = u.OperateAddressRule(itemRule, false)
	}
	return client.Reload()
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

func (u *FirewallService) addPortRecord(req dto.PortRuleOperate) error {
	portKey := firewall.RuleKey{Family: "ipv4", Scope: "input", Kind: "port", Action: req.Strategy, Protocol: req.Protocol, SrcIP: req.Address, DstPort: req.Port}
	if req.Operation == "remove" {
		_ = hostRepo.DeleteFirewallMeta(firewall.Fingerprint(portKey))
		if req.ID != 0 {
			return hostRepo.DeleteFirewallRecordByID(req.ID)
		}
		return nil
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

func (u *FirewallService) addAddressRecord(chain string, req dto.AddrRuleOperate) error {
	addrKey := firewall.RuleKey{Family: "ipv4", Scope: "input", Kind: "address", Action: req.Strategy, SrcIP: req.Address}
	if req.Operation == "remove" {
		_ = hostRepo.DeleteFirewallMeta(firewall.Fingerprint(addrKey))
		if req.ID != 0 {
			return hostRepo.DeleteFirewallRecordByID(req.ID)
		}
		return nil
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
