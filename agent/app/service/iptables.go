package service

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

type IIptablesService interface {
	Search(req dto.SearchPageWithType) (int64, interface{}, error)
	OperateRule(req dto.IptablesRuleOp, withSave bool) error
	BatchOperate(req dto.IptablesBatchOperate) error
	LoadChainStatus(req dto.OperationWithName) dto.IptablesChainStatus

	Operate(req dto.IptablesOp) error
}

type IptablesService struct{}

func NewIIptablesService() IIptablesService {
	return &IptablesService{}
}

func (s *IptablesService) Search(req dto.SearchPageWithType) (int64, interface{}, error) {
	rules, err := iptables.ReadFilterRulesByChain(req.Type)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read iptables rules: %w", err)
	}
	var records []iptables.FilterRules
	total, start, end := len(rules), (req.Page-1)*req.PageSize, req.Page*req.PageSize
	if start > total {
		records = make([]iptables.FilterRules, 0)
	} else {
		if end >= total {
			end = total
		}
		records = rules[start:end]
	}

	rulesInDB, _ := hostRepo.ListFirewallRecord(hostRepo.WithByChain(req.Type))

	for i := 0; i < len(records); i++ {
		for _, item := range rulesInDB {
			if records[i].Strategy == item.Strategy &&
				records[i].DstIP == item.DstIP &&
				fmt.Sprintf("%v", records[i].DstPort) == item.DstPort &&
				records[i].Protocol == item.Protocol &&
				records[i].SrcIP == item.SrcIP &&
				fmt.Sprintf("%v", records[i].SrcPort) == item.SrcPort {
				records[i].ID = item.ID
				records[i].Description = item.Description
			}
		}
	}
	return int64(total), records, nil
}

func (s *IptablesService) OperateRule(req dto.IptablesRuleOp, withSave bool) error {
	action := "ACCEPT"
	if req.Strategy == "drop" {
		action = "DROP"
	}
	policy := iptables.FilterRules{
		Protocol: req.Protocol,
		SrcIP:    req.SrcIP,
		DstIP:    req.DstIP,
		Strategy: action,
	}
	if req.SrcPort != 0 {
		policy.SrcPort = fmt.Sprintf("%v", req.SrcPort)
	}
	if req.DstPort != 0 {
		policy.DstPort = fmt.Sprintf("%v", req.DstPort)
	}

	name := iptables.InputFileName
	if req.Chain == iptables.Chain1PanelOutput {
		name = iptables.OutputFileName
	}
	switch req.Operation {
	case "add":
		if err := s.validateRuleInput(&req); err != nil {
			return err
		}

		if err := iptables.AddFilterRule(req.Chain, policy); err != nil {
			return fmt.Errorf("failed to add iptables rule: %w", err)
		}

		if len(req.Description) != 0 {
			rule := &model.Firewall{
				Chain:       req.Chain,
				Protocol:    req.Protocol,
				SrcIP:       req.SrcIP,
				SrcPort:     policy.SrcPort,
				DstIP:       req.DstIP,
				DstPort:     policy.DstPort,
				Strategy:    req.Strategy,
				Description: req.Description,
			}

			if err := hostRepo.SaveFirewallRecord(rule); err != nil {
				return fmt.Errorf("failed to save rule to database: %w", err)
			}
		}
	case "remove":
		if err := iptables.DeleteFilterRule(req.Chain, policy); err != nil {
			return fmt.Errorf("failed to remove iptables rule: %w", err)
		}
		if req.ID != 0 {
			if err := hostRepo.DeleteFirewallRecordByID(req.ID); err != nil {
				return fmt.Errorf("failed to delete rule from database: %w", err)
			}
		}
	}

	if !withSave {
		return nil
	}
	if err := iptables.SaveRulesToFile(iptables.FilterTab, req.Chain, name); err != nil {
		global.LOG.Errorf("persistence for %s failed, err: %v", iptables.Chain1PanelBasic, err)
	}
	return nil
}

func (s *IptablesService) BatchOperate(req dto.IptablesBatchOperate) error {
	if len(req.Rules) == 0 {
		return errors.New("no rules to operate")
	}
	for _, rule := range req.Rules {
		if err := s.OperateRule(rule, false); err != nil {
			return err
		}
	}
	chain := iptables.Chain1PanelInput
	fileName := iptables.InputFileName
	if req.Rules[0].Chain == iptables.Chain1PanelOutput {
		chain = iptables.Chain1PanelOutput
		fileName = iptables.OutputFileName
	}
	if err := iptables.SaveRulesToFile(iptables.FilterTab, chain, fileName); err != nil {
		global.LOG.Errorf("persistence for %s failed, err: %v", iptables.Chain1PanelBasic, err)
	}
	return nil
}

func (s *IptablesService) Operate(req dto.IptablesOp) error {
	targetChain := iptables.ChainInput
	if req.Name == iptables.Chain1PanelOutput {
		targetChain = iptables.ChainOutput
	}
	switch req.Operate {
	case "init-base":
		if ok := cmd.Which("iptables"); !ok {
			return fmt.Errorf("failed to find iptables")
		}
		for _, chain := range baseChainOrder {
			if err := iptables.AddChain(iptables.FilterTab, chain); err != nil {
				return err
			}
		}
		// v6：先建链（让白名单镜像能写 BASELINE6/ALLOW6），再渲染固定规则、绑定、持久化。
		if err := setupBaseChains6(); err != nil {
			return err
		}
		if err := initPreRules(); err != nil {
			return err
		}
		if err := renderGuardAfter6(); err != nil {
			return err
		}
		if err := bindBaseChainsInOrder(); err != nil {
			return err
		}
		if err := bindBaseChainsInOrder6(); err != nil {
			return err
		}
		if err := saveBaseChains(); err != nil {
			return err
		}
		if err := saveBaseChains6(); err != nil {
			return err
		}
		_ = settingRepo.Update("IptablesStatus", constant.StatusEnable)
		return nil
	case "init-forward":
		if err := client.EnableIptablesForward(); err != nil {
			return err
		}
		_ = settingRepo.Update("IptablesForwardStatus", constant.StatusEnable)
		return nil
	case "init-advance":
		if err := iptables.AddChain(iptables.FilterTab, iptables.Chain1PanelInput); err != nil {
			return err
		}
		if err := iptables.AddChain(iptables.FilterTab, iptables.Chain1PanelOutput); err != nil {
			return err
		}
		if err := iptables.BindChain(iptables.FilterTab, iptables.ChainOutput, iptables.Chain1PanelOutput, 1); err != nil {
			return err
		}
		number := loadBindNumber(iptables.Chain1PanelInput)
		if err := iptables.BindChain(iptables.FilterTab, iptables.ChainInput, iptables.Chain1PanelInput, number); err != nil {
			return err
		}
		_ = settingRepo.Update("IptablesInputStatus", constant.StatusEnable)
		_ = settingRepo.Update("IptablesOutputStatus", constant.StatusEnable)
		return nil
	case "bind-base":
		if err := setupBaseChains6(); err != nil {
			return err
		}
		if err := initPreRules(); err != nil {
			return err
		}
		if err := renderGuardAfter6(); err != nil {
			return err
		}
		if err := bindBaseChainsInOrder(); err != nil {
			return err
		}
		if err := bindBaseChainsInOrder6(); err != nil {
			return err
		}
		if err := saveBaseChains(); err != nil {
			return err
		}
		if err := saveBaseChains6(); err != nil {
			return err
		}
		_ = settingRepo.Update("IptablesStatus", constant.StatusEnable)
		return nil
	case "bind-base-without-init":
		if err := bindBaseChainsInOrder(); err != nil {
			return err
		}
		if err := bindBaseChainsInOrder6(); err != nil {
			return err
		}
		_ = settingRepo.Update("IptablesStatus", constant.StatusEnable)
		return nil
	case "unbind-base":
		unbindBaseChains()
		unbindBaseChains6()
		_ = settingRepo.Update("IptablesStatus", constant.StatusDisable)
		return nil
	case "bind":
		if err := iptables.BindChain(iptables.FilterTab, targetChain, req.Name, loadBindNumber(req.Name)); err != nil {
			return err
		}
		if req.Name == iptables.Chain1PanelInput {
			_ = settingRepo.Update("IptablesInputStatus", constant.StatusEnable)
		}
		if req.Name == iptables.Chain1PanelOutput {
			_ = settingRepo.Update("IptablesOutputStatus", constant.StatusEnable)
		}
		return nil
	case "unbind":
		if err := iptables.UnbindChain(iptables.FilterTab, targetChain, req.Name); err != nil {
			return err
		}
		if req.Name == iptables.Chain1PanelInput {
			_ = settingRepo.Update("IptablesInputStatus", constant.StatusDisable)
		}
		if req.Name == iptables.Chain1PanelOutput {
			_ = settingRepo.Update("IptablesOutputStatus", constant.StatusDisable)
		}
		return nil
	case "enable-strict":
		return enableStrictMode()
	case "disable-strict":
		return disableStrictMode()
	}
	return nil
}

// enableStrictMode 开启白名单（严格）模式：向已绑定的 AFTER 链注入 DROP all tcp/udp（v4+v6），
// 未列出端口将被拒绝。高危（可能锁外）→ 先 BeginSession 武装提交-确认窗口（60s 未确认自动还原）。
func enableStrictMode() error {
	// 先武装提交-确认会话（拍快照=空 AFTER），再注入 DROP；不在此落盘、也不写 IptablesStrictMode setting
	// ——遵守"确认前不落定"：用户点「确认保留」时 ConfirmSession 会 persistManagedChains（含 AFTER），超时/崩溃
	// 则 RevertSession 还原为空 AFTER 并落盘，自动回到宽松，杜绝误开严格把人锁外。StrictMode 以内核为准
	// （isStrictMode 读 AFTER 链），setting 不在确认前写盘，避免 DB/内核分裂（修 B7）。
	if err := firewall.BeginSession("enable strict (whitelist) mode"); err != nil {
		return err
	}
	if err := ensureAfterDropRules(); err != nil {
		return err
	}
	return nil
}

// disableStrictMode 关闭白名单模式：清空 AFTER 链（v4+v6），未列出端口落回 INPUT(ACCEPT) 即宽松放行。
func disableStrictMode() error {
	if firewall.SessionStatus().Active {
		if err := firewall.RevertSession(); err != nil {
			return err
		}
	}
	if err := iptables.ClearChain(iptables.FilterTab, iptables.Chain1PanelAfter); err != nil {
		return err
	}
	if err := iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelAfter, iptables.AfterFileName); err != nil {
		return err
	}
	if iptables.HasIP6tables() {
		if err := iptables.ClearChain6(iptables.FilterTab, iptables.Chain1PanelAfter); err != nil {
			return err
		}
		if err := iptables.SaveRulesToFile6(iptables.FilterTab, iptables.Chain1PanelAfter, iptables.AfterFileName); err != nil {
			return err
		}
	}
	// 不写 IptablesStrictMode setting：该 setting 全仓无读取方，StrictMode 以内核为准（isStrictMode），
	// 不在变更点写盘可避免 enable/disable/会话回滚间的 DB/内核分裂（修 B7）。
	return nil
}

// ensureAfterDropRules 幂等地向 AFTER 链（v4+v6）注入 DROP all tcp/udp。
// v6 关键操作失败必须上抛（修 B6）：否则 enableStrictMode 仍返回 nil，造成"v4 严格/v6 宽松"不对称，
// IPv6 旁路绕过白名单；上抛后上层会话（BeginSession 已武装）会在超时/崩溃时 RevertSession 还原 v4+v6。
func ensureAfterDropRules() error {
	for _, proto := range []string{"tcp", "udp"} {
		if !iptables.CheckRuleExist(iptables.FilterTab, iptables.Chain1PanelAfter, "-p", proto, "-j", "DROP") {
			if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelAfter, "-p", proto, "-j", "DROP"); err != nil {
				return err
			}
		}
		if iptables.HasIP6tables() && !iptables.CheckRuleExist6(iptables.FilterTab, iptables.Chain1PanelAfter, "-p", proto, "-j", "DROP") {
			if err := iptables.AddRule6(iptables.FilterTab, iptables.Chain1PanelAfter, "-p", proto, "-j", "DROP"); err != nil {
				return err
			}
		}
	}
	return nil
}

// isStrictMode 判断当前是否白名单模式：AFTER 链需"已 jump 到 INPUT 且含 DROP all tcp"才算生效（注入时 tcp/udp 成对，检 tcp 即可）。
// v4 与 v6（若可用）都满足才算启用；unbind-base 解绑后链内残留 DROP 时返回 false（与"实际未生效"一致，修 B5）；
// v4/v6 仅一侧严格视为不一致，返回 false 避免 UI 误报"严格已开"并 warn 暴露 IPv6 旁路风险（修 B6）。
func isStrictMode() bool {
	v4Bind, _ := iptables.CheckChainBind(iptables.FilterTab, iptables.ChainInput, iptables.Chain1PanelAfter)
	v4Strict := v4Bind && iptables.CheckRuleExist(iptables.FilterTab, iptables.Chain1PanelAfter, "-p", "tcp", "-j", "DROP")
	if !iptables.HasIP6tables() {
		return v4Strict
	}
	v6Strict := iptables.FindChainNum6(iptables.FilterTab, iptables.ChainInput, iptables.Chain1PanelAfter) > 0 &&
		iptables.CheckRuleExist6(iptables.FilterTab, iptables.Chain1PanelAfter, "-p", "tcp", "-j", "DROP")
	if v4Strict != v6Strict {
		global.LOG.Warnf("[firewall] strict mode inconsistent: v4=%v v6=%v, treating as disabled to avoid false \"strict on\"", v4Strict, v6Strict)
		return false
	}
	return v4Strict
}

func (s *IptablesService) LoadChainStatus(req dto.OperationWithName) dto.IptablesChainStatus {
	var data dto.IptablesChainStatus
	var err error
	data.DefaultStrategy, err = iptables.LoadDefaultStrategy(req.Name)
	if err != nil {
		global.LOG.Error(err)
	}
	switch req.Name {
	case iptables.Chain1PanelBasic:
		data.IsBind, _ = iptables.CheckChainBind(iptables.FilterTab, iptables.ChainInput, req.Name)
	case iptables.Chain1PanelInput:
		data.IsBind, _ = iptables.CheckChainBind(iptables.FilterTab, iptables.ChainInput, req.Name)
	case iptables.Chain1PanelOutput:
		data.IsBind, _ = iptables.CheckChainBind(iptables.FilterTab, iptables.ChainOutput, req.Name)
	}
	return data
}

func (s *IptablesService) validateRuleInput(req *dto.IptablesRuleOp) error {
	if req.Protocol != "" {
		validProtocols := map[string]bool{"tcp": true, "udp": true, "icmp": true, "all": true}
		if !validProtocols[strings.ToLower(req.Protocol)] {
			return fmt.Errorf("invalid protocol: %s, must be tcp, udp, icmp or all", req.Protocol)
		}
	}
	if req.SrcIP != "" {
		if err := s.validateIPOrCIDR(req.SrcIP); err != nil {
			return fmt.Errorf("invalid source IP: %w", err)
		}
	}
	if req.DstIP != "" {
		if err := s.validateIPOrCIDR(req.DstIP); err != nil {
			return fmt.Errorf("invalid destination IP: %w", err)
		}
	}
	if req.SrcPort > 65535 {
		return fmt.Errorf("invalid source port: %d, must be between 1 and 65535", req.SrcPort)
	}
	if req.DstPort > 65535 {
		return fmt.Errorf("invalid destination port: %d, must be between 1 and 65535", req.DstPort)
	}
	if (req.SrcPort > 0 || req.DstPort > 0) && req.Protocol == "" {
		return fmt.Errorf("port specification requires protocol (tcp/udp)")
	}

	return nil
}

func (s *IptablesService) validateIPOrCIDR(ipStr string) error {
	if strings.Contains(ipStr, "/") {
		_, _, err := net.ParseCIDR(ipStr)
		if err != nil {
			return fmt.Errorf("invalid CIDR format: %w", err)
		}
		return nil
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP address format")
	}

	return nil
}

func loadBindNumber(chain string) int {
	if chain == iptables.Chain1PanelOutput {
		return 1
	}
	// 1PANEL_INPUT（高级过滤）插在 ALLOW 之后、AFTER 之前（设计稿 §3.4 位置 5）。
	if num, _ := iptables.FindChainNum(iptables.FilterTab, iptables.ChainInput, iptables.Chain1PanelAfter); num > 0 {
		return num
	}
	// AFTER 未绑定（非严格）→ 追加到已绑定基础链之后。
	count := 0
	for _, c := range []string{
		iptables.Chain1PanelGuard,
		iptables.Chain1PanelDeny,
		iptables.Chain1PanelBaseline,
		iptables.Chain1PanelAllow,
	} {
		if num, _ := iptables.FindChainNum(iptables.FilterTab, iptables.ChainInput, c); num > 0 {
			count++
		}
	}
	return count + 1
}

func initPreRules() error {
	// GUARD：lo + ESTABLISHED 放行（每包都过，放最前）。caller-IP 紧急放行由 L2 中间件动态插 INPUT 顶。
	if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelGuard, "-i", "lo", "-j", "ACCEPT", "-m", "comment", "--comment", "Loopback Whitelist"); err != nil {
		return err
	}
	if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelGuard, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT", "-m", "comment", "--comment", "ESTABLISHED Whitelist"); err != nil {
		return err
	}
	// 渲染保底集（SSH/面板 → BASELINE）与白名单（80/443 → ALLOW）。
	if err := syncIptablesFirewallPortWhiteList(false); err != nil {
		return err
	}
	// AFTER 默认留空（宽松模式：未列出端口落回 INPUT(ACCEPT)，面向小白默认放行）。
	// 白名单（严格）模式由用户通过 enable-strict 显式开启，届时再向 AFTER 注入 DROP all。
	return nil
}

// bindBaseChainsInOrder 按固定顺序 GUARD(1) DENY(2) BASELINE(3) ALLOW(4) AFTER(5) 绑定到 INPUT，
// 先全部解绑再按序插入，最后回读断言顺序（根治 #12476 链顺序错乱，修 C9）。
func bindBaseChainsInOrder() error {
	unbindBaseChains()
	for i, chain := range baseChainOrder {
		if err := iptables.Run(iptables.FilterTab, "-I", iptables.ChainInput, strconv.Itoa(i+1), "-j", chain); err != nil {
			return fmt.Errorf("bind base chain %s failed: %w", chain, err)
		}
	}
	return assertBaseOrder()
}

// unbindBaseChains 解绑 INPUT 上全部新布局基础链（循环删，处理重复绑定）。
// 同时解绑旧 BASIC 布局残留的 INPUT jump：升级机器上 INPUT 仍可能挂着 BASIC_BEFORE/BASIC/BASIC_AFTER，
// 不一并解绑则旧严格 DROP 路径在绑定新链后依然生效，且 unbind-base 关闭防火墙时无法真正停用旧路径（评审 P1）。
// 迁移完成后这些旧链已不在 INPUT，FindChainNum 返回 0，循环立即跳过，对存量机为无害幂等操作。
func unbindBaseChains() {
	chains := append([]string{}, baseChainOrder...)
	chains = append(chains,
		iptables.Chain1PanelBasicBefore,
		iptables.Chain1PanelBasic,
		iptables.Chain1PanelBasicAfter,
	)
	for _, chain := range chains {
		for i := 0; i < 16; i++ {
			num, _ := iptables.FindChainNum(iptables.FilterTab, iptables.ChainInput, chain)
			if num == 0 {
				break
			}
			if err := iptables.Run(iptables.FilterTab, "-D", iptables.ChainInput, strconv.Itoa(num)); err != nil {
				break
			}
		}
	}
}

// assertBaseOrder 回读 INPUT，断言 GUARD/DENY/BASELINE/ALLOW/AFTER 的相对顺序正确（忽略可选的 1PANEL_INPUT）。
func assertBaseOrder() error {
	jumps := orderedPanelJumps()
	expected := baseChainOrder
	var got []string
	expectedSet := map[string]struct{}{}
	for _, c := range expected {
		expectedSet[c] = struct{}{}
	}
	for _, j := range jumps {
		if _, ok := expectedSet[j]; ok {
			got = append(got, j)
		}
	}
	if len(got) != len(expected) {
		return fmt.Errorf("base chain order assertion failed: expected %v, got %v", expected, got)
	}
	for i := range expected {
		if got[i] != expected[i] {
			return fmt.Errorf("base chain order assertion failed: expected %v, got %v", expected, got)
		}
	}
	return nil
}

// orderedPanelJumps 返回 INPUT 中所有跳向 1PANEL_* 链的目标（按出现顺序）。
func orderedPanelJumps() []string {
	out, err := iptables.RunWithStd(iptables.FilterTab, "-S", iptables.ChainInput)
	if err != nil {
		return nil
	}
	var jumps []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A "+iptables.ChainInput+" -j 1PANEL_") {
			continue
		}
		fields := strings.Fields(line)
		jumps = append(jumps, fields[len(fields)-1])
	}
	return jumps
}

var baseChainOrder = []string{
	iptables.Chain1PanelGuard,
	iptables.Chain1PanelDeny,
	iptables.Chain1PanelBaseline,
	iptables.Chain1PanelAllow,
	iptables.Chain1PanelAfter,
}

// setupBaseChains6 在 ip6tables 上建链 + 渲染 GUARD6/AFTER6 固定规则（BASELINE6/ALLOW6 由白名单同步镜像写入），
// 须在 initPreRules 之前建好链（否则白名单镜像 AddRule6 找不到链）。设计稿 §3.7。
func setupBaseChains6() error {
	if !iptables.HasIP6tables() {
		return nil
	}
	for _, chain := range baseChainOrder {
		if err := iptables.AddChain6(iptables.FilterTab, chain); err != nil {
			return err
		}
	}
	return nil
}

// renderGuardAfter6 写入 v6 的 GUARD（lo + ICMPv6/NDP + ESTABLISHED）与 AFTER（DROP all）。
// ICMPv6 必放行，否则 NDP 被丢导致 IPv6 不通。
func renderGuardAfter6() error {
	if !iptables.HasIP6tables() {
		return nil
	}
	if err := iptables.AddRule6(iptables.FilterTab, iptables.Chain1PanelGuard, "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := iptables.AddRule6(iptables.FilterTab, iptables.Chain1PanelGuard, "-p", "ipv6-icmp", "-j", "ACCEPT"); err != nil {
		return err
	}
	// AFTER6 默认留空（宽松模式）；严格模式由 enable-strict 注入 DROP（与 v4 对称）。
	return iptables.AddRule6(iptables.FilterTab, iptables.Chain1PanelGuard, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
}

func bindBaseChainsInOrder6() error {
	if !iptables.HasIP6tables() {
		return nil
	}
	for _, chain := range baseChainOrder {
		iptables.UnbindChain6(iptables.FilterTab, iptables.ChainInput, chain)
	}
	for i, chain := range baseChainOrder {
		if err := iptables.InsertChain6(iptables.FilterTab, iptables.ChainInput, chain, i+1); err != nil {
			return err
		}
	}
	return nil
}

func unbindBaseChains6() {
	if !iptables.HasIP6tables() {
		return
	}
	for _, chain := range baseChainOrder {
		iptables.UnbindChain6(iptables.FilterTab, iptables.ChainInput, chain)
	}
}

func saveBaseChains6() error {
	if !iptables.HasIP6tables() {
		return nil
	}
	for _, chain := range baseChainOrder {
		if err := iptables.SaveRulesToFile6(iptables.FilterTab, chain, iptables.ChainFileName(chain)); err != nil {
			return err
		}
	}
	return nil
}

func saveBaseChains() error {
	for _, chain := range baseChainOrder {
		if err := iptables.SaveRulesToFile(iptables.FilterTab, chain, iptables.ChainFileName(chain)); err != nil {
			return err
		}
	}
	return nil
}

func syncIptablesFirewallPortWhiteList(withSave bool, oldConfiguredPortWhiteList ...[]firewallPortWhitelist) error {
	requiredPorts, err := loadRequiredFirewallPortWhiteList()
	if err != nil {
		return err
	}
	if err := applyRequiredFirewallPortWhiteListRules(requiredPorts, withSave); err != nil {
		return err
	}
	portWhiteList, err := loadConfiguredFirewallPortWhiteList()
	if err != nil {
		return err
	}
	return applyFirewallPortWhiteListRules(portWhiteList, withSave, oldConfiguredPortWhiteList...)
}

func applyRequiredFirewallPortWhiteListRules(portWhiteList []firewallPortWhitelist, withSave bool) error {
	// 保底集（SSH/面板）渲染进 BASELINE 链（不可移除），镜像写 v6（修 C7）。
	if err := syncRequiredFirewallPortWhiteListRules(portWhiteList); err != nil {
		return err
	}
	for _, item := range portWhiteList {
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", item.Protocol, "-m", item.Protocol, "--dport", item.Port, "-j", "ACCEPT"); err != nil {
			return err
		}
		if iptables.HasIP6tables() {
			_ = iptables.AddRule6(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", item.Protocol, "-m", item.Protocol, "--dport", item.Port, "-j", "ACCEPT")
		}
	}
	if !withSave {
		return nil
	}
	if err := iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelBaseline, iptables.BaselineFileName); err != nil {
		return err
	}
	if iptables.HasIP6tables() {
		_ = iptables.SaveRulesToFile6(iptables.FilterTab, iptables.Chain1PanelBaseline, iptables.BaselineFileName)
		_ = iptables.SaveRulesToFile6(iptables.FilterTab, iptables.Chain1PanelAfter, iptables.AfterFileName)
	}
	return iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelAfter, iptables.AfterFileName)
}

func applyFirewallPortWhiteListRules(portWhiteList []firewallPortWhitelist, withSave bool, oldConfiguredPortWhiteList ...[]firewallPortWhitelist) error {
	// 用户白名单（80/443 默认在此，可删）渲染进 ALLOW 链——位于 DENY 之后，故黑名单可压过它（根治 #12897）。
	if err := syncFirewallPortWhiteListRules(portWhiteList, oldConfiguredPortWhiteList...); err != nil {
		return err
	}
	for _, item := range portWhiteList {
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelAllow, "-p", item.Protocol, "-m", item.Protocol, "--dport", item.Port, "-j", "ACCEPT"); err != nil {
			return err
		}
		if iptables.HasIP6tables() {
			_ = iptables.AddRule6(iptables.FilterTab, iptables.Chain1PanelAllow, "-p", item.Protocol, "-m", item.Protocol, "--dport", item.Port, "-j", "ACCEPT")
		}
	}
	if !withSave {
		return nil
	}
	if iptables.HasIP6tables() {
		_ = iptables.SaveRulesToFile6(iptables.FilterTab, iptables.Chain1PanelAllow, iptables.AllowFileName)
	}
	return iptables.SaveRulesToFile(iptables.FilterTab, iptables.Chain1PanelAllow, iptables.AllowFileName)
}

func syncRequiredFirewallPortWhiteListRules(portWhiteList []firewallPortWhitelist) error {
	tcpWhitelist := make(map[string]struct{})
	udpWhitelist := make(map[string]struct{})
	for _, item := range portWhiteList {
		if item.Protocol == "udp" {
			udpWhitelist[item.Port] = struct{}{}
			continue
		}
		tcpWhitelist[item.Port] = struct{}{}
	}

	if err := cleanExtraFirewallPortRules(iptables.Chain1PanelBaseline, "tcp", tcpWhitelist); err != nil {
		return err
	}
	if err := cleanExtraFirewallPortRules(iptables.Chain1PanelBaseline, "udp", udpWhitelist); err != nil {
		return err
	}
	return nil
}

func syncFirewallPortWhiteListRules(portWhiteList []firewallPortWhitelist, oldConfiguredPortWhiteList ...[]firewallPortWhitelist) error {
	portWhitelist := firewallPortWhiteListMap(portWhiteList)
	if len(oldConfiguredPortWhiteList) == 0 {
		return nil
	}
	for _, item := range oldConfiguredPortWhiteList[0] {
		if _, ok := portWhitelist[firewallPortWhiteListKey(item)]; ok {
			continue
		}
		if iptables.CheckRuleExist(iptables.FilterTab, iptables.Chain1PanelAllow, "-p", item.Protocol, "--dport", item.Port, "-j", "ACCEPT") {
			if err := iptables.DeleteRule(iptables.FilterTab, iptables.Chain1PanelAllow, "-p", item.Protocol, "--dport", item.Port, "-j", "ACCEPT"); err != nil {
				return err
			}
		}
		// 删除时必须同步清掉 v6 镜像：添加白名单端口会镜像写 ip6tables ALLOW，
		// 仅删 v4 会让端口在 IPv6 上持续放行（且随后又被 SaveRulesToFile6 落盘）（评审 P2）。
		if iptables.HasIP6tables() && iptables.CheckRuleExist6(iptables.FilterTab, iptables.Chain1PanelAllow, "-p", item.Protocol, "--dport", item.Port, "-j", "ACCEPT") {
			if err := iptables.DeleteRule6(iptables.FilterTab, iptables.Chain1PanelAllow, "-p", item.Protocol, "--dport", item.Port, "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}
	return nil
}

func cleanExtraFirewallPortRules(chain, protocol string, whitelist map[string]struct{}) error {
	if err := cleanExtraPortRulesByFamily(chain, protocol, whitelist, iptables.ReadFilterRulesByChain, iptables.DeleteRule); err != nil {
		return err
	}
	// v6 镜像同样清理：保底集（SSH/面板端口）由 applyRequiredFirewallPortWhiteListRules 镜像写入 v6 BASELINE，
	// 若只清 v4，端口变更后旧端口会在 IPv6 上持续放行并被 SaveRulesToFile6 再次落盘（评审 P2，与 ALLOW 链 v6 删除同源）。
	// 独立扫一遍 v6 链，可一并自愈本修复前已残留的 v6-only 陈旧项。
	if !iptables.HasIP6tables() {
		return nil
	}
	return cleanExtraPortRulesByFamily(chain, protocol, whitelist, iptables.ReadFilterRulesByChain6, iptables.DeleteRule6)
}

// cleanExtraPortRulesByFamily 按指定地址族（由 read/del 决定 v4 或 v6）清掉某链中不在白名单内的多余端口 ACCEPT，
// 同名端口仅保留首条。沿用本包既有的 reader 函数值传参风格（见 appendPortRules）。
func cleanExtraPortRulesByFamily(chain, protocol string, whitelist map[string]struct{}, read func(string) ([]iptables.FilterRules, error), del func(string, string, ...string) error) error {
	rules, err := read(chain)
	if err != nil {
		return err
	}
	kept := make(map[string]struct{})
	for _, rule := range rules {
		if rule.Strategy != "accept" || rule.Protocol != protocol || rule.DstPort == "" || rule.SrcIP != "" || rule.DstIP != "" || rule.SrcPort != "" {
			continue
		}
		if _, ok := whitelist[rule.DstPort]; ok {
			if _, seen := kept[rule.DstPort]; !seen {
				kept[rule.DstPort] = struct{}{}
				continue
			}
		}
		if err := del(iptables.FilterTab, chain, "-p", protocol, "-m", protocol, "--dport", rule.DstPort, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	return nil
}

func LoadPanelPort() string {
	if !global.IsMaster {
		return global.CONF.Base.Port
	} else {
		var portSetting model.Setting
		_ = global.CoreDB.Where("key = ?", "ServerPort").First(&portSetting).Error
		if len(portSetting.Value) != 0 {
			return portSetting.Value
		}
	}
	return ""
}
