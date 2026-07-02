package firewall

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/repo"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	firewallClient "github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
)

func Init() {
	// 安全栈 L2/L3：无论是否首启都要做的两件保命事——
	//  1. 后台清理过期的 caller-IP 紧急放行；
	//  2. 回收未确认的提交-确认会话（agent 崩溃/重启 = 视同窗口超时立即还原，堵死逃逸路径）。
	firewall.StartEmergencyJanitor()
	firewall.ReclaimSession()

	// runBootReplay 默认每个主机引导周期跑一次（/run 引导标记区分"重启进程"与"重启主机"）。
	// 但升级首启通常是进程重启（标记仍在），若旧 BASIC 布局尚未迁移，必须立即迁移并重放为新布局，
	// 否则内核停留在旧布局而新代码按 GUARD/DENY/BASELINE/ALLOW/AFTER 读写 → 防火墙搜索/规则失效直到下次重启（评审 P1）。
	// 注意 needInit 有副作用（创建引导标记），靠 && 短路保证首启时仍会先创建标记。
	if !needInit() && !legacyMigrationPending() {
		return
	}
	InitPingStatus()
	status := runBootReplay()
	recordBootStatus(status)
}

func runBootReplay() string {
	global.LOG.Info("[firewall-boot] initializing firewall settings...")
	provider, err := firewall.Detect()
	if err != nil {
		return "degraded:no firewall detected"
	}
	clientName := provider.Name()

	// PR-6：Docker 防护与防火墙模式正交，开机重放 1PANEL_DOCKER 并断言 DOCKER-USER jump（自带可用性检测）。
	firewall.LoadDockerRules()

	settingRepo := repo.NewISettingRepo()
	if clientName == "ufw" || clientName == "iptables" {
		if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelForward, iptables.ForwardFileName); err != nil {
			global.LOG.Errorf("[firewall-boot] load forward rules from file failed, err: %v", err)
			return "failed:load forward rules"
		}
		if err := iptables.LoadRulesFromFile(iptables.NatTab, iptables.Chain1PanelPreRouting, iptables.ForwardFileName1); err != nil {
			global.LOG.Errorf("[firewall-boot] load prerouting rules from file failed, err: %v", err)
			return "failed:load prerouting rules"
		}
		if err := iptables.LoadRulesFromFile(iptables.NatTab, iptables.Chain1PanelPostRouting, iptables.ForwardFileName2); err != nil {
			global.LOG.Errorf("[firewall-boot] load postrouting rules from file failed, err: %v", err)
			return "failed:load postrouting rules"
		}
		global.LOG.Infof("[firewall-boot] loaded iptables rules for forward from file successfully")

		iptablesForwardStatus, _ := settingRepo.GetValueByKey("IptablesForwardStatus")
		if iptablesForwardStatus == constant.StatusEnable {
			if err := firewallClient.EnableIptablesForward(); err != nil {
				global.LOG.Errorf("[firewall-boot] enable iptables forward failed, err: %v", err)
				return "failed:enable forward"
			}
		}
	}

	if clientName != "iptables" {
		return "ok"
	}

	// PR-3：把旧 BASIC 布局文件一次性迁移为新的 GUARD/DENY/BASELINE/ALLOW/AFTER 布局文件（幂等）。
	// 迁移失败直接中止本次重放：旧文件未改名、GuardFileName 未写，下次启动 legacyMigrationPending 仍为 true 会重试，
	// 避免在半迁移状态下继续重放导致部分链规则永久丢失。
	if err := migrateLegacyChains(); err != nil {
		global.LOG.Errorf("[firewall-boot] migrate legacy chains failed, err: %v", err)
		return "failed:migrate legacy chains"
	}

	// L4 ①：在任何重放/绑定前，先确保 INPUT 默认策略不是 DROP；若是，直接注入 SSH/面板紧急 ACCEPT。
	firewall.EnsureInputPolicySafe(service.LoadBaselinePorts())

	baseChains := []struct {
		chain string
		file  string
	}{
		{iptables.Chain1PanelGuard, iptables.GuardFileName},
		{iptables.Chain1PanelDeny, iptables.DenyFileName},
		{iptables.Chain1PanelBaseline, iptables.BaselineFileName},
		{iptables.Chain1PanelAllow, iptables.AllowFileName},
		{iptables.Chain1PanelAfter, iptables.AfterFileName},
	}
	for _, item := range baseChains {
		if err := iptables.LoadRulesFromFile(iptables.FilterTab, item.chain, item.file); err != nil {
			global.LOG.Errorf("[firewall-boot] load %s rules from file failed, err: %v", item.chain, err)
			return "failed:load " + item.chain
		}
		// v6 镜像链重放（存在 ip6tables 且有 .v6 文件时）。
		if iptables.HasIP6tables() {
			if err := iptables.LoadRulesFromFile6(iptables.FilterTab, item.chain, item.file); err != nil {
				global.LOG.Warnf("[firewall-boot] load v6 %s rules failed: %v", item.chain, err)
			}
		}
	}
	baselinePorts := service.LoadBaselinePorts()
	if len(baselinePorts) == 0 {
		global.LOG.Errorf("[firewall-boot] find baseline ports (ssh/panel) failed")
		return "failed:find baseline ports"
	}
	// 保底注入：全部保底端口（SSH+面板）ACCEPT 进 BASELINE（AddRule 自带去重；回读校验见下）。
	for _, p := range baselinePorts {
		if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", "tcp", "-m", "tcp", "--dport", p, "-j", "ACCEPT"); err != nil {
			global.LOG.Errorf("[firewall-boot] add baseline port accept rule %v failed, err: %v", p, err)
			return "failed:inject baseline"
		}
	}
	global.LOG.Infof("[firewall-boot] loaded iptables base chains from file successfully")

	iptablesService := service.IptablesService{}
	iptablesStatus, _ := settingRepo.GetValueByKey("IptablesStatus")
	bootStatus := "ok"
	if iptablesStatus == constant.StatusEnable {
		// R2 fail-open 守卫：AFTER 链（存量机天然白名单尾规则 DROP-all）一旦随文件加载并绑定，
		// BASELINE 若未放行全部保底端口即会在绑定瞬间把 SSH/面板 DROP 锁外。故绑定前先断言，
		// 断言失败宁可清空 AFTER（v4+v6）退回宽松布局也不锁外，随后仍继续绑定（此时布局是安全的）。
		if afterChainHasDrop() && !baselinePortsAllAccepted(baselinePorts) {
			global.LOG.Errorf("[firewall-boot] baseline verify failed while AFTER holds DROP-all; suspending strict layout (clearing AFTER)")
			if err := iptables.ClearChain(iptables.FilterTab, iptables.Chain1PanelAfter); err != nil {
				global.LOG.Errorf("[firewall-boot] clear v4 AFTER chain failed, err: %v", err)
			}
			if iptables.HasIP6tables() {
				if err := iptables.ClearChain6(iptables.FilterTab, iptables.Chain1PanelAfter); err != nil {
					global.LOG.Warnf("[firewall-boot] clear v6 AFTER chain failed, err: %v", err)
				}
			}
			bootStatus = "degraded:strict-suspended (baseline verify failed)"
		}
		if err := iptablesService.Operate(dto.IptablesOp{Operate: "bind-base-without-init"}); err != nil {
			global.LOG.Errorf("[firewall-boot] bind base chains failed, err: %v", err)
			return "failed:bind base"
		}
		// L4：绑定后回读校验 BASELINE 是否放行全部保底端口；缺失则降级告警（不阻断，UI 横幅提示）。
		// 不覆盖已置的更严重 strict-suspended。
		if bootStatus == "ok" && !baselinePortsAllAccepted(baselinePorts) {
			global.LOG.Warnf("[firewall-boot] baseline ports accept verification failed")
			bootStatus = "degraded:baseline verify failed"
		}
	}

	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelInput, iptables.InputFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] load input rules from file failed, err: %v", err)
		return "failed:load input rules"
	}
	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelOutput, iptables.OutputFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] load output rules from file failed, err: %v", err)
		return "failed:load output rules"
	}
	global.LOG.Infof("[firewall-boot] loaded iptables rules for input and output from file successfully")
	iptablesInputStatus, _ := settingRepo.GetValueByKey("IptablesInputStatus")
	if iptablesInputStatus == constant.StatusEnable {
		if err := iptablesService.Operate(dto.IptablesOp{Name: iptables.Chain1PanelInput, Operate: "bind"}); err != nil {
			global.LOG.Errorf("[firewall-boot] bind input chains failed, err: %v", err)
			return "failed:bind input"
		}
	}
	iptablesOutputStatus, _ := settingRepo.GetValueByKey("IptablesOutputStatus")
	if iptablesOutputStatus == constant.StatusEnable {
		if err := iptablesService.Operate(dto.IptablesOp{Name: iptables.Chain1PanelOutput, Operate: "bind"}); err != nil {
			global.LOG.Errorf("[firewall-boot] bind output chains failed, err: %v", err)
			return "failed:bind output"
		}
	}
	// R1：迁移把"广源且覆盖保底端口"的旧 DENY 规则隔离进 deny.quarantine（未加载进内核）。
	// 仅在其余检查均正常（ok）时提示：failed 已提前 return，strict-suspended 更严重故不覆盖。
	if n := quarantinedDenyCount(); n > 0 && bootStatus == "ok" {
		bootStatus = fmt.Sprintf("degraded:quarantined %d legacy deny rules", n)
	}
	return bootStatus
}

// afterChainHasDrop 报告 v4 AFTER 内核链是否含任何 -j DROP 规则。
// 读失败按"存在 DROP"处理：宁可多触发一次保底端口断言（最坏是清空本就为空的 AFTER），不漏判锁外风险。
func afterChainHasDrop() bool {
	stdout, err := iptables.RunWithStd(iptables.FilterTab, "-S", iptables.Chain1PanelAfter)
	if err != nil {
		return true
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "-j DROP") {
			return true
		}
	}
	return false
}

// baselinePortsAllAccepted 回读断言 v4 BASELINE 链是否为全部保底端口都有 tcp ACCEPT 放行。
func baselinePortsAllAccepted(ports []string) bool {
	for _, p := range ports {
		if !iptables.CheckRuleExist(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", "tcp", "-m", "tcp", "--dport", p, "-j", "ACCEPT") {
			return false
		}
	}
	return true
}

// recordBootStatus 把开机自检结果写入 firewall_state 单行表，供 /firewall/base 横幅展示（设计稿 §3.8）。
func recordBootStatus(status string) {
	hostRepo := repo.NewIHostRepo()
	state, _ := hostRepo.GetFirewallState()
	if provider, err := firewall.Detect(); err == nil {
		state.Provider = provider.Name()
		state.Mode = string(provider.Mode())
	}
	state.LastBootStatus = status
	state.LastBootAt = time.Now()
	state.Consistent = strings.HasPrefix(status, "ok")
	state.LastCheckAt = time.Now()
	if err := hostRepo.SaveFirewallState(&state); err != nil {
		global.LOG.Warnf("[firewall-boot] record boot status failed: %v", err)
	}
	global.LOG.Infof("[firewall-boot] boot status: %s", status)
}

func needInit() bool {
	file, err := os.OpenFile("/run/1panel_boot_mark", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return false
		}
		global.LOG.Errorf("check boot mark file failed: %v", err)
		return true
	}
	defer file.Close()
	fmt.Fprintf(file, "Boot Mark for 1panel\n")
	return true
}

func InitPingStatus() {
	global.LOG.Info("initializing ban ping status from settings...")
	status := firewall.LoadPingStatus()
	statusInDB, _ := repo.NewISettingRepo().GetValueByKey("BanPing")
	if statusInDB == status {
		return
	}

	enable := "1"
	if statusInDB == constant.StatusDisable {
		enable = "0"
	}
	if err := firewall.UpdatePingStatus(enable); err != nil {
		global.LOG.Errorf("initialize ping status failed: %v", err)
	}
}
