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
	migrateLegacyChains()

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
	panelPort := service.LoadPanelPort()
	if len(panelPort) == 0 {
		global.LOG.Errorf("[firewall-boot] find 1panel service port failed")
		return "failed:find panel port"
	}
	// 保底注入：面板端口 ACCEPT 进 BASELINE（回读校验见下）。
	if err := iptables.AddRule(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", "tcp", "-m", "tcp", "--dport", panelPort, "-j", "ACCEPT"); err != nil {
		global.LOG.Errorf("[firewall-boot] add panel port accept rule %v failed, err: %v", panelPort, err)
		return "failed:inject baseline"
	}
	global.LOG.Infof("[firewall-boot] loaded iptables base chains from file successfully")

	iptablesService := service.IptablesService{}
	iptablesStatus, _ := settingRepo.GetValueByKey("IptablesStatus")
	bootStatus := "ok"
	if iptablesStatus == constant.StatusEnable {
		if err := iptablesService.Operate(dto.IptablesOp{Operate: "bind-base-without-init"}); err != nil {
			global.LOG.Errorf("[firewall-boot] bind base chains failed, err: %v", err)
			return "failed:bind base"
		}
		// L4：回读校验 BASELINE 面板端口 ACCEPT 是否存在；缺失则降级告警（不阻断，但 UI 横幅提示）。
		if !iptables.CheckRuleExist(iptables.FilterTab, iptables.Chain1PanelBaseline, "-p", "tcp", "-m", "tcp", "--dport", panelPort, "-j", "ACCEPT") {
			global.LOG.Warnf("[firewall-boot] baseline panel port accept verification failed")
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
	return bootStatus
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
