package firewall

import (
	"fmt"
	"os"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/repo"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	firewallClient "github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/nftables"
)

// Init runs once per host boot (guarded by /run/1panel_boot_mark) to restore the
// previously persisted firewall state. Boot-time is the single most dangerous
// moment for lock-outs because persisted chains can contain a final DROP-all
// rule while ACCEPT rules for SSH/panel ports might be stale (e.g. the admin
// changed the SSH port since the last save).
//
// Safety contract enforced by this function:
//  1. Rule files are loaded with staging-chain pre-validation (iptables) or
//     an atomic nft -f transaction (nftables). A malformed rule aborts the
//     load and leaves the target table untouched.
//  2. Current SSH and panel ports are re-injected as emergency ACCEPT rules
//     after load, independent of what the file says.
//  3. The emergency rules are verified by re-reading the chain.
//  4. Only if every step above succeeds do we bind the managed chains into
//     INPUT. Any failure returns early, leaving INPUT's default policy
//     (typically ACCEPT) in effect so the host stays reachable and the admin
//     can recover.
func Init() {
	if !needInit() {
		return
	}
	InitPingStatus()
	global.LOG.Info("initializing firewall settings...")
	client, err := firewall.NewFirewallClient()
	if err != nil {
		return
	}
	clientName := client.Name()

	settingRepo := repo.NewISettingRepo()

	if clientName == firewall.ProviderNftables {
		initNftablesBackend(settingRepo, client)
		return
	}

	if clientName == "ufw" || clientName == "iptables" {
		if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelForward, iptables.ForwardFileName); err != nil {
			global.LOG.Errorf("[firewall-boot] load forward rules failed, refusing to proceed: %v", err)
			return
		}
		if err := iptables.LoadRulesFromFile(iptables.NatTab, iptables.Chain1PanelPreRouting, iptables.ForwardFileName1); err != nil {
			global.LOG.Errorf("[firewall-boot] load prerouting rules failed, refusing to proceed: %v", err)
			return
		}
		if err := iptables.LoadRulesFromFile(iptables.NatTab, iptables.Chain1PanelPostRouting, iptables.ForwardFileName2); err != nil {
			global.LOG.Errorf("[firewall-boot] load postrouting rules failed, refusing to proceed: %v", err)
			return
		}
		global.LOG.Infof("loaded iptables rules for forward from file successfully")

		iptablesForwardStatus, _ := settingRepo.GetValueByKey("IptablesForwardStatus")
		if iptablesForwardStatus == constant.StatusEnable {
			if err := firewallClient.EnableIptablesForward(); err != nil {
				global.LOG.Errorf("enable iptables forward failed, err: %v", err)
				return
			}
		}
	}

	if clientName != "iptables" {
		return
	}

	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelBasicBefore, iptables.BasicBeforeFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] load BASIC_BEFORE failed, refusing to bind: %v", err)
		return
	}
	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelBasic, iptables.BasicFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] load BASIC failed, refusing to bind: %v", err)
		return
	}
	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelBasicAfter, iptables.BasicAfterFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] load BASIC_AFTER failed, refusing to bind: %v", err)
		return
	}

	panelPort := service.LoadPanelPort()
	if len(panelPort) == 0 {
		global.LOG.Errorf("[firewall-boot] cannot resolve 1panel service port, refusing to bind")
		return
	}
	sshPort := service.LoadSSHPort()
	emergencySpecs := iptables.EmergencyAccepts(sshPort, panelPort, []string{"80", "443"})
	if err := iptables.EnsureEmergencyAccepts(iptables.FilterTab, iptables.Chain1PanelBasicBefore, emergencySpecs); err != nil {
		global.LOG.Errorf("[firewall-boot] inject emergency accepts failed, refusing to bind: %v", err)
		return
	}
	if err := iptables.VerifyRulesExist(iptables.FilterTab, iptables.Chain1PanelBasicBefore, emergencySpecs); err != nil {
		global.LOG.Errorf("[firewall-boot] emergency accept verification failed, refusing to bind: %v", err)
		return
	}
	if err := iptables.EnsureIPv6EmergencyAccepts(sshPort, panelPort, []string{"80", "443"}); err != nil {
		global.LOG.Errorf("[firewall-boot] inject ipv6 emergency accepts failed, refusing to bind: %v", err)
		return
	}
	if err := iptables.VerifyIPv6EmergencyAccepts(sshPort, panelPort, []string{"80", "443"}); err != nil {
		global.LOG.Errorf("[firewall-boot] ipv6 emergency verification failed, refusing to bind: %v", err)
		return
	}
	global.LOG.Infof("[firewall-boot] emergency accepts verified on %s (ssh=%s panel=%s, v4+v6)", iptables.Chain1PanelBasicBefore, sshPort, panelPort)

	global.LOG.Infof("loaded iptables rules for basic from file successfully")
	iptablesService := service.IptablesService{}
	iptablesStatus, _ := settingRepo.GetValueByKey("IptablesStatus")
	if iptablesStatus == constant.StatusEnable {
		if err := iptablesService.Operate(dto.IptablesOp{Operate: "bind-base-without-init"}); err != nil {
			global.LOG.Errorf("bind base chains failed, err: %v", err)
			return
		}
	}

	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelInput, iptables.InputFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] load INPUT advanced rules failed, skipping bind: %v", err)
		return
	}
	if err := iptables.LoadRulesFromFile(iptables.FilterTab, iptables.Chain1PanelOutput, iptables.OutputFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] load OUTPUT advanced rules failed, skipping bind: %v", err)
		return
	}
	global.LOG.Infof("loaded iptables rules for input and output from file successfully")
	iptablesInputStatus, _ := settingRepo.GetValueByKey("IptablesInputStatus")
	if iptablesInputStatus == constant.StatusEnable {
		if err := iptablesService.Operate(dto.IptablesOp{Name: iptables.Chain1PanelInput, Operate: "bind"}); err != nil {
			global.LOG.Errorf("bind input chains failed, err: %v", err)
			return
		}
	}
	iptablesOutputStatus, _ := settingRepo.GetValueByKey("IptablesOutputStatus")
	if iptablesOutputStatus == constant.StatusEnable {
		if err := iptablesService.Operate(dto.IptablesOp{Name: iptables.Chain1PanelOutput, Operate: "bind"}); err != nil {
			global.LOG.Errorf("bind output chains failed, err: %v", err)
			return
		}
	}
}

// initNftablesBackend mirrors the iptables boot flow for a host running
// with FirewallProvider=nftables:
//  1. Make sure the inet 1panel / ip 1panel_nat topology exists.
//  2. Replay persisted rulesets with a single nft transaction each so
//     a corrupt file can't leave the table half-populated.
//  3. Re-ensure topology (an atomic restore rebuilds hook chains too,
//     but Reload is idempotent and cheap — cheaper than debugging a
//     missed jump).
//  4. Flip IP forwarding back on if the last user choice was "enable".
//  5. Inject + verify emergency accepts. nft's `inet` family already
//     covers both IPv4 and IPv6, so no separate v6 step is needed.
func initNftablesBackend(settingRepo repo.ISettingRepo, c firewall.FirewallClient) {
	if err := c.Reload(); err != nil {
		global.LOG.Errorf("[firewall-boot] nft topology ensure failed, refusing to proceed: %v", err)
		return
	}
	if err := nftables.LoadTable(nftables.InetFamily, nftables.FilterTable, nftables.FilterFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] nft load filter table failed, refusing to proceed: %v", err)
		return
	}
	if err := nftables.LoadTable(nftables.IPFamily, nftables.NatTable, nftables.NatFileName); err != nil {
		global.LOG.Errorf("[firewall-boot] nft load nat table failed, refusing to proceed: %v", err)
		return
	}
	if err := c.Reload(); err != nil {
		global.LOG.Errorf("[firewall-boot] nft post-load topology ensure failed: %v", err)
		return
	}

	forwardStatus, _ := settingRepo.GetValueByKey("IptablesForwardStatus")
	if forwardStatus == constant.StatusEnable {
		if err := c.EnableForward(); err != nil {
			global.LOG.Errorf("[firewall-boot] nft enable forward failed: %v", err)
			return
		}
	}

	panelPort := service.LoadPanelPort()
	if len(panelPort) == 0 {
		global.LOG.Errorf("[firewall-boot] cannot resolve 1panel service port, refusing to inject nft emergency")
		return
	}
	sshPort := service.LoadSSHPort()
	specs := nftables.EmergencyAcceptSpecs(sshPort, panelPort, []string{"80", "443"})
	if err := nftables.EnsureEmergencyAccepts(nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBefore, specs); err != nil {
		global.LOG.Errorf("[firewall-boot] nft inject emergency accepts failed: %v", err)
		return
	}
	if err := nftables.VerifyEmergencyAccepts(nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBefore, specs); err != nil {
		global.LOG.Errorf("[firewall-boot] nft emergency accept verification failed: %v", err)
		return
	}
	global.LOG.Infof("[firewall-boot] nft emergency accepts verified on %s %s %s (ssh=%s panel=%s, inet covers v4+v6)",
		nftables.InetFamily, nftables.FilterTable, nftables.ChainPanelBefore, sshPort, panelPort)
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
