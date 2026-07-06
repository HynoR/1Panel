package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// 安全栈 L4 ② 的灾备命令（设计稿 §3.5）：供用户从云厂商 VNC/串口自救，
// 解绑全部 1PANEL_* 链或恢复最近一次快照——即使 agent 已崩溃也能用（纯 shell，无 DB/agent 依赖）。

func init() {
	firewallRescueCmd.Flags().BoolVar(&rescueRestoreLatest, "restore-latest", false, "restore the last known-good firewall snapshot: latest (taken before each pending change), falling back to pre-migrate (full iptables-restore)")
	firewallRescueCmd.Flags().BoolVar(&rescueCleanNewChains, "clean-new-chains", false, "also delete the 1PANEL_* chains, not just unbind them")
	firewallCmd.AddCommand(firewallRescueCmd)
	RootCmd.AddCommand(firewallCmd)
}

var (
	rescueRestoreLatest  bool
	rescueCleanNewChains bool
)

var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "1Panel firewall rescue utilities",
}

var firewallRescueCmd = &cobra.Command{
	Use:   "rescue",
	Short: "Recover from a firewall lockout (unbind 1PANEL_* chains or restore the latest snapshot)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !isRoot() {
			fmt.Println("Please run as root: sudo 1pctl firewall rescue")
			return nil
		}
		if rescueRestoreLatest {
			return rescueRestoreLatestSnapshot()
		}
		return rescueUnbindPanelChains()
	},
}

var rescueBaseChains = map[string][]string{
	// DOCKER-USER 也在此：rescue 须解绑挂在它下面的 1PANEL_DOCKER jump，否则
	// --clean-new-chains 删 1PANEL_DOCKER 会因仍被引用而失败，Docker 封禁残留（修 P2）。
	"filter": {"INPUT", "OUTPUT", "FORWARD", "DOCKER-USER"},
	"nat":    {"PREROUTING", "POSTROUTING", "OUTPUT"},
}

func rescueUnbindPanelChains() error {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if !rescueBinExists(bin) {
			continue
		}
		for table, chains := range rescueBaseChains {
			for _, chain := range chains {
				unbindPanelJumps(bin, table, chain)
			}
		}
		if rescueCleanNewChains {
			for _, table := range []string{"filter", "nat"} {
				for _, chain := range listPanelChains(bin, table) {
					_ = runRescue(bin, "-t", table, "-w", "-F", chain)
					_ = runRescue(bin, "-t", table, "-w", "-X", chain)
				}
			}
		}
	}
	fmt.Println("1Panel firewall chains unbound. SSH/panel should be reachable now.")
	fmt.Println("Restart the 1Panel agent (or reboot) to re-apply managed rules once you have fixed the configuration.")
	return nil
}

// 快照只有两个固定文件（无版本管理）：latest（每次武装提交-确认会话时覆盖写）优先，
// 无则回退 pre-migrate（升级迁移前的一次性留底）。
func rescueRestoreLatestSnapshot() error {
	baseDir, err := loadBaseDir()
	if err != nil {
		return err
	}
	backupDir := path.Join(baseDir, "1panel/firewall/backup")
	name := ""
	for _, candidate := range []string{"latest", "pre-migrate"} {
		if _, err := os.Stat(path.Join(backupDir, candidate+".v4")); err == nil {
			name = candidate
			break
		}
	}
	if name == "" {
		return fmt.Errorf("no firewall snapshot (latest.v4 / pre-migrate.v4) found in %s", backupDir)
	}
	fmt.Printf("Restoring snapshot %s (full iptables-restore)...\n", name)
	if err := restoreSnapshotFile(path.Join(backupDir, name+".v4"), "iptables-restore"); err != nil {
		return err
	}
	v6 := path.Join(backupDir, name+".v6")
	if _, err := os.Stat(v6); err == nil && rescueBinExists("ip6tables-restore") {
		if err := restoreSnapshotFile(v6, "ip6tables-restore"); err != nil {
			fmt.Printf("warning: restore ipv6 snapshot failed: %v\n", err)
		}
	}
	fmt.Println("Snapshot restored.")
	return nil
}

func restoreSnapshotFile(file, restoreBin string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	c := exec.Command(restoreBin)
	c.Stdin = f
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func unbindPanelJumps(bin, table, chain string) {
	for {
		num := firstPanelJumpNum(bin, table, chain)
		if num == 0 {
			return
		}
		if err := runRescue(bin, "-t", table, "-w", "-D", chain, strconv.Itoa(num)); err != nil {
			return
		}
	}
}

func firstPanelJumpNum(bin, table, chain string) int {
	out, err := runRescueOut(bin, "-t", table, "-w", "-L", chain, "--line-numbers", "-n")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if strings.HasPrefix(fields[1], "1PANEL_") {
			if n, err := strconv.Atoi(fields[0]); err == nil {
				return n
			}
		}
	}
	return 0
}

func listPanelChains(bin, table string) []string {
	out, err := runRescueOut(bin, "-t", table, "-w", "-S")
	if err != nil {
		return nil
	}
	var chains []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-N 1PANEL_") {
			chains = append(chains, strings.TrimPrefix(line, "-N "))
		}
	}
	return chains
}

func rescueBinExists(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func runRescue(bin string, args ...string) error {
	return exec.Command(bin, args...).Run()
}

func runRescueOut(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).Output()
	return string(out), err
}
