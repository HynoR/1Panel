package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

const (
	// 旧布局文件（迁移用，保留两个版本）。
	BasicBeforeFileName = "1panel_basic_before.rules"
	BasicFileName       = "1panel_basic.rules"
	BasicAfterFileName  = "1panel_basic_after.rules"

	// 新布局文件（设计稿 §3.4）。
	GuardFileName    = "1panel_guard.rules"
	DenyFileName     = "1panel_deny.rules"
	BaselineFileName = "1panel_baseline.rules"
	AllowFileName    = "1panel_allow.rules"
	AfterFileName    = "1panel_after.rules"
	DockerFileName   = "1panel_docker.rules"

	InputFileName    = "1panel_input.rules"
	OutputFileName   = "1panel_out.rules"
	ForwardFileName  = "1panel_forward.rules"
	ForwardFileName1 = "1panel_forward_pre.rules"
	ForwardFileName2 = "1panel_forward_post.rules"
)

// ChainFileName 返回某条 1PANEL 链对应的持久化文件名。
func ChainFileName(chain string) string {
	switch chain {
	case Chain1PanelGuard:
		return GuardFileName
	case Chain1PanelDeny:
		return DenyFileName
	case Chain1PanelBaseline:
		return BaselineFileName
	case Chain1PanelAllow:
		return AllowFileName
	case Chain1PanelAfter:
		return AfterFileName
	case Chain1PanelDocker:
		return DockerFileName
	case Chain1PanelInput:
		return InputFileName
	case Chain1PanelOutput:
		return OutputFileName
	case Chain1PanelForward:
		return ForwardFileName
	case Chain1PanelBasicBefore:
		return BasicBeforeFileName
	case Chain1PanelBasic:
		return BasicFileName
	case Chain1PanelBasicAfter:
		return BasicAfterFileName
	default:
		return ""
	}
}

func SaveRulesToFile(tab, chain, fileName string) error {
	rulesFile := path.Join(global.Dir.FirewallDir, fileName)

	stdout, err := RunWithStd(tab, "-S", chain)
	if err != nil {
		return fmt.Errorf("failed to list %s rules: %w", chain, err)
	}
	var rules []string
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, fmt.Sprintf("-A %s", chain)) {
			rules = append(rules, line)
		}
	}

	file, err := os.Create(rulesFile)
	if err != nil {
		return fmt.Errorf("failed to create rules file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, rule := range rules {
		_, err := writer.WriteString(rule + "\n")
		if err != nil {
			return fmt.Errorf("failed to write rule to file: %w", err)
		}
	}

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("failed to flush rules to file: %w", err)
	}

	global.LOG.Infof("persistence rules to %s successful", rulesFile)
	return nil
}

func LoadRulesFromFile(tab, chain, fileName string) error {
	if err := AddChain(tab, chain); err != nil {
		global.LOG.Errorf("create chain %s failed: %v", chain, err)
		return err
	}
	rulesFile := path.Join(global.Dir.FirewallDir, fileName)
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		return nil
	}
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		global.LOG.Errorf("read rules from file %s failed, err: %v", rulesFile, err)
		return err
	}
	rules := strings.Split(string(data), "\n")
	if err := ClearChain(tab, chain); err != nil {
		global.LOG.Warnf("clear existing rules from %s failed, err: %v", chain, err)
	}

	for _, rule := range rules {
		if strings.HasPrefix(rule, fmt.Sprintf("-A %s", chain)) {
			if err := restoreRule(tab, rule); err != nil {
				global.LOG.Errorf("apply rule '%s' failed, err: %v", rule, err)
			}
		}
	}

	return nil
}

func restoreRule(tab, rule string) error {
	restoreInput := fmt.Sprintf("*%s\n%s\nCOMMIT\n", tab, rule)
	commandName, commandArgs := cmd.WrapWithOptionalSudo("iptables-restore", "-n")
	_, err := cmd.NewCommandMgr().RunPipe(cmd.PipeCommand{
		Name:  commandName,
		Args:  commandArgs,
		Stdin: bytes.NewReader([]byte(restoreInput)),
	})
	return err
}
