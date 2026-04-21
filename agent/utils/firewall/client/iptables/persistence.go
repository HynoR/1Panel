package iptables

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/global"
)

const (
	BasicBeforeFileName = "1panel_basic_before.rules"
	BasicFileName       = "1panel_basic.rules"
	BasicAfterFileName  = "1panel_basic_after.rules"
	InputFileName       = "1panel_input.rules"
	OutputFileName      = "1panel_out.rules"
	ForwardFileName     = "1panel_forward.rules"
	ForwardFileName1    = "1panel_forward_pre.rules"
	ForwardFileName2    = "1panel_forward_post.rules"
)

func SaveRulesToFile(tab, chain, fileName string) error {
	rulesFile := path.Join(global.Dir.FirewallDir, fileName)

	stdout, err := RunWithStd(tab, fmt.Sprintf("-S %s", chain))
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

// LoadRulesFromFile loads persisted rules from fileName into chain.
//
// The loader is fail-fast and pre-validates via a staging chain: rules are first
// replayed into <chain>_STAGE. Only if every rule is accepted there do we flush the
// target chain and replicate them. A malformed rule therefore aborts the entire load
// and leaves the target chain untouched, instead of partially populating it and
// silently dropping protective ACCEPT rules while leaving destructive DROP-all rules
// in sibling chains. Callers (notably boot Init) must honour the error and refuse to
// bind the chain to INPUT/OUTPUT on failure.
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

	chainPrefix := fmt.Sprintf("-A %s ", chain)
	chainPrefixNoSpace := fmt.Sprintf("-A %s", chain)
	var rules []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimRight(line, "\r\n\t ")
		if len(trimmed) == 0 {
			continue
		}
		if !strings.HasPrefix(trimmed, chainPrefixNoSpace) {
			continue
		}
		rules = append(rules, trimmed)
	}

	if len(rules) == 0 {
		if err := ClearChain(tab, chain); err != nil {
			global.LOG.Warnf("clear rules from %s failed, err: %v", chain, err)
		}
		return nil
	}

	stageChain := chain + "_STAGE"
	_ = removeChainIfExists(tab, stageChain)
	if err := NewChain(tab, stageChain); err != nil {
		return fmt.Errorf("create stage chain %s failed: %w", stageChain, err)
	}
	defer func() { _ = removeChainIfExists(tab, stageChain) }()

	stagePrefix := fmt.Sprintf("-A %s ", stageChain)
	for _, r := range rules {
		stageRule := stagePrefix + strings.TrimPrefix(r, chainPrefix)
		if err := Run(tab, stageRule); err != nil {
			return fmt.Errorf("validate rule %q into %s failed: %w", r, stageChain, err)
		}
	}

	if err := ClearChain(tab, chain); err != nil {
		global.LOG.Warnf("clear existing rules from %s failed, err: %v", chain, err)
	}
	for _, r := range rules {
		if err := Run(tab, r); err != nil {
			return fmt.Errorf("apply validated rule %q to %s failed: %w", r, chain, err)
		}
	}

	global.LOG.Infof("loaded %d rules into chain %s from %s", len(rules), chain, fileName)
	return nil
}

// removeChainIfExists flushes and deletes a chain. No-op if the chain is absent.
func removeChainIfExists(tab, chain string) error {
	exist, err := CheckChainExist(tab, chain)
	if err != nil {
		return err
	}
	if !exist {
		return nil
	}
	if err := ClearChain(tab, chain); err != nil {
		return err
	}
	return Run(tab, "-X "+chain)
}
