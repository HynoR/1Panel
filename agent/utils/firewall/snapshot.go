package firewall

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/cmd"
)

// 快照只保留两个固定文件、零版本管理（2026-07-06 会议结论：持久化由每链文件 + 开机重放保证，
// 快照不做版本控制）：
//   - pre-migrate.{v4,v6}：升级迁移前的一次性全量留底（迁移唯一回滚锚点），存在即不再覆盖；
//   - latest.{v4,v6}：每次武装提交-确认会话时覆盖写，仅供 `1pctl firewall rescue --restore-latest`
//     在面板失联时做全量 iptables-restore 自救。
//
// 会话回滚不再解析 iptables-save 输出做限定恢复，改用会话开始时的 pre-session 逐链文件重载
// （见 session.go，与开机重放共用同一套 Save/LoadRulesFromFile 代码）。

const (
	snapshotLatestName     = "latest"
	snapshotPreMigrateName = "pre-migrate"
)

func snapshotDir() string {
	return path.Join(global.Dir.FirewallDir, "backup")
}

// WriteRescueSnapshot 覆盖写 latest.{v4,v6} 全量留底（v4 失败即上抛，v6 best-effort）。
func WriteRescueSnapshot() error {
	return writeSnapshotFiles(snapshotLatestName, true)
}

// WritePreMigrateSnapshot 写 pre-migrate.{v4,v6}；已存在则不覆盖（它是最老的可回退状态）。
func WritePreMigrateSnapshot() error {
	return writeSnapshotFiles(snapshotPreMigrateName, false)
}

func writeSnapshotFiles(name string, overwrite bool) error {
	dir := snapshotDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create snapshot dir failed: %w", err)
	}
	v4Path := path.Join(dir, name+".v4")
	if !overwrite {
		if _, err := os.Stat(v4Path); err == nil {
			return nil
		}
	}
	v4, err := saveOutput("iptables-save")
	if err != nil {
		return fmt.Errorf("iptables-save failed: %w", err)
	}
	if err := os.WriteFile(v4Path, []byte(v4), 0600); err != nil {
		return err
	}
	if cmd.Which("ip6tables-save") {
		if v6, err := saveOutput("ip6tables-save"); err == nil {
			_ = os.WriteFile(path.Join(dir, name+".v6"), []byte(v6), 0600)
		}
	}
	global.LOG.Infof("[firewall-snapshot] captured %s", name)
	return nil
}

func saveOutput(bin string) (string, error) {
	return cmd.NewCommandMgr(cmd.WithTimeout(60 * time.Second)).RunWithOptionalSudoAndStdout(bin)
}
