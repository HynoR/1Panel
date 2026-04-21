package firewall

import (
	"fmt"

	"github.com/1Panel-dev/1Panel/core/utils/cmd"
)

// UpdatePort is a safety-first helper invoked from core when the 1Panel listen
// port changes. It opens the NEW port in whichever native firewall is running
// (firewalld or ufw), but deliberately does NOT remove the old port.
//
// Rationale: this runs in the core process, which bypasses the agent's rule
// tracking, snapshot capture, and caller-IP emergency accept. If the add
// succeeds but a subsequent reload fails, removing the old port would leave
// the admin unable to reach 1Panel on either port. Leaking one extra ACCEPT
// rule is cheap; locking the admin out is catastrophic. The stale rule can
// be cleaned up from the agent UI after the port swap is verified.
//
// The long-term fix is to route this through the agent's firewall service so
// a snapshot is captured, the rule metadata is tracked, and IP v6 gets the
// same treatment. Until that refactor lands, treat this function as an
// emergency "open new port" shim.
func UpdatePort(oldPort, newPort string) error {
	_ = oldPort

	if cmd.Which("firewalld") {
		status, _ := cmd.RunDefaultWithStdoutBashC("LANGUAGE=en_US:en firewall-cmd --state")
		if status == "running\n" {
			return firewallOpenPort(newPort)
		}
	}

	if cmd.Which("ufw") {
		status, _ := cmd.RunDefaultWithStdoutBashC("LANGUAGE=en_US:en ufw status | grep Status")
		if status == "Status: active\n" {
			return ufwOpenPort(newPort)
		}
	}
	return nil
}

func firewallOpenPort(newPort string) error {
	stdout, err := cmd.RunDefaultWithStdoutBashCf("firewall-cmd --zone=public --add-port=%s/tcp --permanent", newPort)
	if err != nil {
		return fmt.Errorf("add (port: %s/tcp) failed, err: %s", newPort, stdout)
	}
	_, _ = cmd.RunDefaultWithStdoutBashC("firewall-cmd --reload")
	return nil
}

func ufwOpenPort(newPort string) error {
	stdout, err := cmd.RunDefaultWithStdoutBashCf("ufw allow %s", newPort)
	if err != nil {
		return fmt.Errorf("add (port: %s/tcp) failed, err: %s", newPort, stdout)
	}
	return nil
}
