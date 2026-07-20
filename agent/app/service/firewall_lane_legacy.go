package service

import (
	"fmt"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	fireClient "github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
	"github.com/jinzhu/copier"
)

// Legacy-v1 lane (iptables): keeps the current dev-v2 self-managed filter implementation.

func loadLegacyInitStatus(tab string) (bool, bool) {
	return iptables.LoadInitStatus("iptables", tab)
}

func (u *FirewallService) operateLegacyPortRule(client firewall.FilterClient, req dto.PortRuleOperate, reload bool) error {
	if len(req.Chain) == 0 {
		req.Chain = iptables.Chain1PanelBasic
	}
	protos := strings.Split(req.Protocol, "/")
	itemAddress := splitFirewallRuleAddresses(req.Address)

	itemPorts := req.Port
	for _, proto := range protos {
		if strings.Contains(req.Port, "-") {
			for _, addr := range itemAddress {
				req.Protocol = proto
				req.Address = addr
				if err := u.operateLegacyPort(client, req); err != nil {
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
					if err := u.operateLegacyPort(client, req); err != nil {
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

func (u *FirewallService) operateLegacyAddressRule(client firewall.FilterClient, req dto.AddrRuleOperate, reload bool) error {
	chain := iptables.Chain1PanelBasic
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

func (u *FirewallService) operateLegacyPort(client firewall.FilterClient, req dto.PortRuleOperate) error {
	var fireInfo fireClient.FireInfo
	if err := copier.Copy(&fireInfo, &req); err != nil {
		return err
	}
	fireInfo.Address = normalizeFirewallRuleAddress(fireInfo.Address)

	if len(fireInfo.Address) != 0 || fireInfo.Strategy == "drop" {
		return client.RichRules(fireInfo, req.Operation)
	}
	return client.Port(fireInfo, req.Operation)
}

func (u *FirewallService) addLegacyPortsBeforeStart(client firewall.FilterClient) error {
	isInit, _ := iptables.LoadInitStatus("iptables", "base")
	if !isInit {
		return nil
	}
	return syncIptablesFirewallPortWhiteList(true)
}

func syncLegacyFirewallPortWhiteList(oldValue string) error {
	isInit, _ := iptables.LoadInitStatus("iptables", "base")
	if !isInit {
		return nil
	}
	oldPortWhiteList, err := parseFirewallPortWhiteList(oldValue)
	if err != nil {
		return err
	}
	return syncIptablesFirewallPortWhiteList(true, oldPortWhiteList)
}

func listLegacyFilterRules(client firewall.FilterClient, ruleType string) ([]fireClient.FireInfo, error) {
	switch ruleType {
	case "port":
		return client.ListPort()
	case "address":
		return client.ListAddress()
	default:
		return nil, fmt.Errorf("unsupported legacy filter rule type: %s", ruleType)
	}
}

func operateLegacyFilterLifecycle(client firewall.FilterClient, operation string) error {
	return operateFilterLifecycle(client, operation)
}

func operateLegacyFirewallPort(client firewall.FilterClient, oldPorts, newPorts []int) error {
	return operateFirewallPorts(client, oldPorts, newPorts)
}
