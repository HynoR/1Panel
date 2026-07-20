package service

import (
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall"
	fireClient "github.com/1Panel-dev/1Panel/agent/utils/firewall/client"
	"github.com/1Panel-dev/1Panel/agent/utils/firewall/client/iptables"
	"github.com/jinzhu/copier"
)

// External lane (UFW/firewalld): thin native proxy.
// Keeps dev-v2 command behavior; never creates 1PANEL managed filter chains.

func loadExternalInitStatus(clientName, tab string) (bool, bool) {
	// Preserve exact LoadInitStatus semantics, including ufw+forward checking iptables NAT/forward chains.
	return iptables.LoadInitStatus(clientName, tab)
}

func (u *FirewallService) operateExternalPortRule(client firewall.FirewallClient, req dto.PortRuleOperate, reload bool) error {
	protos := strings.Split(req.Protocol, "/")
	itemAddress := splitFirewallRuleAddresses(req.Address)

	if client.Name() == "ufw" {
		if strings.Contains(req.Port, ",") || strings.Contains(req.Port, "-") {
			for _, proto := range protos {
				for _, addr := range itemAddress {
					if len(addr) == 0 {
						addr = "Anywhere"
					}
					req.Address = addr
					req.Port = strings.ReplaceAll(req.Port, "-", ":")
					req.Protocol = proto
					if err := u.operateExternalPort(client, req); err != nil {
						return err
					}
					req.Port = strings.ReplaceAll(req.Port, ":", "-")
					if err := u.addPortRecord(req); err != nil {
						return err
					}
				}
			}
			return nil
		}
		for _, addr := range itemAddress {
			if len(addr) == 0 {
				addr = "Anywhere"
			}
			if req.Protocol == "tcp/udp" {
				req.Protocol = ""
			}
			req.Address = addr
			if err := u.operateExternalPort(client, req); err != nil {
				return err
			}
			if len(req.Protocol) == 0 {
				req.Protocol = "tcp/udp"
			}
			if err := u.addPortRecord(req); err != nil {
				return err
			}
		}
		return nil
	}

	// firewalld
	itemPorts := req.Port
	for _, proto := range protos {
		if strings.Contains(req.Port, "-") {
			for _, addr := range itemAddress {
				req.Protocol = proto
				req.Address = addr
				if err := u.operateExternalPort(client, req); err != nil {
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
					if err := u.operateExternalPort(client, req); err != nil {
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

func (u *FirewallService) operateExternalAddressRule(client firewall.FirewallClient, req dto.AddrRuleOperate, reload bool) error {
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
		if err := u.addAddressRecord("", req); err != nil {
			return err
		}
	}
	if reload {
		return client.Reload()
	}
	return nil
}

func (u *FirewallService) operateExternalPort(client firewall.FirewallClient, req dto.PortRuleOperate) error {
	var fireInfo fireClient.FireInfo
	if err := copier.Copy(&fireInfo, &req); err != nil {
		return err
	}
	fireInfo.Address = normalizeFirewallRuleAddress(fireInfo.Address)

	if client.Name() == "ufw" {
		if len(fireInfo.Address) != 0 && !strings.EqualFold(fireInfo.Address, "Anywhere") {
			return client.RichRules(fireInfo, req.Operation)
		}
		return client.Port(fireInfo, req.Operation)
	}

	if len(fireInfo.Address) != 0 || fireInfo.Strategy == "drop" {
		return client.RichRules(fireInfo, req.Operation)
	}
	return client.Port(fireInfo, req.Operation)
}

func (u *FirewallService) addExternalPortsBeforeStart(client firewall.FirewallClient) error {
	portWhiteList, err := loadFirewallPortWhiteList()
	if err != nil {
		return err
	}
	for _, item := range portWhiteList {
		if err := client.Port(fireClient.FireInfo{Port: item.Port, Protocol: item.Protocol, Strategy: "accept"}, "add"); err != nil {
			return err
		}
	}
	return client.Reload()
}

func syncExternalFirewallPortWhiteList(client firewall.FirewallClient, oldValue string) error {
	isActive, _ := client.Status()
	if !isActive {
		return nil
	}
	portWhiteList, err := loadFirewallPortWhiteList()
	if err != nil {
		return err
	}
	oldPortWhiteList, err := parseFirewallPortWhiteList(oldValue)
	if err != nil {
		return err
	}
	requiredPorts, err := loadRequiredFirewallPortWhiteList()
	if err != nil {
		return err
	}
	oldPortWhiteList = normalizeFirewallPortWhiteList(append(oldPortWhiteList, requiredPorts...))
	return syncFirewallClientPortWhiteList(client, oldPortWhiteList, portWhiteList)
}
