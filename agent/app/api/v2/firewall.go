package v2

import (
	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/utils/callerip"
	"github.com/gin-gonic/gin"
)

// firewallCallerIP 返回调用方真实客户端 IP（B9 单 IP 自锁检测用）。
// 优先读 FirewallEmergency 中间件解析并写入 context 的结果（单点解析）；
// 未挂该中间件的路由回退自行解析。信任模型见 callerip.Resolve：
// unix socket 采信 core 注入的受信头，TCP 用 RemoteAddr。
func firewallCallerIP(c *gin.Context) string {
	if v, ok := c.Get(callerip.ContextKey); ok {
		if ip, ok := v.(string); ok && ip != "" {
			return ip
		}
	}
	return callerip.Resolve(c.Request)
}

// @Tags Firewall
// @Summary Load firewall base info
// @Accept json
// @Param request body dto.OperationWithName true "request"
// @Success 200 {object} dto.FirewallBaseInfo
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/base [post]
func (b *BaseApi) LoadFirewallBaseInfo(c *gin.Context) {
	var req dto.OperationWithName
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	data, err := firewallService.LoadBaseInfo(req.Name)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}

	helper.SuccessWithData(c, data)
}

// @Tags Firewall
// @Summary Page firewall rules
// @Accept json
// @Param request body dto.RuleSearch true "request"
// @Success 200 {object} dto.PageResult
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/search [post]
func (b *BaseApi) SearchFirewallRule(c *gin.Context) {
	var req dto.RuleSearch
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	total, list, err := firewallService.SearchWithPage(req)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}

	helper.SuccessWithData(c, dto.PageResult{
		Items: list,
		Total: total,
	})
}

// @Tags Firewall
// @Summary Operate firewall
// @Accept json
// @Param request body dto.FirewallOperation true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/operate [post]
// @x-panel-log {"bodyKeys":["operation"],"paramKeys":[],"BeforeFunctions":[],"formatZH":"[operation] 防火墙","formatEN":"[operation] firewall"}
func (b *BaseApi) OperateFirewall(c *gin.Context) {
	var req dto.FirewallOperation
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	if err := firewallService.OperateFirewall(req); err != nil {
		helper.InternalServer(c, err)
		return
	}

	helper.Success(c)
}

// @Tags Firewall
// @Summary Create group
// @Accept json
// @Param request body dto.PortRuleOperate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/port [post]
// @x-panel-log {"bodyKeys":["port","strategy"],"paramKeys":[],"BeforeFunctions":[],"formatZH":"添加端口规则 [strategy] [port]","formatEN":"create port rules [strategy][port]"}
func (b *BaseApi) OperatePortRule(c *gin.Context) {
	var req dto.PortRuleOperate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	if err := firewallService.OperatePortRule(req, true); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// OperateForwardRule
// @Tags Firewall
// @Summary Operate forward rule
// @Accept json
// @Param request body dto.ForwardRuleOperate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/forward [post]
// @x-panel-log {"bodyKeys":[],"paramKeys":[],"BeforeFunctions":[],"formatZH":"更新端口转发规则","formatEN":"update port forward rules"}
func (b *BaseApi) OperateForwardRule(c *gin.Context) {
	var req dto.ForwardRuleOperate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	if err := firewallService.OperateForwardRule(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Operate Ip rule
// @Accept json
// @Param request body dto.AddrRuleOperate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/ip [post]
// @x-panel-log {"bodyKeys":["strategy","address"],"paramKeys":[],"BeforeFunctions":[],"formatZH":"添加 ip 规则 [strategy] [address]","formatEN":"create address rules [strategy][address]"}
func (b *BaseApi) OperateIPRule(c *gin.Context) {
	var req dto.AddrRuleOperate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	req.CallerIP = firewallCallerIP(c)

	if err := firewallService.OperateAddressRule(req, true); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Batch operate rule
// @Accept json
// @Param request body dto.BatchRuleOperate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/batch [post]
func (b *BaseApi) BatchOperateRule(c *gin.Context) {
	var req dto.BatchRuleOperate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	req.CallerIP = firewallCallerIP(c)

	if err := firewallService.BatchOperateRule(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Update rule description
// @Accept json
// @Param request body dto.UpdateFirewallDescription true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/update/description [post]
func (b *BaseApi) UpdateFirewallDescription(c *gin.Context) {
	var req dto.UpdateFirewallDescription
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	if err := firewallService.UpdateDescription(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Update port rule
// @Accept json
// @Param request body dto.PortRuleUpdate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/update/port [post]
func (b *BaseApi) UpdatePortRule(c *gin.Context) {
	var req dto.PortRuleUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	if err := firewallService.UpdatePortRule(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Update Ip rule
// @Accept json
// @Param request body dto.AddrRuleUpdate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/update/addr [post]
func (b *BaseApi) UpdateAddrRule(c *gin.Context) {
	var req dto.AddrRuleUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	callerIP := firewallCallerIP(c)
	req.OldRule.CallerIP = callerIP
	req.NewRule.CallerIP = callerIP

	if err := firewallService.UpdateAddrRule(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Clean orphan firewall rule descriptions
// @Accept json
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/clean [post]
func (b *BaseApi) CleanOrphanFirewallRecords(c *gin.Context) {
	if err := firewallService.CleanOrphanFirewallRecords(); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary List quarantined legacy deny rules
// @Accept json
// @Success 200 {array} string
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/quarantine [get]
func (b *BaseApi) ListFirewallQuarantine(c *gin.Context) {
	list, err := firewallService.ListQuarantineRules()
	if err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.SuccessWithData(c, list)
}

// @Tags Firewall
// @Summary Clean quarantined legacy deny rules
// @Accept json
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/quarantine/clean [post]
func (b *BaseApi) CleanFirewallQuarantine(c *gin.Context) {
	if err := firewallService.CleanQuarantineRules(); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Load commit-confirm session status
// @Accept json
// @Success 200 {object} dto.FirewallSessionInfo
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/session/status [post]
func (b *BaseApi) LoadFirewallSession(c *gin.Context) {
	helper.SuccessWithData(c, firewallService.SessionStatus())
}

// @Tags Firewall
// @Summary Confirm commit-confirm session
// @Accept json
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/session/confirm [post]
func (b *BaseApi) ConfirmFirewallSession(c *gin.Context) {
	if err := firewallService.ConfirmSession(); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Revert commit-confirm session
// @Accept json
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/session/revert [post]
func (b *BaseApi) RevertFirewallSession(c *gin.Context) {
	if err := firewallService.RevertSession(); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Allow the new panel port (core delegates here on port change)
// @Accept json
// @Param request body dto.PanelPortUpdate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/panel-port [post]
func (b *BaseApi) UpdateFirewallPanelPort(c *gin.Context) {
	var req dto.PanelPortUpdate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := firewallService.UpdatePanelPort(req); err != nil {
		helper.InternalServer(c, err)
		return
	}
	helper.Success(c)
}

// @Tags Firewall
// @Summary Docker protection status
// @Accept json
// @Success 200 {object} dto.FirewallDockerStatus
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/docker/status [post]
func (b *BaseApi) LoadFirewallDockerStatus(c *gin.Context) {
	helper.SuccessWithData(c, firewallService.DockerStatus())
}

// @Tags Firewall
// @Summary search iptables filter rules
// @Accept json
// @Param request body dto.SearchPageWithType true "request"
// @Success 200 {object} dto.PageResult
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/filter/rule/search [post]
func (b *BaseApi) SearchFilterRules(c *gin.Context) {
	var req dto.SearchPageWithType
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	total, list, err := iptablesService.Search(req)
	if err != nil {
		helper.InternalServer(c, err)
		return
	}

	helper.SuccessWithData(c, dto.PageResult{
		Items: list,
		Total: total,
	})
}

// @Tags Firewall
// @Summary Operate iptables filter rule
// @Accept json
// @Param request body dto.IptablesRuleOp true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/filter/rule/operate [post]
// @x-panel-log {"bodyKeys":["operation","chain"],"paramKeys":[],"BeforeFunctions":[],"formatZH":"[operation] filter规则到 [chain]","formatEN":"[operation] filter rule to [chain]"}
func (b *BaseApi) OperateFilterRule(c *gin.Context) {
	var req dto.IptablesRuleOp
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := iptablesService.OperateRule(req, true); err != nil {
		helper.InternalServer(c, err)
		return
	}

	helper.Success(c)
}

// @Tags Firewall
// @Summary Batch operate iptables filter rules
// @Accept json
// @Param request body dto.IptablesBatchOperate true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/filter/rule/batch [post]
func (b *BaseApi) BatchOperateFilterRule(c *gin.Context) {
	var req dto.IptablesBatchOperate
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	if err := iptablesService.BatchOperate(req); err != nil {
		helper.InternalServer(c, err)
		return
	}

	helper.Success(c)
}

// @Tags Firewall
// @Summary Apply/Unload/Init iptables filter
// @Accept json
// @Param request body dto.IptablesOp true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/filter/operate [post]
// @x-panel-log {"bodyKeys":["operate"],"paramKeys":[],"BeforeFunctions":[],"formatZH":"[operate] iptables filter 防火墙","formatEN":"[operate] iptables filter firewall"}
func (b *BaseApi) OperateFilterChain(c *gin.Context) {
	var req dto.IptablesOp
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}
	if err := iptablesService.Operate(req); err != nil {
		helper.InternalServer(c, err)
		return
	}

	helper.Success(c)
}

// @Tags Firewall
// @Summary load chain status with name
// @Accept json
// @Param request body dto.OperationWithName true "request"
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /hosts/firewall/filter/chain/status [post]
func (b *BaseApi) LoadChainStatus(c *gin.Context) {
	var req dto.OperationWithName
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	helper.SuccessWithData(c, iptablesService.LoadChainStatus(req))
}
