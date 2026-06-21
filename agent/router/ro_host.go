package router

import (
	v2 "github.com/1Panel-dev/1Panel/agent/app/api/v2"
	"github.com/1Panel-dev/1Panel/agent/middleware"
	"github.com/gin-gonic/gin"
)

type HostRouter struct{}

func (s *HostRouter) InitRouter(Router *gin.RouterGroup) {
	hostRouter := Router.Group("hosts")
	baseApi := v2.ApiGroupApp.BaseApi
	{
		hostRouter.POST("", baseApi.CreateHost)
		hostRouter.POST("/info", baseApi.GetHostByID)
		hostRouter.POST("/del", baseApi.DeleteHost)
		hostRouter.POST("/update", baseApi.UpdateHost)
		hostRouter.POST("/update/group", baseApi.UpdateHostGroup)
		hostRouter.POST("/search", baseApi.SearchHost)
		hostRouter.POST("/tree", baseApi.HostTree)
		hostRouter.POST("/test/byinfo", baseApi.TestByInfo)
		hostRouter.POST("/test/byid", baseApi.TestByID)

		// L2 安全栈：变更型端点统一挂 caller-IP 紧急放行中间件（设计稿 §3.5）。
		fwEmergency := middleware.FirewallEmergency()
		hostRouter.POST("/firewall/base", baseApi.LoadFirewallBaseInfo)
		hostRouter.POST("/firewall/search", baseApi.SearchFirewallRule)
		hostRouter.POST("/firewall/operate", baseApi.OperateFirewall)
		hostRouter.POST("/firewall/port", fwEmergency, baseApi.OperatePortRule)
		hostRouter.POST("/firewall/forward", fwEmergency, baseApi.OperateForwardRule)
		hostRouter.POST("/firewall/ip", fwEmergency, baseApi.OperateIPRule)
		hostRouter.POST("/firewall/batch", fwEmergency, baseApi.BatchOperateRule)
		hostRouter.POST("/firewall/update/port", fwEmergency, baseApi.UpdatePortRule)
		hostRouter.POST("/firewall/update/addr", fwEmergency, baseApi.UpdateAddrRule)
		hostRouter.POST("/firewall/update/description", baseApi.UpdateFirewallDescription)
		hostRouter.POST("/firewall/clean", baseApi.CleanOrphanFirewallRecords)

		hostRouter.POST("/firewall/filter/rule/search", baseApi.SearchFilterRules)
		hostRouter.POST("/firewall/filter/rule/operate", fwEmergency, baseApi.OperateFilterRule)
		hostRouter.POST("/firewall/filter/rule/batch", fwEmergency, baseApi.BatchOperateFilterRule)
		hostRouter.POST("/firewall/filter/operate", fwEmergency, baseApi.OperateFilterChain)
		hostRouter.POST("/firewall/filter/chain/status", baseApi.LoadChainStatus)

		// L3 安全栈：提交-确认会话 + 快照管理（设计稿 §3.5.1 / §3.10）。
		hostRouter.POST("/firewall/session/status", baseApi.LoadFirewallSession)
		hostRouter.POST("/firewall/session/confirm", baseApi.ConfirmFirewallSession)
		hostRouter.POST("/firewall/session/revert", baseApi.RevertFirewallSession)
		hostRouter.POST("/firewall/snapshot/list", baseApi.ListFirewallSnapshot)
		hostRouter.POST("/firewall/snapshot/restore", fwEmergency, baseApi.RestoreFirewallSnapshot)
		hostRouter.POST("/firewall/docker/status", baseApi.LoadFirewallDockerStatus)

		hostRouter.POST("/monitor/search", baseApi.LoadMonitor)
		hostRouter.POST("/monitor/clean", baseApi.CleanMonitor)
		hostRouter.GET("/monitor/netoptions", baseApi.GetNetworkOptions)
		hostRouter.GET("/monitor/iooptions", baseApi.GetIOOptions)
		hostRouter.GET("/monitor/setting", baseApi.LoadMonitorSetting)
		hostRouter.POST("/monitor/setting/update", baseApi.UpdateMonitorSetting)

		hostRouter.POST("/ssh/search", baseApi.GetSSHInfo)
		hostRouter.POST("/ssh/update", baseApi.UpdateSSH)
		hostRouter.POST("/ssh/log", baseApi.LoadSSHLogs)
		hostRouter.POST("/ssh/log/export", baseApi.ExportSSHLogs)
		hostRouter.POST("/ssh/operate", baseApi.OperateSSH)
		hostRouter.POST("/ssh/file", baseApi.LoadSSHFile)
		hostRouter.POST("/ssh/file/update", baseApi.UpdateSSHByFile)

		hostRouter.POST("/ssh/cert", baseApi.CreateRootCert)
		hostRouter.POST("/ssh/cert/update", baseApi.EditRootCert)
		hostRouter.POST("/ssh/cert/sync", baseApi.SyncRootCert)
		hostRouter.POST("/ssh/cert/search", baseApi.SearchRootCert)
		hostRouter.POST("/ssh/cert/delete", baseApi.DeleteRootCert)

		hostRouter.POST("/tool/status", baseApi.GetToolStatus)
		hostRouter.POST("/tool/init", baseApi.InitToolConfig)
		hostRouter.POST("/tool/operate", baseApi.OperateTool)
		hostRouter.POST("/tool/config/get", baseApi.GetToolConfig)
		hostRouter.POST("/tool/config/set", baseApi.UpdateToolConfig)
		hostRouter.POST("/tool/supervisor/process", baseApi.OperateProcess)
		hostRouter.GET("/tool/supervisor/process", baseApi.GetProcess)
		hostRouter.POST("/tool/supervisor/process/file/get", baseApi.GetProcessFile)
		hostRouter.POST("/tool/supervisor/process/file", baseApi.OperateProcessFile)

		hostRouter.GET("/terminal/local", baseApi.WsLocalTerminal)
		hostRouter.GET("/terminal/ssh", baseApi.WsHostSSH)
		hostRouter.GET("/terminal/container", baseApi.WsContainerTerminal)

		hostRouter.GET("/disks", baseApi.GetCompleteDiskInfo)
		hostRouter.POST("/disks/partition", baseApi.PartitionDisk)
		hostRouter.POST("/disks/mount", baseApi.MountDisk)
		hostRouter.POST("/disks/unmount", baseApi.UnmountDisk)

		hostRouter.GET("/components/:name", baseApi.CheckComponentExistence)
	}
}
