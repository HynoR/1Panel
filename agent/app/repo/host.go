package repo

import (
	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/1Panel-dev/1Panel/agent/utils/encrypt"
	"gorm.io/gorm"
)

type HostRepo struct{}

type IHostRepo interface {
	Get(opts ...DBOption) (model.Host, error)
	GetList(opts ...DBOption) ([]model.Host, error)
	Page(limit, offset int, opts ...DBOption) (int64, []model.Host, error)
	Create(host *model.Host) error
	Update(id uint, vars map[string]interface{}) error
	UpdateGroup(group, newGroup uint) error
	Delete(opts ...DBOption) error

	WithByInfo(info string) DBOption
	WithByPort(port uint) DBOption
	WithByUser(user string) DBOption

	GetFirewallRecord(opts ...DBOption) (model.Firewall, error)
	ListFirewallRecord(opts ...DBOption) ([]model.Firewall, error)
	SaveFirewallRecord(firewall *model.Firewall) error
	DeleteFirewallRecordByID(id uint) error
	DeleteFirewallRecordByTuple(record model.Firewall) error

	GetFirewallMeta(fingerprint string) (model.FirewallRuleMeta, error)
	ListFirewallMeta(opts ...DBOption) ([]model.FirewallRuleMeta, error)
	SaveFirewallMeta(meta *model.FirewallRuleMeta) error
	DeleteFirewallMeta(fingerprint string) error

	GetFirewallState() (model.FirewallState, error)
	SaveFirewallState(state *model.FirewallState) error

	SyncCert(data []model.RootCert) error
	GetCert(opts ...DBOption) (model.RootCert, error)
	PageCert(limit, offset int, opts ...DBOption) (int64, []model.RootCert, error)
	ListCert(opts ...DBOption) ([]model.RootCert, error)
	SaveCert(cert *model.RootCert) error
	UpdateCert(id uint, vars map[string]interface{}) error
	DeleteCert(opts ...DBOption) error

	WithByChain(chain string) DBOption
}

func NewIHostRepo() IHostRepo {
	return &HostRepo{}
}

func (h *HostRepo) Get(opts ...DBOption) (model.Host, error) {
	var host model.Host
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.First(&host).Error
	return host, err
}

func (h *HostRepo) GetList(opts ...DBOption) ([]model.Host, error) {
	var hosts []model.Host
	db := global.DB.Model(&model.Host{})
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.Find(&hosts).Error
	return hosts, err
}

func (h *HostRepo) Page(page, size int, opts ...DBOption) (int64, []model.Host, error) {
	var hosts []model.Host
	db := global.DB.Model(&model.Host{})
	for _, opt := range opts {
		db = opt(db)
	}
	count := int64(0)
	db = db.Count(&count)
	err := db.Limit(size).Offset(size * (page - 1)).Find(&hosts).Error
	return count, hosts, err
}

func (h *HostRepo) WithByInfo(info string) DBOption {
	return func(g *gorm.DB) *gorm.DB {
		if len(info) == 0 {
			return g
		}
		infoStr := "%" + info + "%"
		return g.Where("name LIKE ? OR addr LIKE ?", infoStr, infoStr)
	}
}

func (h *HostRepo) WithByPort(port uint) DBOption {
	return func(g *gorm.DB) *gorm.DB {
		return g.Where("port = ?", port)
	}
}

func (h *HostRepo) WithByUser(user string) DBOption {
	return func(g *gorm.DB) *gorm.DB {
		return g.Where("user = ?", user)
	}
}

func (h *HostRepo) Create(host *model.Host) error {
	return global.DB.Create(host).Error
}

func (h *HostRepo) Update(id uint, vars map[string]interface{}) error {
	return global.DB.Model(&model.Host{}).Where("id = ?", id).Updates(vars).Error
}

func (h *HostRepo) UpdateGroup(group, newGroup uint) error {
	return global.DB.Model(&model.Host{}).Where("group_id = ?", group).Updates(map[string]interface{}{"group_id": newGroup}).Error
}

func (h *HostRepo) Delete(opts ...DBOption) error {
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	return db.Delete(&model.Host{}).Error
}

func (h *HostRepo) GetFirewallRecord(opts ...DBOption) (model.Firewall, error) {
	var firewall model.Firewall
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.First(&firewall).Error
	return firewall, err
}

func (h *HostRepo) ListFirewallRecord(opts ...DBOption) ([]model.Firewall, error) {
	var firewalls []model.Firewall
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	if err := global.DB.Find(&firewalls).Error; err != nil {
		return firewalls, nil
	}
	return firewalls, nil
}

func (h *HostRepo) SaveFirewallRecord(firewall *model.Firewall) error {
	if firewall.ID != 0 {
		return global.DB.Save(firewall).Error
	}
	var data model.Firewall
	switch firewall.Type {
	case "port":
		_ = global.DB.Where("type = ? AND dst_port = ? AND protocol = ? AND src_ip = ? AND strategy = ?", "port",
			firewall.DstPort,
			firewall.Protocol,
			firewall.SrcIP,
			firewall.Strategy,
		).First(&data).Error
	case "ip":
		_ = global.DB.Where("type = ? AND src_ip = ? AND strategy = ?", "address", firewall.SrcIP, firewall.Strategy).First(&data)
	default:
		_ = global.DB.Where("type = ? AND chain = ? AND src_port = ? AND dst_port = ? AND protocol = ? AND src_ip = ? AND dst_ip = ? AND strategy = ?",
			firewall.Type,
			firewall.Chain,
			firewall.SrcPort,
			firewall.DstPort,
			firewall.Protocol,
			firewall.SrcIP,
			firewall.DstIP,
			firewall.Strategy,
		).First(&data).Error
	}
	if data.ID != 0 {
		firewall.ID = data.ID
	}
	return global.DB.Save(firewall).Error
}

func (h *HostRepo) DeleteFirewallRecordByID(id uint) error {
	return global.DB.Where("id = ?", id).Delete(&model.Firewall{}).Error
}

// DeleteFirewallRecordByTuple 按规则元组删除描述记录（删除请求不携带 id 时使用），与 SaveFirewallRecord 的匹配口径一致，
// 避免删规则后 firewalls 行残留、再次添加同名规则时复活旧描述。
func (h *HostRepo) DeleteFirewallRecordByTuple(record model.Firewall) error {
	db := global.DB.Where("type = ? AND strategy = ?", record.Type, record.Strategy)
	switch record.Type {
	case "port":
		db = db.Where("dst_port = ? AND protocol = ? AND src_ip = ?", record.DstPort, record.Protocol, record.SrcIP)
	case "address":
		db = db.Where("src_ip = ?", record.SrcIP)
	default:
		db = db.Where("chain = ? AND src_port = ? AND dst_port = ? AND protocol = ? AND src_ip = ? AND dst_ip = ?",
			record.Chain, record.SrcPort, record.DstPort, record.Protocol, record.SrcIP, record.DstIP)
	}
	return db.Delete(&model.Firewall{}).Error
}

func (h *HostRepo) GetFirewallMeta(fingerprint string) (model.FirewallRuleMeta, error) {
	var meta model.FirewallRuleMeta
	err := global.DB.Where("fingerprint = ?", fingerprint).First(&meta).Error
	return meta, err
}

func (h *HostRepo) ListFirewallMeta(opts ...DBOption) ([]model.FirewallRuleMeta, error) {
	var metas []model.FirewallRuleMeta
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.Find(&metas).Error
	return metas, err
}

// SaveFirewallMeta 按指纹幂等 upsert：已存在则只更新描述/来源/family，不新增（修 C3）。
func (h *HostRepo) SaveFirewallMeta(meta *model.FirewallRuleMeta) error {
	if meta.Fingerprint == "" {
		return nil
	}
	var existing model.FirewallRuleMeta
	if err := global.DB.Where("fingerprint = ?", meta.Fingerprint).First(&existing).Error; err == nil {
		meta.ID = existing.ID
	}
	return global.DB.Save(meta).Error
}

func (h *HostRepo) DeleteFirewallMeta(fingerprint string) error {
	return global.DB.Where("fingerprint = ?", fingerprint).Delete(&model.FirewallRuleMeta{}).Error
}

// GetFirewallState 返回单行状态（固定 id=1），不存在时返回零值且 err=gorm.ErrRecordNotFound。
func (h *HostRepo) GetFirewallState() (model.FirewallState, error) {
	var state model.FirewallState
	err := global.DB.Where("id = ?", 1).First(&state).Error
	return state, err
}

func (h *HostRepo) SaveFirewallState(state *model.FirewallState) error {
	state.ID = 1
	return global.DB.Save(state).Error
}

func (u *HostRepo) GetCert(opts ...DBOption) (model.RootCert, error) {
	var cert model.RootCert
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.First(&cert).Error
	return cert, err
}

func (u *HostRepo) PageCert(page, size int, opts ...DBOption) (int64, []model.RootCert, error) {
	var ops []model.RootCert
	db := global.DB.Model(&model.RootCert{})
	for _, opt := range opts {
		db = opt(db)
	}
	count := int64(0)
	db = db.Count(&count)
	err := db.Limit(size).Offset(size * (page - 1)).Find(&ops).Error
	return count, ops, err
}

func (u *HostRepo) ListCert(opts ...DBOption) ([]model.RootCert, error) {
	var ops []model.RootCert
	db := global.DB.Model(&model.RootCert{})
	for _, opt := range opts {
		db = opt(db)
	}
	count := int64(0)
	db = db.Count(&count)
	err := db.Find(&ops).Error
	return ops, err
}

func (u *HostRepo) SaveCert(cert *model.RootCert) error {
	return global.DB.Save(cert).Error
}

func (u *HostRepo) UpdateCert(id uint, vars map[string]interface{}) error {
	return global.DB.Model(&model.RootCert{}).Where("id = ?", id).Updates(vars).Error
}

func (u *HostRepo) DeleteCert(opts ...DBOption) error {
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	return db.Delete(&model.RootCert{}).Error
}

func (u *HostRepo) SyncCert(data []model.RootCert) error {
	tx := global.DB.Begin()
	var oldCerts []model.RootCert
	_ = tx.Where("1 = ?", 1).Find(&oldCerts).Error
	oldCertsMap := make(map[string]uint)
	for _, item := range oldCerts {
		oldCertsMap[item.Name] = item.ID
	}
	for _, item := range data {
		if _, ok := oldCertsMap[item.Name]; ok {
			delete(oldCertsMap, item.Name)
			continue
		}
		item.PassPhrase, _ = encrypt.StringEncrypt("<UN-SET>")
		if err := tx.Model(model.RootCert{}).Create(&item).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	for _, val := range oldCertsMap {
		if err := tx.Where("id = ?", val).Delete(&model.RootCert{}).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	tx.Commit()
	return nil
}

func (u *HostRepo) WithByChain(chain string) DBOption {
	return func(g *gorm.DB) *gorm.DB {
		return g.Where("chain = ?", chain)
	}
}
