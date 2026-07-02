import { ref } from 'vue';
import { Host } from '@/api/interface/host';
import { getSSHInfo } from '@/api/modules/host';
import { getSettingInfo } from '@/api/modules/setting';
import i18n from '@/lang';
import { portRuleIncludes } from '@/views/host/firewall/composables/firewallHelpers';

// Pure-client heuristic: the ultimate safety net is still the post-submit
// 60s session-confirm auto-revert. This just keeps the user from self-locking
// before the request fires.
//
// Shared by the inbound list (inline strategy toggle) and the operate drawer,
// so both paths evaluate redline/warn with identical rules and a single port
// source. Ports are a module-level singleton fetched once per session; views
// that need the resolved ports (overview / inbound / white-list) consume the
// exported refs after ensurePortsLoaded() instead of refetching.

export const sshPort = ref('22');
// 面板端口取核心设置，而非 window.location.port（开发/反代下不等于真实面板端口），保证封禁风险预检准确。
export const panelPort = ref('');

let portsLoaded = false;
let portsLoading: Promise<void> | null = null;

export interface RiskInput {
    // 目标策略（翻转后的值），仅 'drop' 方向有自锁风险
    strategy: string;
    objectType: Host.InboundRuleType;
    address: string;
    port: string;
}

export const isBroadSource = (address: string): boolean => {
    const addr = (address || '').trim();
    return addr === '' || addr === 'Anywhere' || addr === '0.0.0.0/0' || addr === '::/0';
};

const isAllPorts = (port: string): boolean => {
    const p = (port || '').trim();
    return p === '' || p === '0';
};

const portsInclude = (port: string, target: string): boolean => {
    if (!target) return false;
    return portRuleIncludes(port, Number(target));
};

const loadPorts = async (): Promise<void> => {
    const [sshRes, settingRes] = await Promise.allSettled([getSSHInfo(), getSettingInfo()]);
    sshPort.value = sshRes.status === 'fulfilled' ? sshRes.value.data.port || '22' : '22';
    panelPort.value = settingRes.status === 'fulfilled' ? String(settingRes.value.data.serverPort || '') : '';
};

// Idempotent: concurrent callers share the same in-flight load; later callers
// no-op once loaded. Awaiting this before risk eval guarantees ssh/panel ports
// are ready (fixes the operate-drawer V-2 race where ports were never awaited).
export const ensurePortsLoaded = async (): Promise<void> => {
    if (portsLoaded) return;
    if (!portsLoading) {
        portsLoading = loadPorts().finally(() => {
            portsLoaded = true;
            portsLoading = null;
        });
    }
    await portsLoading;
};

export const computeFirewallRisk = (input: RiskInput): Host.RiskInfo => {
    if (input.strategy !== 'drop') {
        return { mode: 'none', message: '' };
    }
    if (input.objectType === 'address') {
        // 纯 IP 黑名单：仅当来源宽泛（可能把所有人含自己挡掉）时提示。
        return isBroadSource(input.address)
            ? { mode: 'warn', message: i18n.global.t('firewall.riskBlockSelf') }
            : { mode: 'none', message: '' };
    }
    // 指定来源的端口拒绝只影响该来源，自锁风险低。
    if (!isBroadSource(input.address)) {
        return { mode: 'none', message: '' };
    }
    const coversAll = isAllPorts(input.port);
    const coversSSH = coversAll || portsInclude(input.port, sshPort.value);
    const coversPanel = coversAll || portsInclude(input.port, panelPort.value);
    if (coversAll || (coversSSH && coversPanel)) {
        return { mode: 'redline', message: i18n.global.t('firewall.redlineBlockBoth') };
    }
    if (coversSSH || coversPanel) {
        return { mode: 'warn', message: i18n.global.t('firewall.riskBlockSelf') };
    }
    return { mode: 'none', message: '' };
};
