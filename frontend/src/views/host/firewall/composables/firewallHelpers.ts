// 防火墙前端共享辅助函数：端口/地址表达式校验、端口规则解析、白名单解析等。
// inbound 列表 / operate 抽屉 / import 对话框 / overview / 高级控制共用，避免各处口径分叉。
import { checkCidr, checkCidrV6, checkIpV4V6, checkPort } from '@/utils/validate';
import i18n from '@/lang';

// 端口表达式校验：支持单端口、范围（8080-8090）、列表（8080,8090），底层复用 checkPort。
export const isValidPortExpr = (port: string): boolean => {
    const ports =
        port.indexOf('-') !== -1 && !port.startsWith('-')
            ? port.split('-')
            : port.indexOf(',') !== -1 && !port.startsWith(',')
              ? port.split(',')
              : [port];
    return ports.every((p) => !checkPort(p));
};

// 地址表达式校验：支持逗号分隔多地址、IPv4/IPv6 单 IP 与 CIDR，空与 Anywhere 视为合法。
export const isValidAddressList = (address: string): boolean => {
    if (!address || address === 'Anywhere') return true;
    return address.split(',').every((item) => {
        const trimmed = item.trim();
        if (!trimmed) return false;
        if (trimmed.indexOf('/') !== -1) {
            return trimmed.indexOf(':') !== -1 ? !checkCidrV6(trimmed) : !checkCidr(trimmed);
        }
        return !checkIpV4V6(trimmed);
    });
};

// 解析端口规则的单个片段（单端口或范围）；'-' 与 ':' 均接受为范围分隔符
//（ufw / firewalld / iptables 回显不一致）。非法片段返回 null。
const parsePortSegment = (segment: string): { from: number; to: number } | null => {
    const s = segment.trim();
    if (!s) return null;
    const delimiter = s.includes('-') && !s.startsWith('-') ? '-' : s.includes(':') && !s.startsWith(':') ? ':' : '';
    if (delimiter) {
        const [from, to] = s.split(delimiter).map((item) => parseInt(item.trim()));
        if (isNaN(from) || isNaN(to)) return null;
        return { from, to };
    }
    const port = parseInt(s);
    return isNaN(port) ? null : { from: port, to: port };
};

// 展开端口规则（如 "80,8080-8090"）为端口数组。
export const expandPortRule = (rulePort: string): number[] => {
    const ports: number[] = [];
    for (const segment of (rulePort || '').split(',')) {
        const range = parsePortSegment(segment);
        if (!range) continue;
        for (let port = range.from; port <= range.to; port++) {
            ports.push(port);
        }
    }
    return ports;
};

// 判断端口规则表达式是否覆盖指定端口。
export const portRuleIncludes = (rulePort: string, port: number): boolean => {
    if (isNaN(port)) return false;
    return (rulePort || '').split(',').some((segment) => {
        const range = parsePortSegment(segment);
        return !!range && port >= range.from && port <= range.to;
    });
};

// FirewallPortWhiteList 设置项解析：空白/逗号/分号分隔。
export const parseFirewallWhiteList = (value: string): string[] =>
    (value || '')
        .split(/[\s,;]+/)
        .map((item) => item.trim())
        .filter((item) => item !== '');

// fu-input-rw-switch 的 @enter 会随即触发 @blur，两次都会调回调；
// 单飞包装：in-flight 期间忽略后续触发，避免描述行内编辑重复提交。
export const singleFlight = <Args extends unknown[]>(fn: (...args: Args) => Promise<void>) => {
    let inFlight = false;
    return async (...args: Args): Promise<void> => {
        if (inFlight) return;
        inFlight = true;
        try {
            await fn(...args);
        } finally {
            inFlight = false;
        }
    };
};

// 链名 → 方向文案：1PANEL_OUTPUT 为出站，其余为入站。
export const chainDirectionLabel = (chain?: string): string =>
    chain === '1PANEL_OUTPUT'
        ? i18n.global.t('firewall.outboundDirection')
        : i18n.global.t('firewall.inboundDirection');
