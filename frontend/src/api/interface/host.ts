import { CommonModel, ReqPage } from '.';

export namespace Host {
    export interface HostTree {
        id: number;
        label: string;
        children: Array<TreeNode>;
    }
    export interface TreeNode {
        id: number;
        label: string;
    }
    export interface Host extends CommonModel {
        name: string;
        groupID: number;
        groupBelong: string;
        addr: string;
        port: number;
        user: string;
        authMode: string;
        password: string;
        privateKey: string;
        passPhrase: string;
        rememberPassword: boolean;
        description: string;
    }
    export interface HostOperate {
        isLocal: boolean;
        id: number;
        name: string;
        groupID: number;
        addr: string;
        port: number;
        user: string;
        authMode: string;
        password: string;
        privateKey: string;
        passPhrase: string;
        rememberPassword: boolean;

        description: string;
    }
    export interface HostConnTest {
        isLocal: boolean;
        addr: string;
        port: number;
        user: string;
        authMode: string;
        privateKey: string;
        passPhrase: string;
        password: string;

        localSSHConnShow: string;
    }
    export interface GroupChange {
        id: number;
        groupID: number;
    }
    export interface ReqSearch {
        info?: string;
    }
    export interface SearchWithPage extends ReqPage {
        groupID: number;
        info?: string;
    }

    export interface FirewallBase {
        name: string;
        mode: string;
        isExist: boolean;
        isActive: boolean;
        isInit: boolean;
        isBind: boolean;
        version: string;
        pingStatus: string;
        capabilities: FirewallCapabilities;
        conflict: FirewallConflict;
        bootStatus: string;
        consistent: boolean;
        strictMode: boolean;
    }
    export interface FirewallCapabilities {
        rules: boolean;
        forward: boolean;
        forwardImpl: string;
        filter: boolean;
        baseline: boolean;
        snapshot: string;
        ipv6Rules: boolean;
        defaultDrop: boolean;
    }
    export interface FirewallConflict {
        hasConflict: boolean;
        providers: string[];
        message: string;
    }
    export interface FirewallSessionChange {
        summary: string;
        at: string;
    }
    export interface FirewallSession {
        active: boolean;
        changes: FirewallSessionChange[];
        remainSeconds: number;
        since: string;
        snapshot: string;
    }
    export interface FirewallSnapshot {
        name: string;
        tag: string;
        createdAt: string;
        hasV6: boolean;
        size: number;
    }
    export interface RuleSearch extends ReqPage {
        strategy: string;
        info: string;
        type: string;
    }
    export interface RuleInfo extends ReqPage {
        family: string;
        address: string;
        destination: string;
        port: string;
        srcPort: string;
        destPort: string;
        protocol: string;
        strategy: string;

        usedStatus: string;
        description: string;
        applyToDocker?: boolean;

        [key: string]: any;
    }
    export interface UpdateDescription {
        type: string;
        chain: string;
        srcIP: string;
        dstIP: string;
        srcPort: string;
        dstPort: string;
        protocol: string;
        strategy: string;
        family?: string;
        description: string;
    }
    export interface RulePort {
        operation: string;
        address: string;
        port: string;
        source: string;
        protocol: string;
        strategy: string;
        description: string;
        family?: string;
        applyToDocker?: boolean;
    }
    export interface RuleForward {
        operation: string;
        protocol: string;
        port: string;
        targetIP: string;
        targetPort: string;
        interface: string;
    }
    export interface RuleIP {
        operation: string;
        address: string;
        strategy: string;
        description: string;
        family?: string;
        applyToDocker?: boolean;
    }
    export interface FirewallDockerRule {
        address: string;
        port: string;
        protocol: string;
        strategy: string;
    }
    export interface FirewallDockerStatus {
        available: boolean;
        rules: FirewallDockerRule[];
    }
    export interface UpdatePortRule {
        oldRule: RulePort;
        newRule: RulePort;
    }
    export interface UpdateAddrRule {
        oldRule: RuleIP;
        newRule: RuleIP;
    }
    export interface BatchRule {
        type: string;
        rules: Array<RulePort>;
    }

    // ---- FRONTEND-ONLY view types for the unified inbound rules (no backend DTO change) ----
    export type InboundRuleType = 'port' | 'address';
    export type InboundRuleLevel = 'deny' | 'baseline' | 'allow';
    // A RuleInfo row tagged for the merged inbound table; level is derived client-side.
    export interface InboundRule extends RuleInfo {
        ruleType: InboundRuleType;
        level?: InboundRuleLevel;
        dockerPublished?: boolean;
    }
    // Unified create/edit form model; objectType routes to operatePortRule / operateIPRule.
    export interface UnifiedRuleForm {
        objectType: InboundRuleType;
        port: string;
        address: string;
        protocol: string;
        strategy: string;
        family: string;
        applyToDocker: boolean;
        description: string;
    }
    // Client-side risk heuristic result (no backend risk field / precheck endpoint).
    export interface RiskInfo {
        mode: 'warn' | 'redline' | 'none';
        message: string;
    }
    // A rescue channel shown on the overview (SSH / panel / 80 / 443).
    export interface RescueChannel {
        name: string;
        port: string;
        status: 'allowed' | 'closable' | 'readonly';
        readonly: boolean;
    }

    export interface MonitorSetting {
        defaultNetwork: string;
        defaultIO: string;
        monitorStatus: string;
        monitorStoreDays: string;
        monitorInterval: string;
    }
    export interface MonitorData {
        param: string;
        date: Array<Date>;
        value: Array<any>;
    }
    export interface MonitorSearch {
        param: string;
        io: string;
        network: string;
        startTime: Date;
        endTime: Date;
    }

    export interface SSHInfo {
        autoStart: boolean;
        isActive: boolean;
        message: string;
        port: string;
        listenAddress: string;
        passwordAuthentication: string;
        pubkeyAuthentication: string;
        encryptionMode: string;
        primaryKey: string;
        permitRootLogin: string;
        useDNS: string;
        currentUser: string;
    }
    export interface SSHUpdate {
        key: string;
        newValue: string;
    }
    export interface RootCert {
        name: string;
        mode: string;
        encryptionMode: string;
        passPhrase: string;
        privateKey: string;
        publicKey: string;
        description: string;
    }
    export interface RootCertInfo {
        id: number;
        createAt: Date;
        name: string;
        mode: string;
        encryptionMode: string;
        passPhrase: string;
        description: string;
        publicKey: string;
        privateKey: string;
    }
    export interface searchSSHLog extends ReqPage {
        info: string;
        status: string;
        startTime?: string | Date;
        endTime?: string | Date;
    }
    export interface analysisSSHLog extends ReqPage {
        orderBy: string;
    }
    export interface sshHistory {
        date: Date;
        area: string;
        user: string;
        authMode: string;
        address: string;
        port: string;
        status: string;
        message: string;
    }

    export interface DiskBasicInfo {
        device: string;
        size: string;
        model: string;
        diskType: string;
        isRemovable: boolean;
        isSystem: boolean;
        filesystem: string;
        used: string;
        avail: string;
        usePercent: number;
        mountPoint: string;
        isMounted: boolean;
        serial: string;
    }

    export interface DiskInfo extends DiskBasicInfo {
        partitions?: DiskBasicInfo[];
    }

    export interface CompleteDiskInfo {
        disks: DiskInfo[];
        unpartitionedDisks: DiskBasicInfo[];
        systemDisks?: DiskInfo[];
        totalDisks: number;
        totalCapacity: number;
    }

    export interface DiskPartition {
        device: string;
        filesystem: string;
        label: string;
        autoMount: boolean;
        mountPoint: string;
        noFail: boolean;
    }

    export interface DiskMount {
        device: string;
        mountPoint: string;
        filesystem?: string;
    }

    export interface DiskUmount {
        mountPoint: string;
    }

    export interface ComponentInfo {
        exists: boolean;
        version: string;
        path: string;
        error: string;
    }

    // Iptables Filter
    export interface IptablesFilterRuleSearch extends ReqPage {
        info: string;
        type: string;
    }
    export interface IptablesData {
        items: IptablesRules[];
        total: number;
        defaultStrategy: string;
    }
    export interface IptablesRules {
        id: number;
        protocol: string;
        srcPort: string;
        dstPort: string;
        srcIP: string;
        dstIP: string;
        strategy: string;
        description: string;
    }
    export interface ChainStatus {
        isBind: boolean;
        defaultStrategy: string;
    }
    export interface IptablesFilterRuleOp {
        operation: string;
        id?: number;
        chain: string;
        protocol: string;
        srcIP?: string;
        srcPort?: number;
        dstIP?: string;
        dstPort?: number;
        strategy: string;
        description?: string;
    }
}
