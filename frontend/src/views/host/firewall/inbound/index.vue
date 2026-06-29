<template>
    <div>
        <FireRouter />

        <div v-loading="loading">
            <el-card v-if="!isReady" class="mask-prompt">
                <span>{{ $t('firewall.goOverviewInit') }}</span>
                <el-button type="primary" link class="ml-2" @click="goOverview">
                    {{ $t('firewall.overview') }}
                </el-button>
            </el-card>

            <div v-else>
                <FlowBar
                    :default-drop="strictMode"
                    :active-level="activeLevel"
                    :counts="levelCounts"
                    @filter="onFilterLevel"
                />

                <LayoutContent :title="$t('firewall.inboundRule', 2)">
                    <template #prompt>
                        <div class="mb-2" v-if="mode === 'external'">
                            <el-alert :closable="false" :title="$t('firewall.iptablesHelper', [name])" />
                        </div>
                    </template>
                    <template #leftToolBar>
                        <el-button v-permission v-node-admin type="primary" @click="onAllowPort">
                            {{ $t('firewall.allowPort') }}
                        </el-button>
                        <el-button v-permission v-node-admin type="danger" plain @click="onBlockIP">
                            {{ $t('firewall.blockIP') }}
                        </el-button>
                        <el-button v-permission v-node-admin @click="onOpenDialog('create')">
                            {{ $t('commons.button.create') }}
                        </el-button>
                        <el-button
                            v-permission
                            v-node-admin
                            @click="onDelete(null)"
                            plain
                            :disabled="selects.length === 0"
                        >
                            {{ $t('commons.button.delete') }}
                        </el-button>
                        <el-button-group>
                            <el-button v-permission v-node-admin @click="onImport">
                                {{ $t('commons.button.import') }}
                            </el-button>
                            <el-button v-permission v-node-admin :disabled="selects.length === 0" @click="onExport">
                                {{ $t('commons.button.export') }}
                            </el-button>
                        </el-button-group>
                    </template>
                    <template #rightToolBar>
                        <el-select v-model="searchStrategy" @change="onFilterChange" clearable class="p-w-200">
                            <template #prefix>{{ $t('firewall.strategy') }}</template>
                            <el-option :label="$t('commons.table.all')" value=""></el-option>
                            <el-option :label="$t('firewall.allow')" value="accept"></el-option>
                            <el-option :label="$t('firewall.deny')" value="drop"></el-option>
                        </el-select>
                        <TableSearch @search="onFilterChange" v-model:searchName="searchName" />
                        <TableRefresh @search="loadData" />
                        <TableSetting title="firewall-inbound-refresh" @search="loadData" />
                    </template>
                    <template #main>
                        <ComplexTable
                            :pagination-config="paginationConfig"
                            v-model:selects="selects"
                            @search="applyAndSlice"
                            :data="pageData"
                            :heightDiff="440"
                        >
                            <el-table-column type="selection" :selectable="canSelect" fix />
                            <el-table-column :label="$t('firewall.level')" :min-width="90">
                                <template #default="{ row }">
                                    <el-tag v-if="row.level === 'deny'" type="danger">
                                        {{ $t('firewall.levelDeny') }}
                                    </el-tag>
                                    <el-tag v-else-if="row.level === 'baseline'" type="info">
                                        <el-icon class="align-middle"><Lock /></el-icon>
                                        {{ $t('firewall.levelBaseline') }}
                                    </el-tag>
                                    <el-tag v-else type="success">{{ $t('firewall.levelAllow') }}</el-tag>
                                </template>
                            </el-table-column>
                            <el-table-column :min-width="80" :label="$t('firewall.strategy')" prop="strategy">
                                <template #default="{ row }">
                                    <el-button
                                        v-if="row.strategy === 'accept'"
                                        v-permission
                                        v-node-admin
                                        @click="onChangeStatus(row, 'drop')"
                                        link
                                        type="success"
                                    >
                                        {{ $t('firewall.allow') }}
                                    </el-button>
                                    <el-button
                                        v-else
                                        link
                                        type="danger"
                                        v-permission
                                        v-node-admin
                                        @click="onChangeStatus(row, 'accept')"
                                    >
                                        {{ $t('firewall.deny') }}
                                    </el-button>
                                </template>
                            </el-table-column>
                            <el-table-column :label="$t('commons.table.protocol')" :min-width="70">
                                <template #default="{ row }">
                                    <span v-if="row.ruleType === 'port'">{{ row.protocol }}</span>
                                    <span v-else>-</span>
                                </template>
                            </el-table-column>
                            <el-table-column :label="$t('commons.table.port')" :min-width="80">
                                <template #default="{ row }">
                                    <span v-if="row.ruleType === 'port'">{{ row.port }}</span>
                                    <span v-else>-</span>
                                </template>
                            </el-table-column>
                            <el-table-column :label="$t('commons.table.status')" :min-width="180">
                                <template #default="{ row }">
                                    <template v-if="row.ruleType !== 'port'">
                                        <span>-</span>
                                    </template>
                                    <template v-else-if="row.usedStatus">
                                        <template v-if="row.processInfos?.length">
                                            <span class="process-list">
                                                <span
                                                    v-for="(process, index) in row.processInfos"
                                                    v-show="row.expand || index < 3"
                                                    :key="`${process.PID || formatProcessInfo(process)}-${index}`"
                                                >
                                                    <el-button
                                                        v-if="process.PID"
                                                        size="small"
                                                        class="process-link"
                                                        :title="`${formatProcessInfo(process)} (PID: ${process.PID})`"
                                                        @click.stop="showProcessDetail(process.PID)"
                                                    >
                                                        {{ formatProcessInfo(process) }}
                                                        <el-icon class="process-detail-icon">
                                                            <Expand />
                                                        </el-icon>
                                                    </el-button>
                                                    <span v-else class="process-name">
                                                        <el-button size="small">
                                                            {{ formatProcessInfo(process) }}
                                                        </el-button>
                                                    </span>
                                                </span>
                                                <el-button
                                                    v-if="!row.expand && row.processInfos.length > 3"
                                                    type="primary"
                                                    link
                                                    class="process-toggle"
                                                    @click.stop="row.expand = true"
                                                >
                                                    {{ $t('commons.button.expand') }}...
                                                </el-button>
                                                <el-button
                                                    v-if="row.expand && row.processInfos.length > 3"
                                                    type="primary"
                                                    link
                                                    class="process-toggle"
                                                    @click.stop="row.expand = false"
                                                >
                                                    {{ $t('commons.button.collapse') }}
                                                </el-button>
                                            </span>
                                        </template>
                                        <span v-else class="process-list">
                                            <span class="process-name">{{ row.usedStatus }}</span>
                                        </span>
                                    </template>
                                    <el-tag type="info" v-else>{{ $t('firewall.noListen') }}</el-tag>
                                </template>
                            </el-table-column>
                            <el-table-column :min-width="100" :label="$t('firewall.source')" prop="address">
                                <template #default="{ row }">
                                    <span v-if="row.address && row.address !== 'Anywhere'">{{ row.address }}</span>
                                    <span v-else>{{ $t('firewall.allIP') }}</span>
                                </template>
                            </el-table-column>
                            <el-table-column label="Docker" :min-width="80">
                                <template #default="{ row }">
                                    <el-tooltip
                                        v-if="row.dockerPublished"
                                        :content="$t('firewall.dockerPublished')"
                                        placement="top"
                                    >
                                        <span>🐳</span>
                                    </el-tooltip>
                                    <span v-else>-</span>
                                </template>
                            </el-table-column>
                            <el-table-column
                                :min-width="140"
                                :label="$t('commons.table.description')"
                                prop="description"
                                show-overflow-tooltip
                            >
                                <template #default="{ row }">
                                    <fu-input-rw-switch
                                        v-model="row.description"
                                        v-permission
                                        v-node-admin
                                        @enter="onChange(row)"
                                        @blur="onChange(row)"
                                    />
                                </template>
                            </el-table-column>
                            <fu-table-operations
                                width="180px"
                                :buttons="buttons"
                                :ellipsis="10"
                                :label="$t('commons.table.operate')"
                                fix
                            />
                        </ComplexTable>
                    </template>
                </LayoutContent>
            </div>
        </div>

        <OpDialog ref="opRef" @search="loadData" />
        <OperateDialog @search="loadData" ref="dialogRef" />
        <ImportDialog @search="loadData" ref="dialogImportRef" />
        <ProcessDetail ref="processDetailRef" />
    </div>
</template>

<script lang="ts" setup>
import FireRouter from '@/views/host/firewall/index.vue';
import OperateDialog from '@/views/host/firewall/inbound/operate/index.vue';
import ImportDialog from '@/views/host/firewall/inbound/import/index.vue';
import FlowBar from '@/views/host/firewall/components/flow-bar.vue';
import ProcessDetail from '@/views/host/process/process/detail/index.vue';
import { computed, onMounted, reactive, ref } from 'vue';
import {
    batchOperateRule,
    getSSHInfo,
    searchFireRule,
    updateAddrRule,
    updateFirewallDescription,
    updatePortRule,
} from '@/api/modules/host';
import { getAgentSettingInfo, getSettingInfo } from '@/api/modules/setting';
import { getListeningProcess } from '@/api/modules/process';
import { Host } from '@/api/interface/host';
import { Process } from '@/api/interface/process';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { ElMessageBox } from 'element-plus';
import { Expand, Lock } from '@element-plus/icons-vue';
import { routerToName } from '@/utils/router';
import { downloadWithContent } from '@/utils/file';
import { getCurrentDateFormatted } from '@/utils/date';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';

const { capabilities, mode, name, isReady, strictMode, loadBaseInfo, dockerRules, loadDockerStatus } =
    useFireBaseInfo();

const loading = ref(false);
const selects = ref<any>([]);
const searchName = ref('');
const searchStrategy = ref('');
const activeLevel = ref('');

const opRef = ref();
const dialogRef = ref();
const dialogImportRef = ref();
const processDetailRef = ref();

const listeningProcesses = ref<Process.ListeningProcess[]>([]);
const rescuePorts = ref<Set<number>>(new Set());

type ProcessInfoDisplay = Partial<Process.ListeningProcess> & {
    Name: string;
    ports: number[];
};

type InboundRow = Host.InboundRule & {
    expand?: boolean;
    processInfo?: Process.ListeningProcess;
    processInfos?: ProcessInfoDisplay[];
};

const allRows = ref<InboundRow[]>([]);
const pageData = ref<InboundRow[]>([]);
const paginationConfig = reactive({
    cacheSizeKey: 'firewall-inbound-page-size',
    currentPage: 1,
    pageSize: Number(localStorage.getItem('firewall-inbound-page-size')) || 20,
    total: 0,
});

const levelCounts = computed(() => {
    const counts = { deny: 0, baseline: 0, allow: 0 };
    for (const row of allRows.value) {
        if (row.level === 'deny') counts.deny++;
        else if (row.level === 'baseline') counts.baseline++;
        else counts.allow++;
    }
    return counts;
});

const levelOrder = (level?: string): number => {
    if (level === 'deny') return 0;
    if (level === 'baseline') return 1;
    return 2;
};

// baseline rows (SSH / panel / 80·443) are read-only-ish: no batch delete.
const canSelect = (row: InboundRow): boolean => row.level !== 'baseline';

const goOverview = () => {
    routerToName('FirewallPort');
};

// ---- rescue port set (panel port + whitelist 80/443 + SSH port) for baseline tagging ----
const loadRescuePorts = async () => {
    const set = new Set<number>();
    // 面板端口取核心设置（与概览保底通道一致）：agent 设置无 serverPort 字段，
    // 之前用 getAgentSettingInfo().serverPort 恒为 undefined → 面板端口从未进保底集，导致面板规则被误判为可删的「放行」。
    try {
        const res = await getSettingInfo();
        const panelPort = Number(res.data.serverPort);
        if (!isNaN(panelPort)) set.add(panelPort);
    } catch (error) {
        console.error('Failed to load panel port:', error);
    }
    try {
        const res = await getAgentSettingInfo();
        const whiteList = res.data.firewallPortWhiteList || '';
        whiteList
            .split(/[\s,;]+/)
            .map((item) => parseInt(item))
            .filter((port) => !isNaN(port))
            .forEach((port) => set.add(port));
    } catch (error) {
        console.error('Failed to load firewall whitelist:', error);
    }
    try {
        const ssh = await getSSHInfo();
        const sshPort = parseInt(ssh.data.port);
        set.add(isNaN(sshPort) ? 22 : sshPort);
    } catch (error) {
        set.add(22);
    }
    rescuePorts.value = set;
};

// ---- level derivation (client-side, mirrors chain eval order deny→baseline→allow) ----
const isRescueRow = (row: InboundRow): boolean => {
    if (row.ruleType !== 'port') return false;
    if (row.address && row.address !== 'Anywhere') return false;
    return extractPortsFromRule(row.port).some((port) => rescuePorts.value.has(port));
};

const deriveLevel = (row: InboundRow): Host.InboundRuleLevel => {
    if (row.strategy === 'drop') return 'deny';
    if (isRescueRow(row)) return 'baseline';
    return 'allow';
};

// ---- docker badge (single source: useFireBaseInfo.dockerRules) ----
const matchDocker = (row: InboundRow): boolean => {
    if (row.ruleType !== 'port') return false;
    return dockerRules.value.some(
        (rule) =>
            rule.port === row.port &&
            (rule.protocol === row.protocol ||
                row.protocol?.includes(rule.protocol) ||
                rule.protocol?.includes(row.protocol)),
    );
};

// ---- listening process merge (carried from port/index.vue) ----
const extractPortsFromObject = (portObj: { [key: string]: {} }): number[] => {
    return Object.keys(portObj)
        .map((portStr) => parseInt(portStr))
        .filter((port) => !isNaN(port));
};

const isPortInRule = (rulePort: string, port: number): boolean => {
    const segments = rulePort.split(',');
    for (const segment of segments) {
        const portSegment = segment.trim();
        if (!portSegment) {
            continue;
        }

        const rangeDelimiter = portSegment.includes('-') && !portSegment.startsWith('-') ? '-' : ':';
        if (portSegment.includes(rangeDelimiter) && !portSegment.startsWith(rangeDelimiter)) {
            const [startPort, endPort] = portSegment.split(rangeDelimiter).map((item) => parseInt(item.trim()));
            if (!isNaN(startPort) && !isNaN(endPort) && port >= startPort && port <= endPort) {
                return true;
            }
            continue;
        }

        if (parseInt(portSegment) === port) {
            return true;
        }
    }
    return false;
};

const formatProcessInfo = (process: ProcessInfoDisplay): string => {
    const ports = process.ports.join(', ');
    if (!process.Name) {
        return ports;
    }
    if (!ports) {
        return process.Name;
    }
    return `${process.Name} (${ports})`;
};

const parseUsedStatus = (usedStatus: string, rulePort: string): ProcessInfoDisplay[] => {
    if (!usedStatus) {
        return [];
    }

    return usedStatus
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item)
        .map((item) => {
            const appMatch = item.match(/^(\d+)\s+\((.+)\)$/);
            if (appMatch) {
                return {
                    Name: appMatch[2],
                    ports: [Number(appMatch[1])],
                };
            }

            const port = Number(item);
            if (!isNaN(port)) {
                return {
                    Name: '',
                    ports: [port],
                };
            }

            const rulePorts = extractPortsFromRule(rulePort);
            return {
                Name: item,
                ports: rulePorts.length === 1 ? rulePorts : [],
            };
        });
};

const extractPortsFromRule = (rulePort: string): number[] => {
    const ports: number[] = [];
    const segments = (rulePort || '').split(',');
    for (const segment of segments) {
        const portSegment = segment.trim();
        if (!portSegment) {
            continue;
        }

        const rangeDelimiter = portSegment.includes('-') && !portSegment.startsWith('-') ? '-' : ':';
        if (portSegment.includes(rangeDelimiter) && !portSegment.startsWith(rangeDelimiter)) {
            const [startPort, endPort] = portSegment.split(rangeDelimiter).map((item) => parseInt(item.trim()));
            if (!isNaN(startPort) && !isNaN(endPort)) {
                for (let port = startPort; port <= endPort; port++) {
                    ports.push(port);
                }
            }
            continue;
        }

        const port = parseInt(portSegment);
        if (!isNaN(port)) {
            ports.push(port);
        }
    }
    return ports;
};

const getProtocolNums = (protocol: string): number[] => {
    const protocolValue = (protocol || '').toLowerCase();
    if (protocolValue === 'tcp') {
        return [1];
    }
    if (protocolValue === 'udp') {
        return [2];
    }
    if (protocolValue.includes('tcp') && protocolValue.includes('udp')) {
        return [1, 2];
    }
    return [];
};

const loadMatchedListeningProcesses = (rule: InboundRow): ProcessInfoDisplay[] => {
    const protocolNums = getProtocolNums(rule.protocol);
    const matchedProcesses: ProcessInfoDisplay[] = [];

    for (const proc of listeningProcesses.value) {
        if (!protocolNums.includes(proc.Protocol)) {
            continue;
        }

        const matchedPorts = extractPortsFromObject(proc.Port)
            .filter((port) => isPortInRule(rule.port, port))
            .sort((a, b) => a - b);
        if (matchedPorts.length > 0) {
            matchedProcesses.push({
                ...proc,
                ports: matchedPorts,
            });
        }
    }

    return matchedProcesses;
};

const applyProcessPID = (processInfos: ProcessInfoDisplay[], matchedProcesses: ProcessInfoDisplay[]) => {
    for (const processInfo of processInfos) {
        const matchedProcess = matchedProcesses.find((proc) =>
            processInfo.ports.some((port) => proc.ports.includes(port)),
        );
        if (!matchedProcess) {
            continue;
        }

        processInfo.PID = matchedProcess.PID;
        processInfo.Port = matchedProcess.Port;
        processInfo.Protocol = matchedProcess.Protocol;
        if (processInfo.ports.length === 0) {
            processInfo.ports = matchedProcess.ports;
        }
    }
};

const mergeListeningProcesses = (processInfos: ProcessInfoDisplay[], matchedProcesses: ProcessInfoDisplay[]) => {
    const displayedPorts = new Set<number>();
    for (const processInfo of processInfos) {
        for (const port of processInfo.ports) {
            displayedPorts.add(port);
        }
    }

    for (const matchedProcess of matchedProcesses) {
        const missingPorts = matchedProcess.ports.filter((port) => !displayedPorts.has(port));
        if (missingPorts.length === 0) {
            continue;
        }

        const sameProcess = processInfos.find(
            (processInfo) => processInfo.PID && processInfo.PID === matchedProcess.PID,
        );
        if (sameProcess) {
            sameProcess.ports = [...sameProcess.ports, ...missingPorts].sort((a, b) => a - b);
        } else {
            processInfos.push({
                ...matchedProcess,
                ports: missingPorts,
            });
        }

        for (const port of missingPorts) {
            displayedPorts.add(port);
        }
    }
};

const loadListeningProcesses = async () => {
    try {
        const res = await getListeningProcess();
        listeningProcesses.value = res.data || [];

        for (const item of allRows.value) {
            if (item.ruleType !== 'port') {
                continue;
            }
            const matchedProcesses = loadMatchedListeningProcesses(item);

            if (item.usedStatus) {
                item.expand = false;
                item.processInfos = parseUsedStatus(item.usedStatus, item.port);
                applyProcessPID(item.processInfos, matchedProcesses);
                mergeListeningProcesses(item.processInfos, matchedProcesses);
                item.processInfo = item.processInfos.find((proc) => proc.PID) as Process.ListeningProcess;
                continue;
            }

            if (matchedProcesses.length > 0) {
                item.expand = false;
                item.usedStatus = matchedProcesses.map((proc) => proc.Name).join(', ');
                item.processInfo = matchedProcesses[0] as Process.ListeningProcess;
                item.processInfos = matchedProcesses;
            }
        }
    } catch (error) {
        console.error('Failed to load listening processes:', error);
    }
};

// ---- data load: merge port + address (client-side), tag, level, docker, process ----
const loadData = async () => {
    if (!isReady.value) {
        allRows.value = [];
        pageData.value = [];
        paginationConfig.total = 0;
        return;
    }
    loading.value = true;
    try {
        const [portRes, addrRes] = await Promise.all([
            searchFireRule({ type: 'port', strategy: '', info: '', page: 1, pageSize: 10000 }),
            searchFireRule({ type: 'address', strategy: '', info: '', page: 1, pageSize: 10000 }),
        ]);
        const portRows: InboundRow[] = (portRes.data.items || []).map((item) => ({
            ...item,
            ruleType: 'port',
        }));
        const addrRows: InboundRow[] = (addrRes.data.items || []).map((item) => ({
            ...item,
            ruleType: 'address',
        }));
        allRows.value = [...portRows, ...addrRows];

        await loadListeningProcesses();
        for (const row of allRows.value) {
            row.level = deriveLevel(row);
            row.dockerPublished = matchDocker(row);
        }
        applyAndSlice();
    } finally {
        loading.value = false;
    }
};

const applyAndSlice = () => {
    let rows = allRows.value.slice();
    if (searchStrategy.value) {
        rows = rows.filter((row) => row.strategy === searchStrategy.value);
    }
    if (activeLevel.value) {
        rows = rows.filter((row) => row.level === activeLevel.value);
    }
    if (searchName.value) {
        const keyword = searchName.value.toLowerCase();
        rows = rows.filter(
            (row) =>
                (row.port || '').toLowerCase().includes(keyword) ||
                (row.address || '').toLowerCase().includes(keyword) ||
                (row.description || '').toLowerCase().includes(keyword),
        );
    }
    rows.sort((a, b) => levelOrder(a.level) - levelOrder(b.level));
    paginationConfig.total = rows.length;
    const start = (paginationConfig.currentPage - 1) * paginationConfig.pageSize;
    pageData.value = rows.slice(start, start + paginationConfig.pageSize);
};

const onFilterChange = () => {
    paginationConfig.currentPage = 1;
    applyAndSlice();
};

const onFilterLevel = (level: string) => {
    activeLevel.value = level;
    onFilterChange();
};

// ---- create / edit (unified dialog) ----
const onOpenDialog = (
    title: 'create' | 'edit',
    objectType: Host.InboundRuleType = 'port',
    rowData: Partial<Host.UnifiedRuleForm> = {},
) => {
    dialogRef.value!.acceptParams({
        title,
        objectType,
        rowData,
        capabilities: capabilities.value,
        mode: mode.value,
    });
};

const onAllowPort = () => {
    onOpenDialog('create', 'port', { objectType: 'port', strategy: 'accept', protocol: 'tcp' });
};

const onBlockIP = () => {
    onOpenDialog('create', 'address', { objectType: 'address', strategy: 'drop' });
};

const onEdit = (row: InboundRow) => {
    onOpenDialog('edit', row.ruleType, {
        objectType: row.ruleType,
        port: row.port,
        address: row.address && row.address !== 'Anywhere' ? row.address : '',
        protocol: row.protocol,
        strategy: row.strategy,
        family: row.family,
        applyToDocker: row.dockerPublished,
        description: row.description,
    });
};

const onChange = async (row: InboundRow) => {
    const params: Host.UpdateDescription = {
        type: row.ruleType,
        chain: '',
        srcIP: row.address,
        dstIP: '',
        srcPort: '',
        dstPort: row.ruleType === 'port' ? row.port : '',
        protocol: row.ruleType === 'port' ? row.protocol : '',
        strategy: row.strategy,
        description: row.description,
    };
    await updateFirewallDescription(params);
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
};

const onChangeStatus = async (row: InboundRow, status: string) => {
    const isPort = row.ruleType === 'port';
    let operation: string;
    if (isPort) {
        operation =
            status === 'accept'
                ? i18n.global.t('firewall.changeStrategyPortHelper2')
                : i18n.global.t('firewall.changeStrategyPortHelper1');
    } else {
        operation =
            status === 'accept'
                ? i18n.global.t('firewall.changeStrategyIPHelper2')
                : i18n.global.t('firewall.changeStrategyIPHelper1');
    }
    ElMessageBox.confirm(
        operation,
        i18n.global.t('firewall.changeStrategy', [isPort ? i18n.global.t('commons.table.port') : ' IP ']),
        {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
        },
    ).then(async () => {
        loading.value = true;
        const request = isPort
            ? updatePortRule({
                  oldRule: {
                      operation: 'remove',
                      address: row.address,
                      port: row.port,
                      source: '',
                      protocol: row.protocol,
                      strategy: row.strategy,
                      description: row.description,
                  },
                  newRule: {
                      operation: 'add',
                      address: row.address,
                      port: row.port,
                      source: '',
                      protocol: row.protocol,
                      strategy: status,
                      description: row.description,
                  },
              })
            : updateAddrRule({
                  oldRule: {
                      operation: 'remove',
                      address: row.address,
                      strategy: row.strategy,
                      description: row.description,
                  },
                  newRule: {
                      operation: 'add',
                      address: row.address,
                      strategy: status,
                      description: row.description,
                  },
              });
        await request
            .then(() => {
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                loadData();
            })
            .finally(() => {
                loading.value = false;
            });
    });
};

// ---- delete (group selection by ruleType → two endpoints, single confirm) ----
const buildDeleteRule = (row: InboundRow) => ({
    operation: 'remove',
    chain: row.chain,
    address: row.address,
    port: row.ruleType === 'port' ? row.port : '',
    source: '',
    protocol: row.ruleType === 'port' ? row.protocol : '',
    strategy: row.strategy,
});

const ruleName = (row: InboundRow): string => {
    return row.ruleType === 'port' ? `${row.port} (${row.protocol})` : row.address;
};

const onDelete = (row: InboundRow | null) => {
    const targets = row ? [row] : (selects.value as InboundRow[]);
    const portRules = targets.filter((item) => item.ruleType === 'port').map(buildDeleteRule);
    const addrRules = targets.filter((item) => item.ruleType === 'address').map(buildDeleteRule);
    const names = targets.map(ruleName);

    const deleteApi = (params: { portRules: any[]; addrRules: any[] }) => {
        const tasks = [];
        if (params.portRules.length) {
            tasks.push(batchOperateRule({ type: 'port', rules: params.portRules }));
        }
        if (params.addrRules.length) {
            tasks.push(batchOperateRule({ type: 'address', rules: params.addrRules }));
        }
        return Promise.all(tasks);
    };

    opRef.value.acceptParams({
        title: i18n.global.t('commons.button.delete'),
        names: names,
        msg: i18n.global.t('commons.msg.operatorHelper', [
            i18n.global.t('firewall.inboundRule'),
            i18n.global.t('commons.button.delete'),
        ]),
        api: deleteApi,
        params: { portRules, addrRules },
    });
};

const onImport = () => {
    dialogImportRef.value.acceptParams();
};

const onExport = () => {
    ElMessageBox.confirm(
        i18n.global.t('firewall.exportHelper', [selects.value.length]),
        i18n.global.t('commons.button.export'),
        {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
        },
    ).then(async () => {
        const exportData = (selects.value as InboundRow[]).map((item) => {
            if (item.ruleType === 'port') {
                return {
                    family: item.family,
                    address: item.address,
                    port: item.port,
                    protocol: item.protocol,
                    strategy: item.strategy,
                    description: item.description,
                };
            }
            return {
                family: item.family,
                address: item.address,
                strategy: item.strategy,
                description: item.description,
            };
        });
        const content = JSON.stringify(exportData, null, 2);
        const fileName = `1panel-firewall-inbound-${getCurrentDateFormatted()}.json`;
        downloadWithContent(content, fileName);
    });
};

const showProcessDetail = (pid: number) => {
    processDetailRef.value?.acceptParams(pid);
};

const buttons = [
    {
        label: i18n.global.t('commons.button.edit'),
        permission: true,
        nodeAdmin: true,
        click: (row: InboundRow) => {
            onEdit(row);
        },
    },
    {
        label: i18n.global.t('commons.button.delete'),
        permission: true,
        nodeAdmin: true,
        disabled: (row: InboundRow) => row.level === 'baseline',
        click: (row: InboundRow) => {
            onDelete(row);
        },
    },
];

onMounted(async () => {
    await loadBaseInfo('base');
    await Promise.all([loadRescuePorts(), loadDockerStatus()]);
    await loadData();
});
</script>

<style lang="scss" scoped>
.process-name,
.process-link {
    display: block;
}

.process-link {
    cursor: pointer;
}

.process-list {
    display: block;
    margin-top: 2px;
}

.process-detail-icon {
    margin-left: 4px;
    vertical-align: middle;
}

.process-toggle {
    height: 20px;
    padding: 0;
}
</style>
