<template>
    <div>
        <FireRouter />

        <NoSuchService v-if="!isExist" name="Firewalld / Ufw / iptables" />

        <div v-else v-loading="loading" class="flex flex-col gap-3">
            <!-- 优先级 alert：未初始化 > 未激活 > 开机降级 > 冲突，单一最高优先级，5 秒看清下一步动作 -->
            <el-alert
                v-if="topAlert"
                :type="topAlert.type"
                :closable="false"
                show-icon
                :description="topAlert.description"
            >
                <template #title>
                    <div class="flex flex-wrap items-center gap-2">
                        <span>{{ topAlert.title }}</span>
                        <el-link
                            v-if="showQuarantineEntry"
                            type="primary"
                            :underline="false"
                            @click.stop="onOpenQuarantine"
                        >
                            {{ $t('firewall.quarantineView') }}
                        </el-link>
                    </div>
                </template>
            </el-alert>

            <!-- 区1：状态总览条 -->
            <el-card shadow="never">
                <template #header>
                    <div class="flex flex-col">
                        <span class="font-medium">{{ $t('firewall.statusCard') }}</span>
                        <span class="text-xs text-gray-400">{{ $t('firewall.statusCardTip') }}</span>
                    </div>
                </template>
                <div class="flex flex-wrap items-center gap-x-4 gap-y-2">
                    <el-tag effect="dark" type="success">{{ name || '-' }}</el-tag>
                    <Status :status="isActive ? 'enable' : 'disable'" />
                    <el-tooltip
                        v-if="mode"
                        :content="
                            mode === 'managed' ? $t('firewall.modeManagedTip') : $t('firewall.modeExternalTip', [name])
                        "
                    >
                        <el-tag type="info">
                            {{ mode === 'managed' ? $t('firewall.modeManaged') : $t('firewall.modeExternal') }}
                        </el-tag>
                    </el-tooltip>
                    <el-tag>{{ $t('app.version') }}: {{ version || '-' }}</el-tag>
                    <el-divider direction="vertical" />
                    <div class="flex items-center gap-2">
                        <span class="text-sm text-gray-400">{{ $t('firewall.bootCheck') }}</span>
                        <el-tag v-if="!bootDegraded" type="success" size="small">{{ $t('firewall.bootOk') }}</el-tag>
                        <el-tag v-else type="warning" size="small">{{ baseInfo.bootStatus }}</el-tag>
                    </div>
                    <div v-if="showDefaultPolicy" class="flex items-center gap-2">
                        <span class="text-sm text-gray-400">{{ $t('firewall.defaultPolicy') }}</span>
                        <el-tag :type="strictMode ? 'warning' : 'success'" size="small">
                            {{ strictMode ? $t('firewall.policyStrict') : $t('firewall.policyLoose') }}
                        </el-tag>
                    </div>
                </div>
            </el-card>

            <!-- 区2：主操作区 -->
            <el-card shadow="never">
                <template #header>
                    <div class="flex flex-col">
                        <span class="font-medium">{{ $t('firewall.sectionActions') }}</span>
                        <span class="text-xs text-gray-400">{{ $t('firewall.sectionActionsTip') }}</span>
                    </div>
                </template>
                <div class="flex flex-col gap-4">
                    <!-- 启停 / 重启 / 初始化 -->
                    <div class="flex flex-wrap items-center gap-2">
                        <template v-if="mode === 'external'">
                            <el-button
                                v-if="isActive"
                                v-permission
                                v-node-admin
                                type="primary"
                                link
                                @click="onOperate('stop')"
                            >
                                {{ $t('commons.button.stop') }}
                            </el-button>
                            <el-button v-else v-permission v-node-admin type="primary" link @click="onOperate('start')">
                                {{ $t('commons.button.start') }}
                            </el-button>
                            <el-divider direction="vertical" />
                        </template>
                        <el-button v-permission v-node-admin type="primary" link @click="onOperate('restart')">
                            {{ $t('commons.button.restart') }}
                        </el-button>
                        <template v-if="!readyBase">
                            <el-divider direction="vertical" />
                            <el-button v-permission v-node-admin type="primary" link @click="onOpenWizard">
                                {{ $t('commons.button.init') }}
                            </el-button>
                        </template>
                    </div>

                    <!-- 白名单模式 / 禁 ping -->
                    <div class="flex flex-wrap items-center gap-x-6 gap-y-2">
                        <div v-if="showDefaultPolicy" class="flex items-center gap-2">
                            <span class="text-sm">{{ $t('firewall.whitelistMode') }}</span>
                            <el-switch
                                v-permission
                                v-node-admin
                                size="small"
                                :model-value="strictMode"
                                @change="onToggleStrict"
                            />
                            <el-tooltip :content="$t('firewall.whitelistModeTip')" placement="top">
                                <el-icon class="text-gray-400"><QuestionFilled /></el-icon>
                            </el-tooltip>
                        </div>
                        <div v-if="pingStatus !== 'None'" class="flex items-center gap-2">
                            <span class="text-sm">{{ $t('firewall.noPing') }}</span>
                            <el-switch
                                v-permission
                                v-node-admin
                                size="small"
                                inactive-value="Disable"
                                active-value="Enable"
                                v-model="onPing"
                                @change="onPingOperate"
                            />
                        </div>
                    </div>
                </div>
            </el-card>

            <!-- 区3 + 区4：保护汇总 / 恢复汇总 -->
            <el-row :gutter="12">
                <el-col :xs="24" :sm="24" :md="12" class="mb-3 md:mb-0">
                    <el-card shadow="never" class="h-full">
                        <template #header>
                            <div class="flex flex-col">
                                <span class="font-medium">{{ $t('firewall.rescueChannel') }}</span>
                                <span class="text-xs text-gray-400">{{ $t('firewall.rescueChannelTip') }}</span>
                            </div>
                        </template>
                        <div class="flex flex-col gap-3">
                            <div class="flex items-center justify-between">
                                <span>SSH: {{ sshPort }}</span>
                                <el-tag type="success" size="small">{{ $t('firewall.rescueReadOnly') }}</el-tag>
                            </div>
                            <div class="flex items-center justify-between">
                                <span>{{ $t('firewall.rescuePanel') }}: {{ panelPort }}</span>
                                <el-tag type="success" size="small">{{ $t('firewall.rescueReadOnly') }}</el-tag>
                            </div>
                            <div class="flex items-center justify-between">
                                <span>HTTP: 80</span>
                                <el-tooltip :content="$t('firewall.portWhiteListAlter')" placement="top">
                                    <el-switch
                                        v-permission
                                        v-node-admin
                                        size="small"
                                        v-model="http80"
                                        @change="onToggleRescue('80', $event)"
                                    />
                                </el-tooltip>
                            </div>
                            <div class="flex items-center justify-between">
                                <span>HTTPS: 443</span>
                                <el-tooltip :content="$t('firewall.portWhiteListAlter')" placement="top">
                                    <el-switch
                                        v-permission
                                        v-node-admin
                                        size="small"
                                        v-model="https443"
                                        @change="onToggleRescue('443', $event)"
                                    />
                                </el-tooltip>
                            </div>
                            <span class="text-xs text-gray-400">{{ $t('firewall.rescuePortSwitchHelper') }}</span>
                            <el-divider class="my-1" />
                            <div class="flex flex-wrap items-center gap-2">
                                <el-tag size="small" :type="dockerAvailable ? 'success' : 'info'">
                                    {{ $t('firewall.dockerProtection') }}:
                                    {{ dockerAvailable ? $t('firewall.capSupported') : $t('firewall.capNotSupported') }}
                                </el-tag>
                                <el-tag size="small" :type="capabilities.ipv6Rules ? 'success' : 'info'">
                                    {{ $t('firewall.ipv6RulesCap') }}:
                                    {{
                                        capabilities.ipv6Rules
                                            ? $t('firewall.capSupported')
                                            : $t('firewall.capNotSupported')
                                    }}
                                </el-tag>
                            </div>
                            <div>
                                <el-button v-permission v-node-admin type="primary" link @click="onOpenWhiteList">
                                    {{ $t('firewall.portWhiteList') }}
                                </el-button>
                            </div>
                        </div>
                    </el-card>
                </el-col>

                <el-col :xs="24" :sm="24" :md="12">
                    <el-card shadow="never" class="h-full">
                        <template #header>
                            <div class="flex flex-col">
                                <span class="font-medium">{{ $t('firewall.snapshot') }}</span>
                                <span class="text-xs text-gray-400">{{ $t('firewall.snapshotCardTip') }}</span>
                            </div>
                        </template>
                        <div class="flex flex-col gap-3">
                            <div class="flex items-center justify-between">
                                <span class="text-sm text-gray-400">{{ $t('firewall.snapshotLatest') }}</span>
                                <span class="text-sm">{{ latestSnapshot }}</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <el-tag size="small">{{ $t('firewall.snapshotCount', [snapshots.length]) }}</el-tag>
                            </div>
                            <div class="flex items-center justify-between">
                                <span class="text-sm text-gray-400">{{ $t('firewall.pendingSessionLabel') }}</span>
                                <el-tag v-if="applying" type="info" size="small">{{ $t('firewall.applying') }}</el-tag>
                                <el-tag v-else-if="session.active" type="warning" size="small">
                                    {{ $t('firewall.pendingSessionActive', [remain]) }}
                                </el-tag>
                                <el-tag v-else type="success" size="small">
                                    {{ $t('firewall.pendingSessionNone') }}
                                </el-tag>
                            </div>
                            <div>
                                <el-button
                                    v-permission
                                    v-node-admin
                                    type="primary"
                                    link
                                    :disabled="!capabilities.snapshot"
                                    @click="onOpenSnapshot"
                                >
                                    {{ $t('firewall.snapshot') }}
                                </el-button>
                            </div>
                        </div>
                    </el-card>
                </el-col>
            </el-row>

            <!-- 底部说明 + 快速跳转，避免四区下方留白 -->
            <el-card shadow="never">
                <div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                    <span class="text-xs text-gray-400">{{ $t('firewall.overviewHint') }}</span>
                    <div class="flex flex-wrap items-center gap-3">
                        <span class="text-xs text-gray-400">{{ $t('firewall.quickJump') }}</span>
                        <el-link
                            type="primary"
                            :underline="false"
                            @click="router.push({ path: '/hosts/firewall/inbound' })"
                        >
                            {{ $t('firewall.inboundRule', 2) }}
                        </el-link>
                        <el-link
                            type="primary"
                            :underline="false"
                            @click="router.push({ path: '/hosts/firewall/forward' })"
                        >
                            {{ $t('firewall.forwardRule', 2) }}
                        </el-link>
                        <el-link
                            v-if="capabilities.filter"
                            type="primary"
                            :underline="false"
                            @click="router.push({ path: '/hosts/firewall/advance' })"
                        >
                            {{ $t('firewall.advancedControl') }}
                        </el-link>
                    </div>
                </div>
            </el-card>
        </div>

        <DockerRestart
            ref="dockerRef"
            v-model:withDockerRestart="withDockerRestart"
            @submit="onSubmitWithDocker"
            :title="$t('firewall.firewallHelper', [$t('commons.button.' + operation)])"
        >
            <template #helper>
                <span>{{ $t('firewall.' + operation + 'FirewallHelper') }}</span>
            </template>
        </DockerRestart>
        <WhiteList ref="whiteListRef" @search="onReload" />
        <SnapshotDrawer ref="snapshotRef" />
        <InitWizard ref="wizardRef" @done="onReload" />
        <el-drawer v-model="quarantineDrawerVisible" :title="$t('firewall.quarantineTitle')" size="50%">
            <div class="flex h-full flex-col gap-3">
                <el-alert :closable="false" type="warning" :title="$t('firewall.quarantineHelper')" />
                <el-empty v-if="!quarantineRules.length" :description="$t('firewall.quarantineEmpty')" />
                <el-scrollbar v-else>
                    <div class="flex flex-col gap-2">
                        <el-text v-for="(rule, index) in quarantineRules" :key="index" tag="pre">
                            {{ rule }}
                        </el-text>
                    </div>
                </el-scrollbar>
                <div class="mt-auto flex justify-end">
                    <el-button
                        v-permission
                        v-node-admin
                        type="danger"
                        :loading="quarantineLoading"
                        @click="onCleanQuarantine"
                    >
                        {{ $t('firewall.quarantineClean') }}
                    </el-button>
                </div>
            </div>
        </el-drawer>
    </div>
</template>

<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import i18n from '@/lang';
import { Host } from '@/api/interface/host';
import { dateFormat } from '@/utils/date';
import {
    cleanFireQuarantine,
    getSSHInfo,
    listFireQuarantine,
    listFireSnapshot,
    operateFire,
    operateFilterChain,
} from '@/api/modules/host';
import { QuestionFilled } from '@element-plus/icons-vue';
import { getAgentSettingInfo, getSettingInfo, updateAgentSetting } from '@/api/modules/setting';
import { MsgSuccess, MsgWarning } from '@/utils/message';
import { ElMessageBox } from 'element-plus';
import FireRouter from '@/views/host/firewall/index.vue';
import NoSuchService from '@/components/layout-content/no-such-service.vue';
import Status from '@/components/status/index.vue';
import DockerRestart from '@/components/docker-proxy/docker-restart.vue';
import WhiteList from '@/views/host/firewall/components/white-list.vue';
import SnapshotDrawer from '@/views/host/firewall/components/snapshot-drawer.vue';
import InitWizard from '@/views/host/firewall/overview/init-wizard.vue';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { enterFireApplying, useFireSession } from '@/views/host/firewall/composables/useFireSession';

const router = useRouter();

const {
    baseInfo,
    loadBaseInfo,
    isExist,
    isActive,
    isReadyFor,
    capabilities,
    mode,
    name,
    version,
    pingStatus,
    conflict,
    bootDegraded,
    strictMode,
    dockerAvailable,
    loadDockerStatus,
} = useFireBaseInfo('base');

// 概览页固定按 base 钉住就绪态：不被其它 tab 的后台 loadBaseInfo 改写 activeTab 影响。
const readyBase = isReadyFor('base');

const { session, remain, applying } = useFireSession();

const loading = ref(false);
const onPing = ref('Disable');
const oldPing = ref('Disable');

const sshPort = ref('22');
const panelPort = ref('-');
const http80 = ref(false);
const https443 = ref(false);
const whiteListRaw = ref('');
const quarantineDrawerVisible = ref(false);
const quarantineLoading = ref(false);
const quarantineRules = ref<string[]>([]);

const snapshots = ref<Host.FirewallSnapshot[]>([]);

const dockerRef = ref();
const whiteListRef = ref();
const snapshotRef = ref();
const wizardRef = ref();
const operation = ref('restart');
const withDockerRestart = ref(false);

const showDefaultPolicy = computed(() => mode.value === 'managed' && capabilities.value.defaultDrop && readyBase.value);
const bootQuarantined = computed(() => (baseInfo.value.bootStatus || '').startsWith('degraded:quarantined'));
const showQuarantineEntry = computed(
    () => bootDegraded.value && bootQuarantined.value && readyBase.value && isActive.value,
);

// 顶部 alert 按可行动优先级取最高者：未初始化 > 未激活 > 开机降级 > 冲突。
// 待确认会话由全局 SessionConfirm 呈现，Docker/IPv6 能力归入区3 保护汇总，
// 避免在无 Docker 主机上误报"Docker 不可用"。
const topAlert = computed<{ type: 'warning' | 'error'; title: string; description?: string } | null>(() => {
    if (!readyBase.value) {
        return {
            type: 'warning',
            title: i18n.global.t('firewall.warnNotReady'),
            description: i18n.global.t('firewall.warnNotReadyHelper'),
        };
    }
    if (!isActive.value) {
        return {
            type: 'warning',
            title: i18n.global.t('firewall.warnNotActive'),
            description: i18n.global.t('firewall.warnNotActiveHelper'),
        };
    }
    if (bootDegraded.value) {
        return { type: 'warning', title: i18n.global.t('firewall.bootDegraded', [baseInfo.value.bootStatus]) };
    }
    if (conflict.value?.hasConflict) {
        return { type: 'error', title: conflict.value.message || i18n.global.t('firewall.conflictHelper') };
    }
    return null;
});

// 后端以 UTC 紧凑格式（20060102150405）存快照时间，new Date() 无法直接解析，需手动转本地时间展示。
// 非紧凑格式直接回原值；并对解析结果做有限性兜底，避免 dateFormat 喂入 Invalid Date 输出 NaN-NaN-NaN。
const formatSnapshotTime = (ts: string): string => {
    if (!ts) {
        return '—';
    }
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(ts);
    if (!m) {
        return ts;
    }
    const utc = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
    if (!Number.isFinite(utc)) {
        return ts;
    }
    return dateFormat(0, 0, utc);
};

const latestSnapshot = computed(() => {
    if (!snapshots.value.length) {
        return i18n.global.t('firewall.snapshotEmpty');
    }
    const newest = snapshots.value.reduce((a, b) => (a.createdAt > b.createdAt ? a : b));
    return newest.createdAt ? formatSnapshotTime(newest.createdAt) : newest.name;
});

// 保底端口组：80/443 的开关态从 FirewallPortWhiteList 设置推断（无后端字段）。
const rescueGroups: Record<string, string[]> = {
    '80': ['80/tcp'],
    '443': ['443/tcp', '443/udp'],
};

const parseWhiteList = (value: string): string[] =>
    (value || '')
        .split(/[\s,;]+/)
        .map((item) => item.trim())
        .filter((item) => item !== '');

const load = async () => {
    loading.value = true;
    try {
        await loadBaseInfo('base');
        onPing.value = pingStatus.value || 'Disable';
        oldPing.value = onPing.value;
        await Promise.all([loadDockerStatus(), loadRescue(), loadSnapshots()]);
    } finally {
        loading.value = false;
    }
};

const loadRescue = async () => {
    try {
        const ssh = await getSSHInfo();
        sshPort.value = ssh.data.port || '22';
    } catch {
        sshPort.value = '22';
    }
    try {
        const setting = await getSettingInfo();
        panelPort.value = String(setting.data.serverPort || '-');
    } catch {
        panelPort.value = '-';
    }
    try {
        const agent = await getAgentSettingInfo();
        whiteListRaw.value = agent.data.firewallPortWhiteList ?? '';
    } catch {
        whiteListRaw.value = '';
    }
    const list = parseWhiteList(whiteListRaw.value).map((item) => item.split('/')[0]);
    http80.value = list.includes('80');
    https443.value = list.includes('443');
};

const loadSnapshots = async () => {
    try {
        const res = await listFireSnapshot();
        snapshots.value = res.data || [];
    } catch {
        snapshots.value = [];
    }
};

const loadQuarantine = async () => {
    quarantineLoading.value = true;
    try {
        const res = await listFireQuarantine();
        quarantineRules.value = res.data || [];
    } finally {
        quarantineLoading.value = false;
    }
};

// 白名单（严格）模式开关：开启=向 AFTER 链注入 DROP（未列出端口拒绝），关闭=清空 AFTER（默认放行）。
// 开启高危（可能锁外），后端用 60s 提交-确认窗口兜底。:model-value 单向绑定，取消时开关不会误翻。
const onToggleStrict = async (val: boolean) => {
    const title = val
        ? i18n.global.t('firewall.enableWhitelistTitle')
        : i18n.global.t('firewall.disableWhitelistTitle');
    const helper = val
        ? i18n.global.t('firewall.enableWhitelistHelper')
        : i18n.global.t('firewall.disableWhitelistHelper');
    try {
        await ElMessageBox.confirm(helper, title, {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
            type: 'warning',
        });
    } catch {
        return;
    }
    loading.value = true;
    try {
        await operateFilterChain('1PANEL_INPUT', val ? 'enable-strict' : 'disable-strict');
        if (val) {
            MsgWarning(i18n.global.t('firewall.applying'));
            // 开启严格=会话型（后端 BeginSession 武装 60s 确认窗口）：即时进入应用中过渡态，
            // 不必等 3s 轮询拉起确认卡。
            enterFireApplying();
        } else {
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        }
        await load();
    } catch {
        await load();
    } finally {
        loading.value = false;
    }
};

const onReload = () => {
    load();
};

const onOpenQuarantine = async () => {
    quarantineDrawerVisible.value = true;
    await loadQuarantine();
};

const onCleanQuarantine = async () => {
    try {
        await ElMessageBox.confirm(
            i18n.global.t('firewall.quarantineCleanConfirm'),
            i18n.global.t('firewall.quarantineClean'),
            {
                confirmButtonText: i18n.global.t('commons.button.confirm'),
                cancelButtonText: i18n.global.t('commons.button.cancel'),
                type: 'warning',
            },
        );
    } catch {
        return;
    }
    quarantineLoading.value = true;
    try {
        await cleanFireQuarantine();
        quarantineRules.value = [];
        quarantineDrawerVisible.value = false;
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await load();
    } finally {
        quarantineLoading.value = false;
    }
};

const onOperate = async (op: string) => {
    operation.value = op;
    if (mode.value === 'managed' || !dockerAvailable.value) {
        await runOperate(false);
    } else {
        dockerRef.value.acceptParams({ title: i18n.global.t('firewall.dockerRestart') });
    }
};

const onSubmitWithDocker = async () => {
    await runOperate(withDockerRestart.value);
};

const runOperate = async (withDocker: boolean) => {
    loading.value = true;
    await operateFire(operation.value, withDocker)
        .then(() => {
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
            load();
        })
        .catch(() => {
            load();
        });
};

const onPingOperate = (val: string) => {
    const helper = val === 'Enable' ? i18n.global.t('firewall.noPingHelper') : i18n.global.t('firewall.onPingHelper');
    ElMessageBox.confirm(helper, i18n.global.t('firewall.noPingTitle'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
    })
        .then(async () => {
            loading.value = true;
            await operateFire(val === 'Enable' ? 'enableBanPing' : 'disableBanPing', false)
                .then(() => {
                    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                    load();
                })
                .catch(() => {
                    load();
                });
        })
        .catch(() => {
            onPing.value = oldPing.value;
        });
};

const saveWhiteList = async (port: string, open: boolean) => {
    let list = parseWhiteList(whiteListRaw.value);
    const group = rescueGroups[port];
    list = list.filter((item) => !group.includes(item) && item.split('/')[0] !== port);
    if (open) {
        list.push(...group);
    }
    await updateAgentSetting({ key: 'FirewallPortWhiteList', value: list.join('\n') });
    whiteListRaw.value = list.join('\n');
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
};

const onToggleRescue = async (port: string, val: boolean) => {
    if (!val) {
        try {
            await ElMessageBox.confirm(
                i18n.global.t('firewall.deleteRescuePortHelper', [port]),
                i18n.global.t('commons.button.confirm'),
                {
                    confirmButtonText: i18n.global.t('commons.button.confirm'),
                    cancelButtonText: i18n.global.t('commons.button.cancel'),
                    type: 'warning',
                },
            );
        } catch {
            if (port === '80') http80.value = true;
            if (port === '443') https443.value = true;
            return;
        }
    }
    try {
        await saveWhiteList(port, val);
    } catch {
        loadRescue();
    }
};

const onOpenWhiteList = () => {
    whiteListRef.value.acceptParams();
};
const onOpenSnapshot = () => {
    snapshotRef.value.acceptParams();
};
const onOpenWizard = () => {
    wizardRef.value.acceptParams({
        rescuePorts: [
            { name: 'SSH', port: sshPort.value },
            { name: i18n.global.t('firewall.rescuePanel'), port: panelPort.value },
        ],
    });
};

onMounted(() => {
    load();
});
</script>
