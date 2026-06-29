<template>
    <div>
        <FireRouter />

        <NoSuchService v-if="!isExist" name="Firewalld / Ufw / iptables" />

        <div v-else v-loading="loading">
            <el-alert
                v-if="conflict && conflict.hasConflict"
                class="mb-2"
                type="error"
                :closable="false"
                show-icon
                :title="conflict.message || $t('firewall.conflictHelper')"
            />
            <el-alert
                v-if="bootDegraded"
                class="mb-2"
                type="warning"
                :closable="false"
                show-icon
                :title="$t('firewall.bootDegraded', [baseInfo.bootStatus])"
            />

            <el-row :gutter="12">
                <!-- 卡片①：防火墙状态 -->
                <el-col :xs="24" :sm="24" :md="8" class="mb-3">
                    <el-card class="h-full" shadow="never">
                        <template #header>
                            <div class="flex flex-col">
                                <span class="font-medium">{{ $t('firewall.statusCard') }}</span>
                                <span class="text-xs text-gray-400">{{ $t('firewall.statusCardTip') }}</span>
                            </div>
                        </template>
                        <div class="flex flex-col gap-3">
                            <div class="flex flex-wrap items-center gap-2">
                                <el-tag effect="dark" type="success">{{ name || '-' }}</el-tag>
                                <Status :status="isActive ? 'enable' : 'disable'" />
                                <el-tooltip
                                    v-if="mode"
                                    :content="
                                        mode === 'managed'
                                            ? $t('firewall.modeManagedTip')
                                            : $t('firewall.modeExternalTip', [name])
                                    "
                                >
                                    <el-tag type="info">
                                        {{
                                            mode === 'managed'
                                                ? $t('firewall.modeManaged')
                                                : $t('firewall.modeExternal')
                                        }}
                                    </el-tag>
                                </el-tooltip>
                                <el-tag>{{ $t('app.version') }}: {{ version || '-' }}</el-tag>
                            </div>

                            <div class="flex flex-wrap items-center gap-2">
                                <span class="text-sm">{{ $t('firewall.bootCheck') }}:</span>
                                <el-tag v-if="!bootDegraded" type="success" size="small">
                                    {{ $t('firewall.bootOk') }}
                                </el-tag>
                                <el-tag v-else type="warning" size="small">{{ baseInfo.bootStatus }}</el-tag>
                            </div>

                            <div v-if="showDefaultPolicy" class="flex flex-wrap items-center gap-2">
                                <span class="text-sm">{{ $t('firewall.defaultPolicy') }}:</span>
                                <el-tag :type="strictPolicy ? 'danger' : 'success'" size="small">
                                    {{ strictPolicy ? $t('firewall.policyStrict') : $t('firewall.policyLoose') }}
                                </el-tag>
                            </div>

                            <div class="flex flex-wrap items-center gap-2">
                                <template v-if="mode === 'external'">
                                    <el-button
                                        v-permission
                                        v-node-admin
                                        type="primary"
                                        link
                                        v-if="isActive"
                                        @click="onOperate('stop')"
                                    >
                                        {{ $t('commons.button.stop') }}
                                    </el-button>
                                    <el-button
                                        v-permission
                                        v-node-admin
                                        type="primary"
                                        link
                                        v-else
                                        @click="onOperate('start')"
                                    >
                                        {{ $t('commons.button.start') }}
                                    </el-button>
                                    <el-divider direction="vertical" />
                                </template>
                                <el-button v-permission v-node-admin type="primary" link @click="onOperate('restart')">
                                    {{ $t('commons.button.restart') }}
                                </el-button>
                                <template v-if="!isReady">
                                    <el-divider direction="vertical" />
                                    <el-button v-permission v-node-admin type="primary" link @click="onOpenWizard">
                                        {{ $t('commons.button.init') }}
                                    </el-button>
                                </template>
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
                    </el-card>
                </el-col>

                <!-- 卡片②：保底通道 -->
                <el-col :xs="24" :sm="24" :md="8" class="mb-3">
                    <el-card class="h-full" shadow="never">
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
                                <el-switch
                                    v-permission
                                    v-node-admin
                                    size="small"
                                    v-model="http80"
                                    @change="onToggleRescue('80', $event)"
                                />
                            </div>
                            <div class="flex items-center justify-between">
                                <span>HTTPS: 443</span>
                                <el-switch
                                    v-permission
                                    v-node-admin
                                    size="small"
                                    v-model="https443"
                                    @change="onToggleRescue('443', $event)"
                                />
                            </div>
                            <div>
                                <el-button v-permission v-node-admin type="primary" link @click="onOpenWhiteList">
                                    {{ $t('firewall.portWhiteList') }}
                                </el-button>
                            </div>
                        </div>
                    </el-card>
                </el-col>

                <!-- 卡片③：快照 -->
                <el-col :xs="24" :sm="24" :md="8" class="mb-3">
                    <el-card class="h-full" shadow="never">
                        <template #header>
                            <div class="flex flex-col">
                                <span class="font-medium">{{ $t('firewall.snapshot') }}</span>
                                <span class="text-xs text-gray-400">{{ $t('firewall.snapshotCardTip') }}</span>
                            </div>
                        </template>
                        <div class="flex flex-col gap-3">
                            <div class="flex items-center gap-2">
                                <el-tag size="small">{{ $t('firewall.snapshotCount', [snapshots.length]) }}</el-tag>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="text-sm">{{ $t('firewall.snapshotLatest') }}:</span>
                                <span class="text-sm">{{ latestSnapshot }}</span>
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
    </div>
</template>

<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';
import i18n from '@/lang';
import { Host } from '@/api/interface/host';
import { dateFormat } from '@/utils/date';
import { operateFire, loadChainStatus, listFireSnapshot, getSSHInfo } from '@/api/modules/host';
import { getAgentSettingInfo, getSettingInfo, updateAgentSetting } from '@/api/modules/setting';
import { MsgSuccess } from '@/utils/message';
import { ElMessageBox } from 'element-plus';
import FireRouter from '@/views/host/firewall/index.vue';
import NoSuchService from '@/components/layout-content/no-such-service.vue';
import Status from '@/components/status/index.vue';
import DockerRestart from '@/components/docker-proxy/docker-restart.vue';
import WhiteList from '@/views/host/firewall/status/white-list/index.vue';
import SnapshotDrawer from '@/views/host/firewall/status/snapshot/index.vue';
import InitWizard from '@/views/host/firewall/overview/init-wizard.vue';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';

const {
    baseInfo,
    loadBaseInfo,
    isExist,
    isActive,
    isReady,
    capabilities,
    mode,
    name,
    version,
    pingStatus,
    conflict,
    bootDegraded,
    dockerAvailable,
    loadDockerStatus,
} = useFireBaseInfo();

const loading = ref(false);
const onPing = ref('Disable');
const oldPing = ref('Disable');

const sshPort = ref('22');
const panelPort = ref('-');
const http80 = ref(false);
const https443 = ref(false);
const whiteListRaw = ref('');

const strictPolicy = ref(false);
const snapshots = ref<Host.FirewallSnapshot[]>([]);

const dockerRef = ref();
const whiteListRef = ref();
const snapshotRef = ref();
const wizardRef = ref();
const operation = ref('restart');
const withDockerRestart = ref(false);

const showDefaultPolicy = computed(() => mode.value === 'managed' && capabilities.value.defaultDrop && isReady.value);

// 后端以 UTC 紧凑格式（20060102150405）存快照时间，new Date() 无法直接解析，需手动转本地时间展示。
const formatSnapshotTime = (ts: string): string => {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/.exec(ts || '');
    if (!m) {
        return ts;
    }
    const utc = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
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
        await Promise.all([loadDockerStatus(), loadRescue(), loadSnapshots(), loadDefaultPolicy()]);
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

const loadDefaultPolicy = async () => {
    if (mode.value !== 'managed' || !capabilities.value.defaultDrop || !isReady.value) {
        strictPolicy.value = false;
        return;
    }
    try {
        const res = await loadChainStatus('1PANEL_INPUT');
        strictPolicy.value = (res.data.defaultStrategy || 'ACCEPT').toUpperCase() === 'DROP';
    } catch {
        strictPolicy.value = false;
    }
};

const onReload = () => {
    load();
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
        tab: 'base',
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
