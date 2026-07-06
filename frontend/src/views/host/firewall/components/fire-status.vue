<template>
    <div>
        <el-card v-if="isExist" v-loading="loading" class="card-interval">
            <div class="flex w-full flex-col gap-4 md:flex-row">
                <div class="ml-3 flex flex-wrap items-center gap-4">
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
                </div>
                <div class="mt-0.5">
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
                        <el-button v-permission v-node-admin type="primary" link @click="onOperate('restart')">
                            {{ $t('commons.button.restart') }}
                        </el-button>
                    </template>
                    <template v-if="!readyBase">
                        <el-divider v-if="mode === 'external'" direction="vertical" />
                        <el-button v-permission v-node-admin type="primary" link @click="onInit">
                            {{ $t('commons.button.init') }}
                        </el-button>
                    </template>
                    <template v-if="currentTab === 'base'">
                        <el-divider direction="vertical" />
                        <el-button v-permission v-node-admin type="primary" link @click="onOpenWhiteList">
                            {{ $t('firewall.portWhiteList') }}
                        </el-button>
                    </template>
                    <span v-if="currentTab === 'base' && showDefaultPolicy">
                        <el-divider direction="vertical" />
                        <el-button type="primary" link>{{ $t('firewall.whitelistMode') }}</el-button>
                        <el-tooltip :content="$t('firewall.whitelistModeTip')" placement="top">
                            <el-switch
                                v-permission
                                v-node-admin
                                size="small"
                                class="ml-2"
                                :model-value="strictMode"
                                @change="onToggleStrict"
                            />
                        </el-tooltip>
                    </span>
                    <span v-if="pingStatus !== 'None'">
                        <el-divider direction="vertical" />
                        <el-button type="primary" link>{{ $t('firewall.noPing') }}</el-button>
                        <el-switch
                            v-permission
                            v-node-admin
                            size="small"
                            class="ml-2"
                            inactive-value="Disable"
                            active-value="Enable"
                            v-model="onPing"
                            @change="onPingOperate"
                        />
                    </span>
                </div>
            </div>
        </el-card>
        <NoSuchService v-else name="Firewalld / Ufw / iptables" />

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
        <WhiteList ref="whiteListRef" @search="emitSearch" />
    </div>
</template>

<script lang="ts" setup>
import { computed, h, onMounted, ref } from 'vue';
import i18n from '@/lang';
import { operateFilterChain, operateFire } from '@/api/modules/host';
import { MsgSuccess } from '@/utils/message';
import { ElMessageBox, ElRadio, ElRadioGroup } from 'element-plus';
import NoSuchService from '@/components/layout-content/no-such-service.vue';
import Status from '@/components/status/index.vue';
import DockerRestart from '@/components/docker-proxy/docker-restart.vue';
import WhiteList from '@/views/host/firewall/components/white-list.vue';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { notifyFireChange } from '@/views/host/firewall/composables/useFireSession';

// dev-v2 式内嵌状态栏：一行 el-card（名称/状态 + 启停/重启 + 初始化/端口白名单入口 + 开关），
// 内嵌在各子页顶部。状态数据固定钉在 base tab（启停/禁 ping 均为全局动作），
// forward/advance 各自的初始化入口仍留在其列表页内。
defineProps({
    currentTab: { type: String, default: 'base' },
});

const emit = defineEmits(['search']);

const {
    loadBaseInfo,
    isExist,
    isActive,
    isReadyFor,
    capabilities,
    mode,
    name,
    version,
    pingStatus,
    strictMode,
    dockerAvailable,
    loadDockerStatus,
} = useFireBaseInfo('base');

const readyBase = isReadyFor('base');
const showDefaultPolicy = computed(() => mode.value === 'managed' && capabilities.value.defaultDrop && readyBase.value);

const loading = ref(false);
const onPing = ref('Disable');
const oldPing = ref('Disable');

const dockerRef = ref();
const whiteListRef = ref();
const operation = ref('restart');
const withDockerRestart = ref(false);

const load = async () => {
    loading.value = true;
    try {
        await loadBaseInfo('base');
        onPing.value = pingStatus.value || 'Disable';
        oldPing.value = onPing.value;
        await loadDockerStatus();
    } finally {
        loading.value = false;
    }
};

const emitSearch = () => {
    emit('search');
};

const reload = async () => {
    await load();
    emitSearch();
};

const onOpenWhiteList = () => {
    whiteListRef.value.acceptParams();
};

// 初始化：单个确认框内选默认入站策略（宽松推荐 / 白名单模式附锁外警示），
// 替代原多步向导。message 用渲染函数保证单选切换时警示行响应式更新。
const initPolicy = ref('loose');
const onInit = () => {
    initPolicy.value = 'loose';
    ElMessageBox.confirm(
        () =>
            h('div', { class: 'flex flex-col gap-2' }, [
                h('span', i18n.global.t('firewall.initMsg', [i18n.global.t('firewall.baseIptables')])),
                h('span', { class: 'font-medium' }, i18n.global.t('firewall.defaultPolicy')),
                h(
                    ElRadioGroup,
                    {
                        modelValue: initPolicy.value,
                        'onUpdate:modelValue': (val: string | number | boolean | undefined) => {
                            initPolicy.value = String(val);
                        },
                        class: 'flex flex-col items-start',
                    },
                    () => [
                        h(ElRadio, { value: 'loose' }, () => {
                            return `${i18n.global.t('firewall.policyLoose')} (${i18n.global.t(
                                'firewall.policyRecommended',
                            )})`;
                        }),
                        h(ElRadio, { value: 'strict', disabled: !capabilities.value.defaultDrop }, () => {
                            return i18n.global.t('firewall.policyStrict');
                        }),
                    ],
                ),
                initPolicy.value === 'strict'
                    ? h('span', { class: 'text-xs text-red-500' }, i18n.global.t('firewall.wizardStrictWarn'))
                    : null,
            ]),
        i18n.global.t('commons.button.init'),
        {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
        },
    )
        .then(async () => {
            loading.value = true;
            try {
                await operateFilterChain('1PANEL_BASIC', 'init-base');
                if (initPolicy.value === 'strict') {
                    // 开启白名单模式为会话型变更（后端武装 60s 确认窗口）：确认条接管提示。
                    await operateFilterChain('1PANEL_INPUT', 'enable-strict');
                    await notifyFireChange();
                } else {
                    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                }
            } finally {
                loading.value = false;
            }
            await reload();
        })
        .catch(() => {});
};

// 白名单模式开关：开启=未列出端口默认拒绝（高危，后端 60s 确认窗口兜底）。
// :model-value 单向绑定，取消时开关不会误翻。
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
            await notifyFireChange();
        } else {
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        }
    } finally {
        loading.value = false;
    }
    await reload();
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
            reload();
        })
        .catch(() => {
            reload();
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

onMounted(() => {
    load();
});
</script>
