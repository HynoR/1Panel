<template>
    <div>
        <FireRouter />

        <div v-loading="loading">
            <LayoutContent :divider="true" v-if="!isReady">
                <template #main>
                    <div class="app-warn">
                        <div class="flex flex-col gap-2 items-center justify-center w-full sm:flex-row">
                            <span>{{ $t('firewall.goOverviewInit') }}</span>
                            <el-button type="primary" link @click="goOverview">
                                {{ $t('firewall.overview') }}
                            </el-button>
                        </div>
                        <div>
                            <img src="@/assets/images/no_app.svg" />
                        </div>
                    </div>
                </template>
            </LayoutContent>

            <div v-else-if="!capabilities.filter">
                <LayoutContent :divider="true">
                    <template #main>
                        <div class="app-warn">
                            <div class="flex flex-col gap-2 items-center justify-center w-full sm:flex-row">
                                <span>{{ $t('firewall.advancedControlNotAvailable', [name]) }}</span>
                            </div>
                            <div>
                                <img src="@/assets/images/no_app.svg" />
                            </div>
                        </div>
                    </template>
                </LayoutContent>
            </div>

            <div v-else>
                <el-card v-if="!isActive" class="mask-prompt">
                    <span>{{ $t('firewall.firewallNotStart') }}</span>
                </el-card>
                <LayoutContent :title="$t('firewall.filterRule')" :class="{ mask: !isActive }">
                    <template #prompt>
                        <el-alert type="info" :closable="false" :title="loadPrompt()" />
                    </template>
                    <template #leftToolBar>
                        <el-button v-permission v-node-admin type="primary" @click="onOpenDialog('create')">
                            {{ $t('firewall.create') }}
                        </el-button>
                        <el-button v-if="isBind" v-permission v-node-admin plain @click="onUnBind">
                            {{ $t('firewall.disableManaged') }}
                        </el-button>
                        <el-button v-if="!isBind" v-permission v-node-admin plain @click="onBind">
                            {{ $t('firewall.enableManaged') }}
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
                    </template>

                    <template #rightToolBar>
                        <el-tooltip :content="chainLabel()" placement="top">
                            <el-select v-model="selectedChain" @change="search()" clearable class="p-w-200">
                                <template #prefix>{{ $t('firewall.chain') }}</template>
                                <el-option :label="$t('firewall.inboundDirection')" value="1PANEL_INPUT"></el-option>
                                <el-option :label="$t('firewall.outboundDirection')" value="1PANEL_OUTPUT"></el-option>
                            </el-select>
                        </el-tooltip>
                        <TableRefresh @search="search()" />
                        <TableSetting title="firewall-filter-refresh" @search="search()" />
                    </template>

                    <template #main>
                        <ComplexTable
                            :pagination-config="paginationConfig"
                            v-model:selects="selects"
                            @search="search"
                            :data="data"
                            :heightDiff="220"
                        >
                            <el-table-column type="selection" fix />
                            <el-table-column :label="$t('commons.table.protocol')" :min-width="80" prop="protocol">
                                <template #default="{ row }">
                                    {{ row.protocol === '' ? 'ALL' : row.protocol }}
                                </template>
                            </el-table-column>
                            <el-table-column :label="$t('firewall.sourceIP')" :min-width="120" prop="srcIP">
                                <template #default="{ row }">
                                    {{ formatIP(row.srcIP) }}
                                </template>
                            </el-table-column>
                            <el-table-column :label="$t('firewall.sourcePort')" :min-width="100" prop="sourcePort">
                                <template #default="{ row }">
                                    {{ formatPort(row.srcPort) }}
                                </template>
                            </el-table-column>
                            <el-table-column :label="$t('firewall.destIP')" :min-width="120" prop="dstIP">
                                <template #default="{ row }">
                                    {{ formatIP(row.dstIP) }}
                                </template>
                            </el-table-column>
                            <el-table-column :label="$t('firewall.destPort')" :min-width="100" prop="dstPort">
                                <template #default="{ row }">
                                    {{ formatPort(row.dstPort) }}
                                </template>
                            </el-table-column>
                            <el-table-column :min-width="100" :label="$t('firewall.action')" prop="strategy">
                                <template #default="{ row }">
                                    <el-tag v-if="row.strategy === 'accept'" type="success">
                                        {{ $t('firewall.accept') }}
                                    </el-tag>
                                    <el-tag v-else-if="row.strategy === 'drop'" type="danger">
                                        {{ $t('firewall.drop') }}
                                    </el-tag>
                                    <el-tag v-else-if="row.strategy === 'reject'" type="warning">
                                        {{ row.strategy }}
                                    </el-tag>
                                    <el-tag v-else type="info">{{ row.strategy }}</el-tag>
                                </template>
                            </el-table-column>
                            <el-table-column
                                :min-width="150"
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
                                width="120px"
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

        <OpDialog ref="opRef" @search="search" />
        <OperateDialog @search="search" ref="dialogRef" />
    </div>
</template>

<script lang="ts" setup>
import FireRouter from '@/views/host/firewall/index.vue';
import OperateDialog from '@/views/host/firewall/advance/operate/index.vue';
import { onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';
import {
    searchFilterRules,
    batchOperateFilterRule,
    loadChainStatus,
    operateFilterChain,
    updateFirewallDescription,
} from '@/api/modules/host';
import { Host } from '@/api/interface/host';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { chainDirectionLabel, singleFlight } from '@/views/host/firewall/composables/firewallHelpers';

const { capabilities, isActive, isReady, name, loadBaseInfo } = useFireBaseInfo('advance');

const router = useRouter();
const loading = ref();
const selects = ref<Host.IptablesRules[]>([]);
const selectedChain = ref('1PANEL_INPUT');
const defaultStrategy = ref('ACCEPT');

const isBind = ref(false);

const opRef = ref();

const data = ref<Host.IptablesRules[]>([]);

const formatPort = (port?: number | null | string) => {
    if (port === '' || port === 0 || port === '0') {
        return i18n.global.t('firewall.allPorts');
    }
    if (port === undefined || port === null) {
        return '-';
    }
    return port;
};
const formatIP = (ip?: null | string) => {
    if (ip) {
        return ip === 'anywhere' ? i18n.global.t('firewall.anyWhere') : ip;
    }
    return i18n.global.t('firewall.anyWhere');
};

const paginationConfig = reactive({
    cacheSizeKey: 'firewall-filter-page-size',
    currentPage: 1,
    pageSize: Number(localStorage.getItem('firewall-filter-page-size')) || 20,
    total: 0,
});

const goOverview = () => {
    router.push({ path: '/hosts/firewall/overview' });
};

const chainLabel = () => chainDirectionLabel(selectedChain.value);

const search = async () => {
    if (!isActive.value) {
        loading.value = false;
        paginationConfig.total = 0;
        return;
    }
    let params = {
        type: selectedChain.value,
        info: '',
        page: paginationConfig.currentPage,
        pageSize: paginationConfig.pageSize,
    };
    loading.value = true;
    // 先 await 链状态，保证 loadPrompt() 首屏读到的是当前 chain 的真实 isBind/defaultStrategy，
    // 而不是上一次 search 残留的旧值（fire-and-forget 会让 prompt 短暂错显）。
    await loadStatus();
    await searchFilterRules(params)
        .then((res) => {
            loading.value = false;
            data.value = res.data.items || [];
            paginationConfig.total = res.data.total;
        })
        .catch(() => {
            loading.value = false;
        });
};

const loadPrompt = () => {
    if (isBind.value) {
        return i18n.global.t('firewall.defaultStrategy', [chainLabel(), defaultStrategy.value]);
    }
    return i18n.global.t('firewall.defaultStrategy2', [chainLabel(), defaultStrategy.value]);
};

const loadStatus = async () => {
    await loadChainStatus(selectedChain.value).then((res) => {
        isBind.value = res.data.isBind;
        defaultStrategy.value = res.data.defaultStrategy || 'ACCEPT';
    });
};
const onBind = async () => {
    ElMessageBox.confirm(i18n.global.t('firewall.bindHelper'), i18n.global.t('firewall.enableManaged'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
    })
        .then(async () => {
            await operateFilterChain(selectedChain.value, 'bind').then(() => {
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                loadStatus();
            });
        })
        .catch(() => {});
};
const onUnBind = async () => {
    ElMessageBox.confirm(i18n.global.t('firewall.unbindHelper'), i18n.global.t('firewall.disableManaged'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
    })
        .then(async () => {
            await operateFilterChain(selectedChain.value, 'unbind').then(() => {
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                loadStatus();
            });
        })
        .catch(() => {});
};

// dialogRef 保持未类型化：operate 对话框的 DialogProps.rowData 声明为 Host.IptablesFilterRuleOp（operation 必填），
// 而本页 onOpenDialog 的默认值缺 operation，强类型化会在 vue-tsc 下暴露该既有签名不匹配。
const dialogRef = ref();
const onOpenDialog = async (title: string, rowData?: Host.IptablesFilterRuleOp) => {
    const params = {
        title,
        rowData: rowData || {
            chain: selectedChain.value,
            protocol: 'tcp',
            strategy: 'accept',
            srcPort: 0,
            dstPort: 0,
        },
    };
    dialogRef.value!.acceptParams(params);
};

const onDelete = async (row: Host.IptablesRules | null) => {
    let names = [];
    let rules = [];
    if (row) {
        rules.push({
            operation: 'remove',
            id: row.id,
            chain: selectedChain.value,
            srcPort: Number(row.srcPort),
            dstPort: Number(row.dstPort),
            srcIP: row.srcIP === 'anywhere' ? '' : row.srcIP,
            dstIP: row.dstIP === 'anywhere' ? '' : row.dstIP,
            protocol: row.protocol,
            strategy: row.strategy,
        });
        names = [
            `${row.protocol} ${row.srcIP || '*'}:${row.srcPort || '*'} -> ${row.dstIP || '*'}:${row.dstPort || '*'}`,
        ];
    } else {
        for (const item of selects.value) {
            names.push(
                `${item.protocol} ${item.srcIP || '*'}:${item.srcPort || '*'} -> ${item.dstIP || '*'}:${
                    item.dstPort || '*'
                }`,
            );
            rules.push({
                operation: 'remove',
                id: item.id,
                chain: selectedChain.value,
                srcPort: Number(item.srcPort),
                dstPort: Number(item.dstPort),
                srcIP: item.srcIP === 'anywhere' ? '' : item.srcIP,
                dstIP: item.dstIP === 'anywhere' ? '' : item.dstIP,
                protocol: item.protocol,
                strategy: item.strategy,
            });
        }
    }
    opRef.value.acceptParams({
        title: i18n.global.t('commons.button.delete'),
        names: names,
        msg: i18n.global.t('firewall.deleteRuleConfirm', [rules.length]),
        api: batchOperateFilterRule,
        params: { rules: rules },
    });
};

const onChange = singleFlight(async (row: Host.IptablesRules) => {
    let params = {
        type: 'advance',
        chain: selectedChain.value,
        srcIP: row.srcIP,
        dstIP: row.dstIP,
        srcPort: row.srcPort,
        dstPort: row.dstPort,
        protocol: row.protocol,
        strategy: row.strategy,

        description: row.description,
    };
    await updateFirewallDescription(params);
    MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
});

const buttons = [
    {
        label: i18n.global.t('commons.button.delete'),
        permission: true,
        nodeAdmin: true,
        click: (row: Host.IptablesRules) => {
            onDelete(row);
        },
    },
];

onMounted(async () => {
    loading.value = true;
    await loadBaseInfo('advance');
    if (isReady.value && capabilities.value.filter) {
        await search();
    }
    loading.value = false;
});
</script>

<style lang="scss" scoped>
.chain-card {
    .chain-title {
        font-size: 16px;
        font-weight: 500;
        margin-bottom: 8px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .chain-policy {
        font-size: 14px;
        color: var(--el-text-color-secondary);
    }
}
</style>
