<template>
    <div>
        <FireRouter />
        <FireStatus current-tab="forward" @search="reload" />

        <div v-loading="loading">
            <el-card v-if="isExist && !isReady" class="mask-prompt">
                <div class="flex flex-col items-center justify-center gap-2 py-8">
                    <span>{{ $t('firewall.initHelper', [$t('firewall.forwardIptables')]) }}</span>
                    <div>
                        <el-button v-if="isActive" v-permission v-node-admin type="primary" @click="onInitForward">
                            {{ $t('commons.button.init') }}
                        </el-button>
                    </div>
                </div>
            </el-card>

            <div v-else-if="isExist">
                <el-alert
                    v-if="!isActive"
                    class="mb-2"
                    type="warning"
                    :closable="false"
                    show-icon
                    :title="$t('firewall.firewallNotStart')"
                />

                <LayoutContent :title="$t('firewall.forwardRule', 2)" :class="{ mask: !isActive }">
                    <template #leftToolBar>
                        <el-button v-permission v-node-admin type="primary" @click="onOpenDialog('create')">
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
                        <TableSearch @search="search()" v-model:searchName="searchName" />
                        <TableRefresh @search="search()" />
                        <TableSetting title="firewall-forward-refresh" @search="search()" />
                    </template>
                    <template #main>
                        <ComplexTable
                            :pagination-config="paginationConfig"
                            v-model:selects="selects"
                            @search="search"
                            :data="data"
                            :heightDiff="370"
                        >
                            <el-table-column type="selection" fix />
                            <el-table-column :label="$t('commons.table.protocol')" :min-width="70" prop="protocol" />
                            <el-table-column :label="$t('firewall.sourcePort')" :min-width="70" prop="port" />
                            <el-table-column :min-width="80" :label="$t('firewall.targetIP')" prop="targetIP" />
                            <el-table-column :label="$t('firewall.targetPort')" :min-width="70" prop="targetPort" />
                            <template v-if="capabilities.forwardImpl === 'panel-nat'">
                                <el-table-column
                                    :label="$t('firewall.forwardInboundInterface')"
                                    :min-width="70"
                                    prop="interface"
                                >
                                    <template #default="{ row }">
                                        <span>
                                            {{ row.interface === '' ? $t('commons.table.all') : row.interface }}
                                        </span>
                                    </template>
                                </el-table-column>
                            </template>
                            <fu-table-operations
                                width="200px"
                                :buttons="buttons"
                                :ellipsis="10"
                                :label="$t('commons.table.operate')"
                                fix
                            />
                            <template #empty>
                                <el-empty :image-size="80" :description="$t('firewall.forwardEmpty')">
                                    <div class="mt-1 flex flex-col items-center gap-1 text-xs text-gray-400">
                                        <span>{{ $t('firewall.forwardHelper2') }}</span>
                                        <span>{{ $t('firewall.forwardHelper1') }}</span>
                                        <el-tag type="info" size="small" class="mt-1">8080 → 192.168.1.10:80</el-tag>
                                    </div>
                                </el-empty>
                            </template>
                        </ComplexTable>
                    </template>
                </LayoutContent>
            </div>
        </div>

        <OpDialog ref="opRef" @search="search" @submit="onSubmitDelete()">
            <template #content>
                <el-form class="mt-4 mb-1" ref="deleteForm" label-position="left">
                    <el-form-item>
                        <el-checkbox v-model="forceDelete" :label="$t('website.forceDelete')" />
                        <span class="input-help">
                            {{ $t('website.forceDeleteHelper') }}
                        </span>
                    </el-form-item>
                </el-form>
            </template>
        </OpDialog>
        <OperateDialog @search="search" ref="dialogRef" />
        <ImportDialog @search="search" ref="dialogImportRef" />
    </div>
</template>

<script lang="ts" setup>
import FireRouter from '@/views/host/firewall/index.vue';
import FireStatus from '@/views/host/firewall/components/fire-status.vue';
import OperateDialog from './operate/index.vue';
import ImportDialog from './import/index.vue';
import { onMounted, reactive, ref } from 'vue';
import { operateForwardRule, operateFilterChain, searchFireRule } from '@/api/modules/host';
import { Host } from '@/api/interface/host';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { downloadWithContent } from '@/utils/file';
import { getCurrentDateFormatted } from '@/utils/date';

const { isExist, isActive, isReady, capabilities, loadBaseInfo } = useFireBaseInfo('forward');

const loading = ref();
const activeTag = ref('forward');
const selects = ref<Host.RuleInfo[]>([]);
const searchName = ref();
const searchStrategy = ref('');

const opRef = ref();
const dialogImportRef = ref<InstanceType<typeof ImportDialog>>();
const forceDelete = ref(false);
const operateRules = ref<Host.RuleForward[]>([]);

const data = ref<Host.RuleInfo[]>([]);
const paginationConfig = reactive({
    cacheSizeKey: 'firewall-forward-page-size',
    currentPage: 1,
    pageSize: Number(localStorage.getItem('firewall-forward-page-size')) || 20,
    total: 0,
});

const reload = async () => {
    await loadBaseInfo('forward');
    search();
};

const onInitForward = () => {
    ElMessageBox.confirm(
        i18n.global.t('firewall.initMsg', [i18n.global.t('firewall.forwardIptables')]),
        i18n.global.t('commons.button.init'),
        {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
        },
    )
        .then(async () => {
            await operateFilterChain('1PANEL_FORWARD', 'init-forward').then(() => {
                MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
                reload();
            });
        })
        .catch(() => {});
};

const search = async () => {
    if (!isReady.value || !isActive.value) {
        loading.value = false;
        data.value = [];
        paginationConfig.total = 0;
        return;
    }
    let params = {
        type: activeTag.value,
        strategy: searchStrategy.value,
        info: searchName.value,
        page: paginationConfig.currentPage,
        pageSize: paginationConfig.pageSize,
    };
    loading.value = true;
    await searchFireRule(params)
        .then((res) => {
            loading.value = false;
            data.value =
                res.data.items?.map((item) => {
                    return {
                        ...item,
                        interface: item.interface === '*' ? '' : item.interface,
                    };
                }) || [];
            paginationConfig.total = res.data.total;
        })
        .catch(() => {
            loading.value = false;
        });
};

// dialogRef 保持未类型化：operate 对话框的 DialogProps.rowData 声明为 Host.RuleForward（非 Partial），
// 而本页 onOpenDialog 传的是 Partial<Host.RuleForward>，强类型化会在 vue-tsc 下暴露该既有签名不匹配。
const dialogRef = ref();
const onOpenDialog = async (
    title: string,
    rowData: Partial<Host.RuleForward> = {
        protocol: 'tcp',
        port: '8080',
        targetIP: '',
        targetPort: '',
        interface: '',
    },
) => {
    let params = {
        title,
        rowData: { ...rowData },
        capabilities: capabilities.value,
    };
    dialogRef.value!.acceptParams(params);
};
const onDelete = async (row: Host.RuleForward | null) => {
    let names = [];
    let rules = [];
    if (row) {
        rules.push({
            ...row,
            operation: 'remove',
        });
        names = [row.port + ' (' + row.protocol + ')'];
    } else {
        for (const item of selects.value) {
            names.push(item.port + ' (' + item.protocol + ')');
            rules.push({
                ...item,
                operation: 'remove',
            });
        }
    }
    operateRules.value = rules;
    opRef.value.acceptParams({
        title: i18n.global.t('commons.button.delete'),
        names: names,
        msg: i18n.global.t('commons.msg.operatorHelper', [
            i18n.global.t('firewall.forwardRule'),
            i18n.global.t('commons.button.delete'),
        ]),
        api: null,
        params: null,
    });
};
const onSubmitDelete = async () => {
    loading.value = true;
    await operateForwardRule({ rules: operateRules.value, forceDelete: forceDelete.value })
        .then(() => {
            loading.value = false;
            MsgSuccess(i18n.global.t('commons.msg.deleteSuccess'));
            search();
        })
        .catch(() => {
            loading.value = false;
        });
};

const onImport = () => {
    dialogImportRef.value.acceptParams(capabilities.value.forwardImpl);
};

const onExport = () => {
    ElMessageBox.confirm(
        i18n.global.t('firewall.exportHelper', [selects.value.length]),
        i18n.global.t('commons.button.export'),
        {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
        },
    )
        .then(async () => {
            const exportData = selects.value.map((item: Host.RuleInfo) => ({
                family: item.family,
                protocol: item.protocol,
                port: item.port,
                targetIP: item.targetIP,
                targetPort: item.targetPort,
                interface: item.interface,
            }));
            const content = JSON.stringify(exportData, null, 2);
            const fileName = `1panel-firewall-forward-${getCurrentDateFormatted()}.json`;
            downloadWithContent(content, fileName);
        })
        .catch(() => {});
};

const buttons = [
    {
        label: i18n.global.t('commons.button.edit'),
        permission: true,
        nodeAdmin: true,
        click: (row: Host.RuleForward) => {
            onOpenDialog('edit', row);
        },
    },
    {
        label: i18n.global.t('commons.button.delete'),
        permission: true,
        nodeAdmin: true,
        click: (row: Host.RuleForward) => {
            onDelete(row);
        },
    },
];

onMounted(async () => {
    forceDelete.value = false;
    loading.value = true;
    await reload();
});
</script>

<style lang="scss" scoped>
.svg-icon {
    font-size: 8px;
    margin-bottom: -4px;
    cursor: pointer;
}
</style>
