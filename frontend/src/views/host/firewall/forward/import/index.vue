<template>
    <DialogPro v-model="visible" :title="$t('commons.button.import')" size="large">
        <div>
            <el-alert :closable="false" show-icon type="info">
                <template #default>
                    <div>{{ $t('commons.msg.importHelper') }}</div>
                </template>
            </el-alert>
            <el-upload
                action="#"
                :auto-upload="false"
                ref="uploadRef"
                class="float-left mt-2"
                :show-file-list="false"
                :limit="1"
                accept=".json"
                :on-change="fileOnChange"
                :on-exceed="handleExceed"
                v-model:file-list="uploaderFiles"
            >
                <el-button class="float-left" type="primary">{{ $t('commons.button.upload') }}</el-button>
            </el-upload>

            <el-card class="mt-2 w-full" v-loading="loading">
                <ComplexTable
                    :pagination-config="paginationConfig"
                    @search="search"
                    v-model:selects="selects"
                    :data="pageData"
                    :height="440"
                >
                    <el-table-column type="selection" fix />
                    <el-table-column :label="$t('commons.table.status')" :min-width="80">
                        <template #default="{ row }">
                            <Status :status="row.status" />
                        </template>
                    </el-table-column>
                    <el-table-column :label="$t('commons.table.protocol')" :min-width="70" prop="protocol" />
                    <el-table-column :label="$t('firewall.sourcePort')" :min-width="70" prop="port" />
                    <el-table-column :label="$t('firewall.targetIP')" :min-width="100" prop="targetIP" />
                    <el-table-column :label="$t('firewall.targetPort')" :min-width="70" prop="targetPort" />
                    <el-table-column
                        v-if="forwardImpl === 'panel-nat'"
                        :label="$t('firewall.forwardInboundInterface')"
                        :min-width="100"
                        prop="interface"
                    >
                        <template #default="{ row }">
                            <span>
                                {{
                                    row.interface === '' || row.interface === 'all'
                                        ? $t('commons.table.all')
                                        : row.interface
                                }}
                            </span>
                        </template>
                    </el-table-column>
                </ComplexTable>
            </el-card>
        </div>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="visible = false">
                    {{ $t('commons.button.cancel') }}
                </el-button>
                <el-button type="primary" :disabled="selects.length === 0" @click="onImport">
                    {{ $t('commons.button.import') }}
                </el-button>
            </span>
        </template>
    </DialogPro>
</template>

<script lang="ts" setup>
import { ref } from 'vue';
import { genFileId, UploadFile, UploadFiles, UploadProps, UploadRawFile } from 'element-plus';
import { MsgError, MsgSuccess } from '@/utils/message';
import i18n from '@/lang';
import { operateForwardRule, searchFireRule, getNetworkOptions } from '@/api/modules/host';
import { Host } from '@/api/interface/host';

const emit = defineEmits<{ (e: 'search'): void }>();

const visible = ref(false);
const loading = ref(false);
const selects = ref<Host.RuleInfo[]>([]);
const displayData = ref<Host.RuleInfo[]>([]);
const currentRules = ref<Host.RuleInfo[]>([]);
const forwardImpl = ref('');
const availableInterfaces = ref<string[]>([]);

const uploadRef = ref();
const uploaderFiles = ref();
const pageData = ref<Host.RuleInfo[]>([]);
const paginationConfig = reactive({
    currentPage: 1,
    pageSize: 10,
    total: 0,
});

const acceptParams = async (_fireName: string, impl?: string): Promise<void> => {
    visible.value = true;
    displayData.value = [];
    selects.value = [];
    forwardImpl.value = impl || '';
    loadCurrentData(impl);
};

const loadCurrentData = async (impl?: string) => {
    const res = await searchFireRule({
        type: 'forward',
        strategy: '',
        info: '',
        page: 1,
        pageSize: 10000,
    });
    currentRules.value = res.data.items || [];
    // panel-nat 转发（ufw / iptables）才需要选择入站网卡；firewalld 原生转发不需要。
    if (impl === 'panel-nat') {
        const networkRes = await getNetworkOptions();
        availableInterfaces.value = networkRes.data || [];
    }
};

const search = () => {
    const startIndex = (paginationConfig.currentPage - 1) * paginationConfig.pageSize;
    const endIndex = startIndex + paginationConfig.pageSize;
    pageData.value = displayData.value.slice(startIndex, endIndex);
};

const fileOnChange = (_uploadFile: UploadFile, uploadFiles: UploadFiles) => {
    loading.value = true;
    displayData.value = [];
    uploaderFiles.value = uploadFiles;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const content = e.target.result as string;
            const parsed = JSON.parse(content);

            if (!Array.isArray(parsed)) {
                MsgError(i18n.global.t('commons.msg.errImportFormat'));
                loading.value = false;
                return;
            }

            for (const item of parsed) {
                if (!checkDataFormat(item)) {
                    MsgError(i18n.global.t('commons.msg.errImportFormat'));
                    loading.value = false;
                    return;
                }
            }

            compareRules(parsed);
            loading.value = false;
        } catch (error) {
            MsgError(i18n.global.t('commons.msg.errImport') + error.message);
            loading.value = false;
        }
    };
    reader.readAsText(_uploadFile.raw);
};

const handleExceed: UploadProps['onExceed'] = (files) => {
    uploadRef.value!.clearFiles();
    const file = files[0] as UploadRawFile;
    file.uid = genFileId();
    uploadRef.value!.handleStart(file);
};

const checkDataFormat = (item: any): boolean => {
    if (!item.protocol || !item.port || !item.targetIP || !item.targetPort) {
        return false;
    }
    if (!['tcp', 'udp', 'tcp/udp'].includes(item.protocol)) {
        return false;
    }

    if (forwardImpl.value === 'panel-nat' && item.interface !== undefined && item.interface !== null) {
        const interfaceValue = item.interface;
        if (interfaceValue !== '' && interfaceValue !== 'all') {
            if (!availableInterfaces.value.includes(interfaceValue)) {
                return false;
            }
        }
    }

    return true;
};

// 转发规则入站接口的 canonical 规整："*"(iptables -nvL 回显) 与 "all"/空串均表示"所有接口"，
// 统一映射为空串，使导入判重与后端 OperateForwardRule 判重口径一致。
const normForwardIface = (v: string | undefined | null): string => {
    const s = (v ?? '').trim();
    return s === '*' || s === 'all' ? '' : s;
};

const compareRules = (importedRules: any[]) => {
    const newRules: any[] = [];
    const conflictRules: any[] = [];
    const duplicateRules: any[] = [];

    for (const importedRule of importedRules) {
        const key = `${importedRule.protocol}:${importedRule.port}:${importedRule.targetIP}:${importedRule.targetPort}:${normForwardIface(importedRule.interface)}`;

        const existingRule = currentRules.value.find((rule) => {
            const existingKey = `${rule.protocol}:${rule.port}:${rule.targetIP}:${rule.targetPort}:${normForwardIface(rule.interface)}`;
            return existingKey === key;
        });

        if (!existingRule) {
            newRules.push({ ...importedRule, status: 'new' });
        } else {
            duplicateRules.push({ ...importedRule, status: 'duplicate' });
        }
    }

    displayData.value = [...newRules, ...conflictRules, ...duplicateRules];
    paginationConfig.total = displayData.value.length;
    search();
};

const onImport = async () => {
    loading.value = true;
    const rules: Host.RuleForward[] = [];
    for (const rule of selects.value) {
        rules.push({
            operation: 'add',
            protocol: rule.protocol,
            port: rule.port,
            targetIP: rule.targetIP,
            targetPort: rule.targetPort,
            interface: rule.interface || '',
        });
    }

    await operateForwardRule({ rules })
        .then(() => {
            loading.value = false;
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
            emit('search');
            visible.value = false;
        })
        .catch(() => {
            loading.value = false;
        });
};

defineExpose({
    acceptParams,
});
</script>
