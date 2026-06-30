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
                    <el-table-column type="selection" fix :selectable="isSelectable" />
                    <el-table-column :label="$t('commons.table.status')" :min-width="80">
                        <template #default="{ row }">
                            <Status :status="row.status" />
                        </template>
                    </el-table-column>
                    <el-table-column :label="$t('commons.table.type')" :min-width="90">
                        <template #default="{ row }">
                            {{
                                row.ruleType === 'address'
                                    ? $t('firewall.ruleObjectAddress')
                                    : $t('firewall.ruleObjectPort')
                            }}
                        </template>
                    </el-table-column>
                    <el-table-column :label="$t('commons.table.protocol')" :min-width="70">
                        <template #default="{ row }">
                            <span>{{ row.protocol || '-' }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column :label="$t('commons.table.port')" :min-width="70">
                        <template #default="{ row }">
                            <span>{{ row.port || '-' }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column :label="$t('firewall.address')" :min-width="100">
                        <template #default="{ row }">
                            <span v-if="row.address && row.address !== 'Anywhere'">{{ row.address }}</span>
                            <span v-else>{{ $t('firewall.allIP') }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column :label="$t('firewall.strategy')" :min-width="80" prop="strategy">
                        <template #default="{ row }">
                            {{ row.strategy === 'accept' ? $t('firewall.allow') : $t('firewall.deny') }}
                        </template>
                    </el-table-column>
                    <el-table-column
                        :label="$t('commons.table.description')"
                        :min-width="120"
                        prop="description"
                        show-overflow-tooltip
                    />
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
import { reactive, ref } from 'vue';
import { genFileId } from 'element-plus';
import type { UploadFile, UploadFiles, UploadInstance, UploadProps, UploadRawFile } from 'element-plus';
import { MsgError, MsgSuccess } from '@/utils/message';
import i18n from '@/lang';
import { operateIPRule, operatePortRule, searchFireRule } from '@/api/modules/host';
import { Host } from '@/api/interface/host';
import { checkCidr, checkCidrV6, checkIpV4V6, checkPort } from '@/utils/validate';
import { getErrorMessage } from '@/utils/misc';

const emit = defineEmits<{ (e: 'search'): void }>();

type ImportStatus = 'new' | 'conflict' | 'duplicate';
type RawImportRule = Partial<{
    ruleType: string;
    family: string;
    address: string;
    port: string | number;
    protocol: string;
    strategy: string;
    applyToDocker: boolean;
    description: string;
}>;
interface ImportRule {
    ruleType: Host.InboundRuleType;
    family: string;
    address: string;
    port: string;
    protocol: string;
    strategy: string;
    applyToDocker: boolean;
    description: string;
}
interface PreviewRule extends ImportRule {
    status: ImportStatus;
    existingStrategy?: string;
}

const visible = ref(false);
const loading = ref(false);
const selects = ref<PreviewRule[]>([]);
const displayData = ref<PreviewRule[]>([]);
// 端口/来源 IP 两类既有规则分别缓存，导入对比时各自比对
const currentPortRules = ref<Host.RuleInfo[]>([]);
const currentAddrRules = ref<Host.RuleInfo[]>([]);

const uploadRef = ref<UploadInstance>();
const uploaderFiles = ref<UploadFiles>([]);
const pageData = ref<PreviewRule[]>([]);
const paginationConfig = reactive({
    currentPage: 1,
    pageSize: 10,
    total: 0,
});

const acceptParams = async (): Promise<void> => {
    visible.value = true;
    displayData.value = [];
    selects.value = [];
    // await 既有规则就绪，避免用户开对话框立即选文件时 compareRules 误判全为 new、重复导入已存在规则。
    await loadCurrentData();
};

const loadCurrentData = async () => {
    const [portRes, addrRes] = await Promise.all([
        searchFireRule({ type: 'port', strategy: '', info: '', page: 1, pageSize: 10000 }),
        searchFireRule({ type: 'address', strategy: '', info: '', page: 1, pageSize: 10000 }),
    ]);
    currentPortRules.value = portRes.data.items || [];
    currentAddrRules.value = addrRes.data.items || [];
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

            const normalized: ImportRule[] = [];
            let invalidCount = 0;
            for (const item of parsed) {
                const row = normalizeRule(item as RawImportRule);
                if (!row) {
                    invalidCount++;
                    continue;
                }
                normalized.push(row);
            }

            if (normalized.length === 0) {
                MsgError(i18n.global.t('commons.msg.errImportFormat'));
                loading.value = false;
                return;
            }

            compareRules(normalized);
            if (invalidCount > 0) {
                MsgError(i18n.global.t('firewall.importInvalidSkipped', [invalidCount]));
            }
            loading.value = false;
        } catch (error) {
            MsgError(i18n.global.t('commons.msg.errImport') + getErrorMessage(error));
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

// 端口格式校验：支持单端口、范围（8080-8090）、列表（8080,8090），与 create/edit 复用同一 checkPort。
const isValidPort = (port: string): boolean => {
    const ports =
        port.indexOf('-') !== -1 && !port.startsWith('-')
            ? port.split('-')
            : port.indexOf(',') !== -1 && !port.startsWith(',')
              ? port.split(',')
              : [port];
    return ports.every((p) => !checkPort(p));
};

// 地址格式校验：支持逗号分隔多地址、IPv4/IPv6 单 IP 与 CIDR，Anywhere 视为合法。
const isValidAddress = (address: string): boolean => {
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

const normalizeAddress = (address?: string): string => {
    const trimmed = (address || '').trim();
    return trimmed && trimmed !== 'Anywhere' ? trimmed : 'Anywhere';
};

const normalizeFamily = (family?: string): string => {
    return family && ['ipv4', 'ipv6', 'both'].includes(family) ? family : 'both';
};

const buildRuleKey = (rule: Pick<ImportRule, 'ruleType' | 'address' | 'port' | 'protocol' | 'family'>): string => {
    const address = normalizeAddress(rule.address);
    return rule.ruleType === 'port'
        ? `${address}:${rule.port}:${rule.protocol}:${rule.family}`
        : `${address}:${rule.family}`;
};

// 优先用 ruleType 识别（export 已带该字段），否则按形状回退；校验端口/地址格式，非法返回 null。
const normalizeRule = (item: RawImportRule): ImportRule | null => {
    const strategy = item?.strategy || '';
    if (!item || !['accept', 'drop'].includes(strategy)) {
        return null;
    }
    const ruleType =
        item.ruleType === 'address'
            ? 'address'
            : item.ruleType === 'port'
              ? 'port'
              : item.port
                ? 'port'
                : item.address
                  ? 'address'
                  : '';
    const family = normalizeFamily(item.family);
    const address = normalizeAddress(item.address);
    if (ruleType === 'port') {
        const protocol = item.protocol || '';
        if (!item.port || !['tcp', 'udp', 'tcp/udp'].includes(protocol)) {
            return null;
        }
        const port = String(item.port).trim();
        if (!isValidPort(port) || !isValidAddress(address)) {
            return null;
        }
        return {
            ruleType: 'port',
            family,
            address,
            port,
            protocol,
            strategy,
            applyToDocker: !!item.applyToDocker,
            description: item.description || '',
        };
    }
    if (ruleType === 'address' && item.address) {
        if (!isValidAddress(address)) {
            return null;
        }
        return {
            ruleType: 'address',
            family,
            address,
            port: '',
            protocol: '',
            strategy,
            applyToDocker: !!item.applyToDocker,
            description: item.description || '',
        };
    }
    return null;
};

const compareRules = (importedRules: ImportRule[]) => {
    const newRules: PreviewRule[] = [];
    const conflictRules: PreviewRule[] = [];
    const duplicateRules: PreviewRule[] = [];
    // 导入文件内部按规则身份判重；同身份不同 strategy 视为冲突，避免一次导入生成互斥规则。
    const seenInternal = new Map<string, ImportRule>();

    for (const importedRule of importedRules) {
        const isPort = importedRule.ruleType === 'port';
        const ruleKey = buildRuleKey(importedRule);
        const seenRule = seenInternal.get(ruleKey);
        if (seenRule) {
            if (seenRule.strategy === importedRule.strategy && seenRule.applyToDocker === importedRule.applyToDocker) {
                duplicateRules.push({ ...importedRule, status: 'duplicate' });
            } else {
                conflictRules.push({
                    ...importedRule,
                    status: 'conflict',
                    existingStrategy: seenRule.strategy,
                });
            }
            continue;
        }
        seenInternal.set(ruleKey, importedRule);

        const source = isPort ? currentPortRules.value : currentAddrRules.value;
        const existingRule = source.find((rule) => {
            return (
                buildRuleKey({
                    ruleType: importedRule.ruleType,
                    address: rule.address,
                    port: rule.port,
                    protocol: rule.protocol,
                    family: rule.family || 'both',
                }) === ruleKey
            );
        });

        if (!existingRule) {
            newRules.push({ ...importedRule, status: 'new' });
        } else if (
            existingRule.strategy !== importedRule.strategy ||
            !!existingRule.applyToDocker !== importedRule.applyToDocker
        ) {
            conflictRules.push({
                ...importedRule,
                status: 'conflict',
                existingStrategy: existingRule.strategy,
            });
        } else {
            duplicateRules.push({ ...importedRule, status: 'duplicate' });
        }
    }

    displayData.value = [...newRules, ...conflictRules, ...duplicateRules];
    paginationConfig.total = displayData.value.length;
    search();
};

// 冲突/重复行不可选择，只有 new 行可导入，避免重复导入或覆盖现有规则。
const isSelectable = (row: PreviewRule): boolean => row.status === 'new';

const onImport = async () => {
    loading.value = true;
    const toImport = selects.value.filter((r) => r.status === 'new');
    if (toImport.length === 0) {
        loading.value = false;
        MsgError(i18n.global.t('firewall.importNoNew'));
        return;
    }
    let successCount = 0;
    let errorCount = 0;

    for (const rule of toImport) {
        try {
            if (rule.ruleType === 'address') {
                const params: Host.RuleIP = {
                    operation: 'add',
                    address: rule.address || 'Anywhere',
                    strategy: rule.strategy,
                    family: rule.family || 'both',
                    applyToDocker: !!rule.applyToDocker,
                    description: rule.description || '',
                };
                await operateIPRule(params);
            } else {
                const params: Host.RulePort = {
                    operation: 'add',
                    address: rule.address || 'Anywhere',
                    port: rule.port,
                    source: '',
                    protocol: rule.protocol,
                    strategy: rule.strategy,
                    family: rule.family || 'both',
                    applyToDocker: !!rule.applyToDocker,
                    description: rule.description || '',
                };
                await operatePortRule(params);
            }
            successCount++;
        } catch (error) {
            errorCount++;
            console.error('Failed to import rule:', rule, error);
        }
    }

    loading.value = false;

    if (errorCount === 0) {
        MsgSuccess(i18n.global.t('firewall.importSuccess', [successCount]));
        visible.value = false;
        emit('search');
    } else {
        MsgError(i18n.global.t('firewall.importPartialSuccess', [successCount, errorCount]));
        emit('search');
    }
};

defineExpose({
    acceptParams,
});
</script>
