<template>
    <DrawerPro v-model="drawerVisible" :header="title" @close="handleClose" size="large">
        <el-form ref="formRef" label-position="top" @submit.prevent :model="form" :rules="rules" v-loading="loading">
            <el-form-item :label="$t('firewall.strategy')" prop="strategy" class="mb-4">
                <el-radio-group v-model="form.strategy">
                    <el-radio value="accept">{{ $t('firewall.allow') }}</el-radio>
                    <el-radio value="drop">{{ $t('firewall.deny') }}</el-radio>
                </el-radio-group>
            </el-form-item>
            <el-form-item :label="$t('firewall.ruleObject')" prop="objectType" class="mb-4">
                <el-radio-group v-model="form.objectType" :disabled="dialogTitle === 'edit'">
                    <el-radio value="port">{{ $t('firewall.ruleObjectPort') }}</el-radio>
                    <el-radio value="address">{{ $t('firewall.ruleObjectAddress') }}</el-radio>
                </el-radio-group>
            </el-form-item>

            <template v-if="form.objectType === 'port'">
                <el-form-item :label="$t('commons.table.protocol')" prop="protocol">
                    <el-select class="w-full" v-model="form.protocol">
                        <el-option value="tcp" label="tcp" />
                        <el-option value="udp" label="udp" />
                        <el-option value="tcp/udp" label="tcp/udp" />
                    </el-select>
                </el-form-item>
                <el-form-item :label="$t('commons.table.port')" prop="port">
                    <el-input
                        :disabled="dialogTitle === 'edit'"
                        clearable
                        v-model.trim="form.port"
                        :placeholder="$t('firewall.portHelper1')"
                    />
                </el-form-item>
            </template>

            <el-form-item v-else :label="$t('firewall.address')" prop="address">
                <el-input
                    :disabled="dialogTitle === 'edit'"
                    :rows="3"
                    type="textarea"
                    clearable
                    v-model.trim="form.address"
                    :placeholder="$t('firewall.addressHelper1')"
                />
            </el-form-item>

            <el-collapse v-model="activeCollapse">
                <el-collapse-item name="advanced" :title="$t('firewall.advancedOptions')">
                    <el-form-item v-if="form.objectType === 'port'" :label="$t('firewall.source')" prop="address">
                        <el-input
                            :disabled="dialogTitle === 'edit'"
                            clearable
                            v-model.trim="form.address"
                            :placeholder="$t('firewall.addressHelper1')"
                        />
                        <span class="input-help">{{ $t('firewall.sourceIPHelper') }}</span>
                    </el-form-item>

                    <el-form-item
                        v-if="mode === 'managed' && capabilities.ipv6Rules"
                        :label="$t('firewall.family')"
                        prop="family"
                    >
                        <el-radio-group v-model="form.family">
                            <el-radio value="both">{{ $t('firewall.familyBoth') }}</el-radio>
                            <el-radio value="ipv4">IPv4</el-radio>
                            <el-radio value="ipv6">IPv6</el-radio>
                        </el-radio-group>
                    </el-form-item>

                    <el-form-item v-if="dockerAvailable && form.strategy === 'drop'" prop="applyToDocker">
                        <el-checkbox v-model="form.applyToDocker">{{ $t('firewall.applyToDocker') }}</el-checkbox>
                        <span class="input-help">{{ $t('firewall.applyToDockerHelper') }}</span>
                    </el-form-item>

                    <el-form-item :label="$t('commons.table.description')" prop="description">
                        <el-input clearable v-model.trim="form.description" />
                    </el-form-item>
                </el-collapse-item>
            </el-collapse>
        </el-form>

        <template #footer>
            <span class="dialog-footer">
                <el-button @click="drawerVisible = false">{{ $t('commons.button.cancel') }}</el-button>
                <el-button type="primary" @click="onSubmit(formRef)">
                    {{ $t('commons.button.confirm') }}
                </el-button>
            </span>
        </template>
    </DrawerPro>
</template>

<script lang="ts" setup>
import { reactive, ref } from 'vue';
import { Rules } from '@/global/form-rules';
import i18n from '@/lang';
import { ElForm, ElMessageBox } from 'element-plus';
import { MsgError, MsgSuccess } from '@/utils/message';
import { Host } from '@/api/interface/host';
import { operateIPRule, operatePortRule, updateAddrRule, updatePortRule } from '@/api/modules/host';
import { deepCopy } from '@/utils/misc';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { computeFirewallRisk, ensurePortsLoaded } from '@/views/host/firewall/composables/useFirewallRisk';
import { isValidAddressList, isValidPortExpr } from '@/views/host/firewall/composables/firewallHelpers';
import { notifyFireChange } from '@/views/host/firewall/composables/useFireSession';

// 能力/模式直接读共享 baseInfo（列表页已加载），不再经 acceptParams 层层透传。
const { dockerAvailable, loadDockerStatus, capabilities, mode } = useFireBaseInfo('base');

interface DialogProps {
    title: 'create' | 'edit';
    objectType?: Host.InboundRuleType;
    rowData?: Partial<Host.UnifiedRuleForm>;
}

const loading = ref(false);
const drawerVisible = ref(false);
const title = ref('');
const dialogTitle = ref<'create' | 'edit'>('create');
const activeCollapse = ref<string[]>([]);

const emptyForm = (): Host.UnifiedRuleForm => ({
    objectType: 'port',
    port: '',
    address: '',
    protocol: 'tcp',
    strategy: 'accept',
    family: 'both',
    applyToDocker: false,
    description: '',
});
const form = reactive<Host.UnifiedRuleForm>(emptyForm());
const oldForm = ref<Host.UnifiedRuleForm>(emptyForm());

// 提交时一次红线校验：同时封 SSH+面板 → ElMessageBox 提示后取消。warn 分支删除，
// 自锁风险交给后端 L1 + 60 秒自动回滚兜底。
const evalRisk = (): Host.RiskInfo =>
    computeFirewallRisk({
        strategy: form.strategy,
        objectType: form.objectType,
        address: form.address,
        port: form.port,
    });

const emit = defineEmits<{ (e: 'search'): void }>();

const acceptParams = async (params: DialogProps): Promise<void> => {
    dialogTitle.value = params.title;
    Object.assign(form, emptyForm(), params.rowData || {});
    if (params.objectType) {
        form.objectType = params.objectType;
    }
    // 从列表点「封禁 IP」进入：预设拒绝并展开高级选项里的来源 IP。
    activeCollapse.value = form.objectType === 'address' || form.strategy === 'drop' ? ['advanced'] : [];
    if (params.title === 'edit') {
        oldForm.value = deepCopy(form);
    }
    title.value = i18n.global.t('firewall.' + params.title);
    drawerVisible.value = true;
    // await 端口与 docker 就绪，避免快速点确认时 redline 误判（panelPort 仍空 → coversPanel=false）。
    await Promise.all([ensurePortsLoaded(), loadDocker()]);
};

const loadDocker = async () => {
    await loadDockerStatus();
    if (dockerAvailable.value && dialogTitle.value === 'create') {
        form.applyToDocker = true;
    }
};

const handleClose = () => {
    drawerVisible.value = false;
};

const rules = reactive({
    strategy: [Rules.requiredSelect],
    protocol: [{ validator: checkProtocol, trigger: 'change' }],
    port: [{ validator: checkPortField, trigger: 'blur' }],
    address: [{ validator: checkAddress, trigger: 'blur' }],
});

function checkProtocol(rule: any, value: any, callback: any) {
    if (form.objectType === 'port' && !form.protocol) {
        return callback(new Error(i18n.global.t('commons.rule.requiredSelect')));
    }
    callback();
}

function checkPortField(rule: any, value: any, callback: any) {
    if (form.objectType === 'port' && !form.port) {
        return callback(new Error(i18n.global.t('commons.rule.requiredInput')));
    }
    callback();
}

function checkAddress(rule: any, value: any, callback: any) {
    if (form.objectType === 'address' && !form.address) {
        return callback(new Error(i18n.global.t('firewall.addressFormatError')));
    }
    if (!isValidAddressList(form.address)) {
        return callback(new Error(i18n.global.t('firewall.addressFormatError')));
    }
    callback();
}

const toRulePort = (data: Host.UnifiedRuleForm, operation: string): Host.RulePort => ({
    operation,
    port: data.port,
    protocol: data.protocol,
    strategy: data.strategy,
    address: data.address || '',
    source: data.address ? 'address' : 'anyWhere',
    family: data.family,
    applyToDocker: data.applyToDocker,
    description: data.description,
});

const toRuleIP = (data: Host.UnifiedRuleForm, operation: string): Host.RuleIP => ({
    operation,
    address: data.address,
    strategy: data.strategy,
    family: data.family,
    applyToDocker: data.applyToDocker,
    description: data.description,
});

type FormInstance = InstanceType<typeof ElForm>;
const formRef = ref<FormInstance>();

const onSubmit = async (formEl: FormInstance | undefined) => {
    if (!formEl) return;
    await formEl.validate(async (valid) => {
        if (!valid) return;
        if (form.objectType === 'port' && !isValidPortExpr(form.port)) {
            MsgError(i18n.global.t('firewall.portFormatError'));
            return;
        }
        // 确保端口就绪后再做红线判定，避免 sshPort/panelPort 未加载导致 redline 失效。
        await ensurePortsLoaded();
        const risk = evalRisk();
        if (risk.mode === 'redline') {
            ElMessageBox.alert(risk.message, i18n.global.t('firewall.redlineTitle'), {
                confirmButtonText: i18n.global.t('commons.button.confirm'),
                type: 'error',
            }).catch(() => {});
            return;
        }
        doSubmit();
    });
};

const doSubmit = async () => {
    loading.value = true;
    try {
        if (dialogTitle.value === 'create') {
            if (form.objectType === 'port') {
                await operatePortRule(toRulePort(form, 'add'));
            } else {
                await operateIPRule(toRuleIP(form, 'add'));
            }
        } else if (form.objectType === 'port') {
            await updatePortRule({
                oldRule: toRulePort(oldForm.value, 'remove'),
                newRule: toRulePort(form, 'add'),
            });
        } else {
            await updateAddrRule({
                oldRule: toRuleIP(oldForm.value, 'remove'),
                newRule: toRuleIP(form, 'add'),
            });
        }
        if (form.strategy === 'drop') {
            // drop=会话型候选（后端对触及保底端口的 drop / CIDR 封禁武装 60s 确认窗口）：
            // 刷新会话状态，武装了则由确认条接管提示，未武装补成功提示。
            await notifyFireChange();
        } else {
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        }
        emit('search');
        drawerVisible.value = false;
    } finally {
        loading.value = false;
    }
};

defineExpose({
    acceptParams,
});
</script>
