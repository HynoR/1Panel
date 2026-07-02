<template>
    <DrawerPro v-model="drawerVisible" :header="title" @close="handleClose" size="large">
        <el-form ref="formRef" label-position="top" @submit.prevent :model="form" :rules="rules" v-loading="loading">
            <el-alert :title="ruleHint.text" :type="ruleHint.type" :closable="false" show-icon class="mb-4" />
            <el-form-item :label="$t('firewall.intentLabel')" class="mb-4">
                <el-segmented v-model="intent" :options="intentOptions" />
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

        <el-alert :title="effectSummary" type="info" :closable="false" show-icon class="mt-2" />

        <template #footer>
            <span class="dialog-footer">
                <el-button @click="drawerVisible = false">{{ $t('commons.button.cancel') }}</el-button>
                <el-button type="primary" :disabled="riskLevel === 'redline'" @click="onSubmit(formRef)">
                    {{ $t('commons.button.confirm') }}
                </el-button>
            </span>
        </template>
    </DrawerPro>

    <RiskPrecheck ref="riskRef" @confirm="doSubmit" />
</template>

<script lang="ts" setup>
import { computed, reactive, ref, watch } from 'vue';
import { Rules } from '@/global/form-rules';
import i18n from '@/lang';
import { ElForm } from 'element-plus';
import { MsgError, MsgSuccess } from '@/utils/message';
import { Host } from '@/api/interface/host';
import { operateIPRule, operatePortRule, updateAddrRule, updatePortRule } from '@/api/modules/host';
import { deepCopy } from '@/utils/misc';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { computeFirewallRisk, ensurePortsLoaded } from '@/views/host/firewall/composables/useFirewallRisk';
import { isValidAddressList, isValidPortExpr } from '@/views/host/firewall/composables/firewallHelpers';
import { enterFireApplying } from '@/views/host/firewall/composables/useFireSession';
import RiskPrecheck from '@/views/host/firewall/components/risk-precheck.vue';

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

// 随策略/对象类型实时变化的说明文案，给小白用户讲清这条规则会做什么。
const ruleHint = computed<{ type: 'info' | 'warning'; text: string }>(() => {
    const deny = form.strategy === 'drop';
    if (form.objectType === 'address') {
        return deny
            ? { type: 'warning', text: i18n.global.t('firewall.hintDenyAddress') }
            : { type: 'info', text: i18n.global.t('firewall.hintAllowAddress') };
    }
    return deny
        ? { type: 'warning', text: i18n.global.t('firewall.hintDenyPort') }
        : { type: 'info', text: i18n.global.t('firewall.hintAllowPort') };
});

// 顶部 intent 选择器：用户按「想做什么」选择，strategy / objectType 由 intent 派生，
// 不再暴露独立的策略单选与对象类型单选。
type Intent = 'allowPort' | 'blockPort' | 'blockSource' | 'allowSource';
const intentMap: Record<Intent, { strategy: string; objectType: Host.InboundRuleType }> = {
    allowPort: { strategy: 'accept', objectType: 'port' },
    blockPort: { strategy: 'drop', objectType: 'port' },
    blockSource: { strategy: 'drop', objectType: 'address' },
    allowSource: { strategy: 'accept', objectType: 'address' },
};
const intent = ref<Intent>('allowPort');

const deriveIntent = (f: Host.UnifiedRuleForm): Intent => {
    if (f.objectType === 'address') return f.strategy === 'drop' ? 'blockSource' : 'allowSource';
    return f.strategy === 'drop' ? 'blockPort' : 'allowPort';
};

const intentOptions = computed(() => {
    // 编辑模式下锁定对象类型：只允许在同对象类型内 allow↔block 切换，
    // 避免把 port 规则改写成 address 规则导致 oldRule/newRule 类型错配。
    const isEdit = dialogTitle.value === 'edit';
    const portLocked = isEdit && form.objectType !== 'port';
    const addrLocked = isEdit && form.objectType !== 'address';
    return [
        { label: i18n.global.t('firewall.intentAllowPort'), value: 'allowPort', disabled: portLocked },
        { label: i18n.global.t('firewall.intentBlockPort'), value: 'blockPort', disabled: portLocked },
        { label: i18n.global.t('firewall.intentBlockSource'), value: 'blockSource', disabled: addrLocked },
        { label: i18n.global.t('firewall.intentAllowSource'), value: 'allowSource', disabled: addrLocked },
    ];
});

watch(intent, (v) => {
    if (!v) return;
    const mapped = intentMap[v];
    form.strategy = mapped.strategy;
    form.objectType = mapped.objectType;
});

// 实时效果预览：用现有 strategy / port / address / family 词汇拼出「这条规则将做什么」。
const effectSummary = computed(() => {
    const action = form.strategy === 'drop' ? i18n.global.t('firewall.deny') : i18n.global.t('firewall.allow');
    const source = form.address && form.address !== 'Anywhere' ? form.address : i18n.global.t('firewall.allIP');
    let msg: string;
    if (form.objectType === 'port') {
        msg = i18n.global.t('firewall.effectSummaryPort', [
            action,
            (form.protocol || '').toUpperCase(),
            form.port || '—',
            source,
        ]);
    } else {
        msg = i18n.global.t('firewall.effectSummaryAddr', [action, source]);
    }
    if (form.applyToDocker && dockerAvailable.value && form.strategy === 'drop') {
        msg += i18n.global.t('firewall.effectSummaryDocker');
    }
    return msg;
});

// 实时风险预检：redline 直接禁用 confirm，warn 仍走 onSubmit 的 RiskPrecheck 确认流程。
const riskLevel = ref<Host.RiskInfo['mode']>('none');
const evalRisk = (): Host.RiskInfo =>
    computeFirewallRisk({
        strategy: form.strategy,
        objectType: form.objectType,
        address: form.address,
        port: form.port,
    });
watch(
    form,
    async () => {
        if (!drawerVisible.value) return;
        await ensurePortsLoaded();
        riskLevel.value = evalRisk().mode;
    },
    { deep: true },
);

const riskRef = ref<InstanceType<typeof RiskPrecheck>>();
const emit = defineEmits<{ (e: 'search'): void }>();

const acceptParams = async (params: DialogProps): Promise<void> => {
    dialogTitle.value = params.title;
    Object.assign(form, emptyForm(), params.rowData || {});
    if (params.objectType) {
        form.objectType = params.objectType;
    }
    // 由 rule 反推 intent（编辑模式据此锁定同对象类型内的 allow/block 切换）。
    intent.value = deriveIntent(form);
    // 从列表点「封禁 IP」进入：预设拒绝并展开高级选项里的来源 IP。
    activeCollapse.value = form.objectType === 'address' || form.strategy === 'drop' ? ['advanced'] : [];
    if (params.title === 'edit') {
        oldForm.value = deepCopy(form);
    }
    title.value = i18n.global.t('firewall.' + params.title);
    drawerVisible.value = true;
    // await 端口与 docker 就绪，避免快速点确认时 redline 误判（panelPort 仍空 → coversPanel=false）。
    await Promise.all([ensurePortsLoaded(), loadDocker()]);
    riskLevel.value = evalRisk().mode;
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
        if (risk.mode === 'none') {
            doSubmit();
        } else {
            riskRef.value?.acceptParams({ mode: risk.mode, message: risk.message });
        }
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
            // 即时进入应用中过渡态（含「应用中…」提示），且不显示「最终成功」以免在用户确认前误导。
            enterFireApplying();
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
