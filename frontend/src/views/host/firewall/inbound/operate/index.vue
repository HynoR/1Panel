<template>
    <DrawerPro v-model="drawerVisible" :header="title" @close="handleClose" size="large">
        <el-form ref="formRef" label-position="top" @submit.prevent :model="form" :rules="rules" v-loading="loading">
            <el-alert :title="ruleHint.text" :type="ruleHint.type" :closable="false" show-icon class="mb-4" />
            <el-form-item prop="strategy">
                <template #label>
                    <span class="inline-flex items-center gap-1">
                        {{ $t('firewall.strategy') }}
                        <el-tooltip :content="$t('firewall.strategyTip')" placement="top">
                            <el-icon class="text-gray-400"><QuestionFilled /></el-icon>
                        </el-tooltip>
                    </span>
                </template>
                <el-radio-group v-model="form.strategy">
                    <el-radio value="accept">{{ $t('firewall.allow') }}</el-radio>
                    <el-radio value="drop">{{ $t('firewall.deny') }}</el-radio>
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
                    <el-form-item :label="$t('firewall.inboundRule')" prop="objectType">
                        <el-radio-group v-model="form.objectType" :disabled="dialogTitle === 'edit'">
                            <el-radio value="port">{{ $t('firewall.ruleObjectPort') }}</el-radio>
                            <el-radio value="address">{{ $t('firewall.ruleObjectAddress') }}</el-radio>
                        </el-radio-group>
                    </el-form-item>

                    <el-form-item v-if="form.objectType === 'port'" :label="$t('firewall.address')" prop="address">
                        <el-input
                            :disabled="dialogTitle === 'edit'"
                            clearable
                            v-model.trim="form.address"
                            :placeholder="$t('firewall.addressHelper1')"
                        />
                    </el-form-item>

                    <el-form-item
                        v-if="dialogMode === 'managed' && capabilities && capabilities.ipv6Rules"
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

    <RiskPrecheck ref="riskRef" @confirm="doSubmit" />
</template>

<script lang="ts" setup>
import { computed, reactive, ref } from 'vue';
import { Rules } from '@/global/form-rules';
import i18n from '@/lang';
import { ElForm } from 'element-plus';
import { QuestionFilled } from '@element-plus/icons-vue';
import { MsgError, MsgSuccess } from '@/utils/message';
import { Host } from '@/api/interface/host';
import { getSSHInfo, operateIPRule, operatePortRule, updateAddrRule, updatePortRule } from '@/api/modules/host';
import { getSettingInfo } from '@/api/modules/setting';
import { checkCidr, checkCidrV6, checkIpV4V6, checkPort } from '@/utils/validate';
import { deepCopy } from '@/utils/misc';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import RiskPrecheck from '@/views/host/firewall/components/risk-precheck.vue';

const { dockerAvailable, loadDockerStatus } = useFireBaseInfo();

interface DialogProps {
    title: 'create' | 'edit';
    objectType?: Host.InboundRuleType;
    rowData?: Partial<Host.UnifiedRuleForm>;
    capabilities?: Host.FirewallCapabilities;
    mode?: string;
}

const loading = ref(false);
const drawerVisible = ref(false);
const title = ref('');
const dialogTitle = ref<'create' | 'edit'>('create');
const dialogMode = ref('');
const capabilities = ref<Host.FirewallCapabilities>();
const activeCollapse = ref<string[]>([]);

const sshPort = ref('22');
// 面板端口取核心设置，而非 window.location.port（开发/反代下不等于真实面板端口），保证封禁风险预检准确。
const panelPort = ref('');

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

const riskRef = ref<InstanceType<typeof RiskPrecheck>>();
const emit = defineEmits<{ (e: 'search'): void }>();

const acceptParams = (params: DialogProps): void => {
    dialogTitle.value = params.title;
    dialogMode.value = params.mode || '';
    capabilities.value = params.capabilities;
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
    loadSSHPort();
    loadPanelPort();
    loadDocker();
};

const loadSSHPort = async () => {
    try {
        const res = await getSSHInfo();
        sshPort.value = res.data.port || '22';
    } catch {
        sshPort.value = '22';
    }
};

const loadPanelPort = async () => {
    try {
        const res = await getSettingInfo();
        panelPort.value = String(res.data.serverPort || '');
    } catch {
        panelPort.value = '';
    }
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
    if (form.objectType === 'address') {
        if (!form.address) {
            return callback(new Error(i18n.global.t('firewall.addressFormatError')));
        }
    } else if (!form.address) {
        return callback();
    }
    const addrs = form.address.split(',');
    for (const item of addrs) {
        if (item.indexOf('/') !== -1) {
            if (item.indexOf(':') !== -1) {
                if (checkCidrV6(item)) {
                    return callback(new Error(i18n.global.t('firewall.addressFormatError')));
                }
            } else if (checkCidr(item)) {
                return callback(new Error(i18n.global.t('firewall.addressFormatError')));
            }
        } else if (checkIpV4V6(item)) {
            return callback(new Error(i18n.global.t('firewall.addressFormatError')));
        }
    }
    callback();
}

const isBroadSource = (): boolean => {
    const addr = (form.address || '').trim();
    return addr === '' || addr === '0.0.0.0/0' || addr === '::/0';
};

const isAllPorts = (port: string): boolean => {
    const p = (port || '').trim();
    return p === '' || p === '0';
};

const portsInclude = (port: string, target: string): boolean => {
    if (!target) return false;
    const t = Number(target);
    const segs = (port || '').split(',');
    for (const seg of segs) {
        const s = seg.trim();
        if (!s) continue;
        if (s.indexOf('-') !== -1 && !s.startsWith('-')) {
            const [from, to] = s.split('-').map((n) => Number(n.trim()));
            if (t >= from && t <= to) return true;
        } else if (Number(s) === t) {
            return true;
        }
    }
    return false;
};

// 纯客户端启发式：不依赖后端 risk 字段，最终安全网仍是提交后的会话确认自动撤销。
const computeRisk = (): Host.RiskInfo => {
    if (form.strategy !== 'drop') {
        return { mode: 'none', message: '' };
    }
    if (form.objectType === 'address') {
        // 纯 IP 黑名单：仅当来源宽泛（可能把所有人含自己挡掉）时提示。
        return isBroadSource()
            ? { mode: 'warn', message: i18n.global.t('firewall.riskBlockSelf') }
            : { mode: 'none', message: '' };
    }
    // 指定来源的端口拒绝只影响该来源，自锁风险低。
    if (!isBroadSource()) {
        return { mode: 'none', message: '' };
    }
    const coversAll = isAllPorts(form.port);
    const coversSSH = coversAll || portsInclude(form.port, sshPort.value);
    const coversPanel = coversAll || portsInclude(form.port, panelPort.value);
    if (coversAll || (coversSSH && coversPanel)) {
        return { mode: 'redline', message: i18n.global.t('firewall.redlineBlockBoth') };
    }
    if (coversSSH || coversPanel) {
        return { mode: 'warn', message: i18n.global.t('firewall.riskBlockSelf') };
    }
    return { mode: 'none', message: '' };
};

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
        if (form.objectType === 'port') {
            const ports =
                form.port.indexOf('-') !== -1 && !form.port.startsWith('-')
                    ? form.port.split('-')
                    : form.port.indexOf(',') !== -1 && !form.port.startsWith(',')
                      ? form.port.split(',')
                      : [form.port];
            for (const port of ports) {
                if (checkPort(port)) {
                    MsgError(i18n.global.t('firewall.portFormatError'));
                    return;
                }
            }
        }
        const risk = computeRisk();
        if (risk.mode === 'none') {
            doSubmit();
        } else {
            riskRef.value?.acceptParams({ mode: risk.mode, message: risk.message, detail: risk.detail });
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
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
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
