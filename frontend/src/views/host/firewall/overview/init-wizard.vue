<template>
    <DrawerPro v-model="visible" :header="$t('commons.button.init')" size="small" @close="visible = false">
        <template #content>
            <el-steps :active="active" align-center finish-status="success" class="mb-5">
                <el-step :title="$t('firewall.wizardStep1')" />
                <el-step :title="$t('firewall.wizardStep2')" />
                <el-step :title="$t('firewall.wizardStep3')" />
            </el-steps>

            <div v-if="active === 0">
                <el-alert type="info" :closable="false" :title="$t('firewall.portWhiteListAlter')" />
                <el-descriptions class="mt-4" :column="1" border>
                    <el-descriptions-item v-for="item in rescuePorts" :key="item.name" :label="item.name">
                        <span>{{ item.port }}</span>
                        <el-tag class="ml-2" type="success" size="small">{{ $t('firewall.rescueAllowed') }}</el-tag>
                    </el-descriptions-item>
                </el-descriptions>
            </div>

            <div v-else-if="active === 1">
                <el-form label-position="top">
                    <el-form-item :label="$t('firewall.defaultPolicy')">
                        <el-radio-group v-model="policy">
                            <el-radio value="loose">{{ $t('firewall.policyLoose') }}</el-radio>
                            <el-radio value="strict" :disabled="!capabilities.defaultDrop">
                                {{ $t('firewall.policyStrict') }}
                            </el-radio>
                        </el-radio-group>
                    </el-form-item>
                </el-form>
            </div>

            <div v-else>
                <el-result v-if="checkPassed === true" icon="success" :title="$t('commons.msg.operationSuccess')" />
                <el-result v-else-if="checkPassed === false" icon="warning" :title="$t('firewall.goOverviewInit')" />
                <el-alert v-else type="info" :closable="false" :title="$t('firewall.applying')" />
            </div>
        </template>
        <template #footer>
            <el-button @click="visible = false">{{ $t('commons.button.cancel') }}</el-button>
            <el-button v-if="active > 0 && checkPassed === null" @click="active--">
                {{ $t('commons.button.prev') }}
            </el-button>
            <el-button v-if="active < 2" type="primary" @click="active++">
                {{ $t('commons.button.next') }}
            </el-button>
            <el-button v-if="active === 2 && checkPassed === null" type="primary" :loading="loading" @click="onApply">
                {{ $t('commons.button.confirm') }}
            </el-button>
            <el-button v-if="checkPassed === true" type="primary" @click="onDone">
                {{ $t('commons.button.confirm') }}
            </el-button>
        </template>
    </DrawerPro>
</template>

<script lang="ts" setup>
import { ref } from 'vue';
import i18n from '@/lang';
import { operateFilterChain } from '@/api/modules/host';
import { MsgSuccess } from '@/utils/message';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';

type WizardTab = 'base' | 'forward' | 'advance';

const emit = defineEmits(['done']);

const { capabilities, loadBaseInfo, isReady } = useFireBaseInfo();

const visible = ref(false);
const loading = ref(false);
const active = ref(0);
const policy = ref('loose');
const checkPassed = ref<boolean | null>(null);
const tab = ref<WizardTab>('base');

const rescuePorts = ref<{ name: string; port: string }[]>([]);

// 显式分支映射 tab -> chain / operate，杜绝原 status/index.vue switch 缺 break 的穿透 bug。
const chainOf = (t: WizardTab): { name: string; op: string } => {
    if (t === 'forward') {
        return { name: '1PANEL_FORWARD', op: 'init-forward' };
    }
    if (t === 'advance') {
        return { name: '1PANEL_INPUT', op: 'init-advance' };
    }
    return { name: '1PANEL_BASIC', op: 'init-base' };
};

const acceptParams = (params?: { tab?: WizardTab; rescuePorts?: { name: string; port: string }[] }): void => {
    tab.value = params?.tab || 'base';
    rescuePorts.value = params?.rescuePorts || [];
    active.value = 0;
    policy.value = 'loose';
    checkPassed.value = null;
    visible.value = true;
};

const onApply = async () => {
    const { name, op } = chainOf(tab.value);
    loading.value = true;
    try {
        await operateFilterChain(name, op);
        // 基础初始化后，按所选默认策略决定是否开启白名单（严格）模式（向 AFTER 链注入 DROP）。
        if (tab.value === 'base' && policy.value === 'strict') {
            await operateFilterChain('1PANEL_INPUT', 'enable-strict');
        }
        await loadBaseInfo(tab.value);
        checkPassed.value = isReady.value;
        if (checkPassed.value) {
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        }
    } catch {
        checkPassed.value = false;
    } finally {
        loading.value = false;
    }
};

const onDone = () => {
    visible.value = false;
    emit('done');
};

defineExpose({ acceptParams });
</script>
