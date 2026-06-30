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
import { MsgError, MsgSuccess } from '@/utils/message';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';

const emit = defineEmits(['done']);

const { capabilities, loadBaseInfo, isReady } = useFireBaseInfo();

const visible = ref(false);
const loading = ref(false);
const active = ref(0);
const policy = ref('loose');
const checkPassed = ref<boolean | null>(null);

const rescuePorts = ref<{ name: string; port: string }[]>([]);

// 初始化向导只服务于 base（保底链）。forward/advance 的初始化入口在各自列表页内，
// 原 wizard 的 forward/advance 分支不可达（onOpenWizard 仅以 base 唤起），已移除。
const acceptParams = (params?: { rescuePorts?: { name: string; port: string }[] }): void => {
    rescuePorts.value = params?.rescuePorts || [];
    active.value = 0;
    policy.value = 'loose';
    checkPassed.value = null;
    visible.value = true;
};

const onApply = async () => {
    loading.value = true;
    try {
        await operateFilterChain('1PANEL_BASIC', 'init-base');
        // 基础初始化后，按所选默认策略决定是否开启白名单（严格）模式（向 AFTER 链注入 DROP）。
        if (policy.value === 'strict') {
            await operateFilterChain('1PANEL_INPUT', 'enable-strict');
        }
        await loadBaseInfo('base');
        checkPassed.value = isReady.value;
        if (checkPassed.value) {
            MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        }
    } catch (error: any) {
        // 业务错误已被全局 axios 拦截器弹 MsgError；此处补一条兜底（网络错误等无 message 时用通用文案），
        // 避免 apply 失败时 wizard 仅显示"未就绪"而无任何错误详情。
        checkPassed.value = false;
        MsgError(String(error?.message || i18n.global.t('commons.res.commonError')));
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
