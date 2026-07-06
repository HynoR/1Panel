<template>
    <div>
        <RouterButton :buttons="buttons" />
        <SessionConfirm />
        <!-- 全局横幅：ufw+firewalld 冲突 / 开机降级（含隔离规则内联展示），各子页可见 -->
        <el-alert v-if="topBanner" :type="topBanner.type" :closable="false" show-icon class="card-interval">
            <template #title>
                <span>{{ topBanner.title }}</span>
            </template>
            <div v-if="bootQuarantined" class="mt-2 flex flex-col gap-2">
                <span>{{ $t('firewall.quarantineHelper') }}</span>
                <el-text v-for="(rule, index) in quarantineRules" :key="index" tag="pre">
                    {{ rule }}
                </el-text>
                <div>
                    <el-button
                        v-permission
                        v-node-admin
                        type="danger"
                        :loading="quarantineLoading"
                        @click="onCleanQuarantine"
                    >
                        {{ $t('firewall.quarantineClean') }}
                    </el-button>
                </div>
            </div>
        </el-alert>
        <LayoutContent>
            <router-view></router-view>
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import i18n from '@/lang';
import SessionConfirm from '@/views/host/firewall/session-confirm.vue';
import { operateFire } from '@/api/modules/host';
import { MsgSuccess } from '@/utils/message';
import { ElMessageBox } from 'element-plus';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { computed, onMounted, ref } from 'vue';

const { baseInfo, mode, conflict, bootDegraded, hasAdvancedRules, loadBaseInfo, probeAdvancedRules } =
    useFireBaseInfo('base');

const buttons = computed(() => {
    const list = [
        {
            label: i18n.global.t('firewall.inboundRule', 2),
            path: '/hosts/firewall/inbound',
        },
        {
            label: i18n.global.t('firewall.forwardRule', 2),
            path: '/hosts/firewall/forward',
        },
    ];
    if (mode.value === 'managed' && hasAdvancedRules.value) {
        list.push({
            label: 'iptables ' + i18n.global.t('firewall.advancedControl'),
            path: '/hosts/firewall/advance',
        });
    }
    return list;
});

// 未初始化/未启动由各子页与状态栏承载，这里只提示需要全局关注的异常：开机降级 > 冲突。
const topBanner = computed<{ type: 'warning' | 'error'; title: string } | null>(() => {
    if (bootDegraded.value) {
        return { type: 'warning', title: i18n.global.t('firewall.bootDegraded', [baseInfo.value.bootStatus]) };
    }
    if (conflict.value?.hasConflict) {
        return { type: 'error', title: conflict.value.message || i18n.global.t('firewall.conflictHelper') };
    }
    return null;
});

const bootQuarantined = computed(() => (baseInfo.value.bootStatus || '').startsWith('degraded:quarantined'));
const quarantineRules = computed(() => baseInfo.value.quarantine || []);
const quarantineLoading = ref(false);

const onCleanQuarantine = async () => {
    try {
        await ElMessageBox.confirm(
            i18n.global.t('firewall.quarantineCleanConfirm'),
            i18n.global.t('firewall.quarantineClean'),
            {
                confirmButtonText: i18n.global.t('commons.button.confirm'),
                cancelButtonText: i18n.global.t('commons.button.cancel'),
                type: 'warning',
            },
        );
    } catch {
        return;
    }
    quarantineLoading.value = true;
    try {
        await operateFire('quarantineClean', false);
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await loadBaseInfo('base');
    } finally {
        quarantineLoading.value = false;
    }
};

onMounted(() => {
    loadBaseInfo('base');
    probeAdvancedRules();
});
</script>
