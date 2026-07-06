<template>
    <div>
        <RouterButton :buttons="buttons" />
        <SessionConfirm />
        <!-- 全局横幅：ufw+firewalld 冲突 / 开机降级（含隔离规则入口），各子页可见 -->
        <el-alert v-if="topBanner" :type="topBanner.type" :closable="false" show-icon class="card-interval">
            <template #title>
                <div class="flex flex-wrap items-center gap-2">
                    <span>{{ topBanner.title }}</span>
                    <el-link
                        v-if="showQuarantineEntry"
                        type="primary"
                        :underline="false"
                        @click.stop="onOpenQuarantine"
                    >
                        {{ $t('firewall.quarantineView') }}
                    </el-link>
                </div>
            </template>
        </el-alert>
        <LayoutContent>
            <router-view></router-view>
        </LayoutContent>

        <el-drawer v-model="quarantineDrawerVisible" :title="$t('firewall.quarantineTitle')" size="50%">
            <div class="flex h-full flex-col gap-3">
                <el-alert :closable="false" type="warning" :title="$t('firewall.quarantineHelper')" />
                <el-empty v-if="!quarantineRules.length" :description="$t('firewall.quarantineEmpty')" />
                <el-scrollbar v-else>
                    <div class="flex flex-col gap-2">
                        <el-text v-for="(rule, index) in quarantineRules" :key="index" tag="pre">
                            {{ rule }}
                        </el-text>
                    </div>
                </el-scrollbar>
                <div class="mt-auto flex justify-end">
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
        </el-drawer>
    </div>
</template>

<script lang="ts" setup>
import i18n from '@/lang';
import SessionConfirm from '@/views/host/firewall/session-confirm.vue';
import { cleanFireQuarantine, listFireQuarantine } from '@/api/modules/host';
import { MsgSuccess } from '@/utils/message';
import { ElMessageBox } from 'element-plus';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { computed, onMounted, ref } from 'vue';

const {
    baseInfo,
    mode,
    conflict,
    bootDegraded,
    isActive,
    isReady,
    hasAdvancedRules,
    loadBaseInfo,
    probeAdvancedRules,
} = useFireBaseInfo('base');

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
const showQuarantineEntry = computed(
    () => bootDegraded.value && bootQuarantined.value && isReady.value && isActive.value,
);

const quarantineDrawerVisible = ref(false);
const quarantineLoading = ref(false);
const quarantineRules = ref<string[]>([]);

const onOpenQuarantine = async () => {
    quarantineDrawerVisible.value = true;
    quarantineLoading.value = true;
    try {
        const res = await listFireQuarantine();
        quarantineRules.value = res.data || [];
    } finally {
        quarantineLoading.value = false;
    }
};

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
        await cleanFireQuarantine();
        quarantineRules.value = [];
        quarantineDrawerVisible.value = false;
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
