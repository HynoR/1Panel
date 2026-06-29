<template>
    <el-alert v-if="applying" :closable="false" type="info" class="firewall-confirm card-interval">
        <template #title>
            <div class="flex items-center gap-2">
                <el-icon class="is-loading"><Loading /></el-icon>
                <span class="font-bold">{{ $t('firewall.applying') }}</span>
            </div>
        </template>
    </el-alert>
    <el-alert v-else-if="session.active" :closable="false" type="warning" class="firewall-confirm card-interval">
        <template #title>
            <div class="flex w-full flex-col gap-2 md:flex-row md:items-center md:justify-between">
                <div>
                    <span class="font-bold">{{ $t('firewall.confirmTitle') }}</span>
                    <span class="ml-2">
                        {{ $t('firewall.confirmTip', { count: session.changes.length, seconds: remain }) }}
                    </span>
                </div>
                <div>
                    <el-button type="success" size="small" :loading="loading" @click="onConfirm">
                        {{ $t('firewall.confirmKeep') }}
                    </el-button>
                    <el-button type="danger" size="small" :loading="loading" @click="onRevert">
                        {{ $t('firewall.revertNow') }}
                    </el-button>
                </div>
            </div>
        </template>
        <ul v-if="session.changes.length" class="mt-2 list-disc pl-5 text-xs">
            <li v-for="(item, index) in session.changes" :key="index">{{ item.at }} — {{ item.summary }}</li>
        </ul>
    </el-alert>
</template>

<script lang="ts" setup>
import { onMounted, onUnmounted, ref } from 'vue';
import { Loading } from '@element-plus/icons-vue';
import { Host } from '@/api/interface/host';
import { confirmFireSession, loadFireSession, revertFireSession } from '@/api/modules/host';
import i18n from '@/lang';
import { MsgSuccess, MsgWarning } from '@/utils/message';

const session = ref<Host.FirewallSession>({ active: false, changes: [], remainSeconds: 0, since: '', snapshot: '' });
const remain = ref(0);
const loading = ref(false);
// 保存成功后立即进入的「应用中…」过渡态：禁用确认/撤销，约 2s 或拿到确认窗口为止。
const applying = ref(false);
let pollTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;
let applyTimer: ReturnType<typeof setTimeout> | null = null;

const refresh = async () => {
    try {
        const res = await loadFireSession();
        session.value = res.data;
        remain.value = res.data.remainSeconds;
    } catch (error) {
        session.value.active = false;
    }
    // 已拿到确认窗口，提前结束过渡态。
    if (applying.value && session.value.active) {
        applying.value = false;
        if (applyTimer) {
            clearTimeout(applyTimer);
            applyTimer = null;
        }
    }
};

// 由保存成功的调用方触发：先显示 spinner，再主动刷新拿确认窗口；约 2s 后兜底退出。
const enterApplying = () => {
    applying.value = true;
    refresh();
    if (applyTimer) clearTimeout(applyTimer);
    applyTimer = setTimeout(() => {
        applying.value = false;
        applyTimer = null;
        refresh();
    }, 2000);
};

// 倒计时归 0：后端会自动撤销，前端主动刷新并据结果提示。
const onCountdownZero = async () => {
    await refresh();
    if (!session.value.active) {
        MsgWarning(i18n.global.t('firewall.autoReverted'));
    }
};

const onConfirm = async () => {
    loading.value = true;
    try {
        await confirmFireSession();
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await refresh();
    } finally {
        loading.value = false;
    }
};

const onRevert = async () => {
    loading.value = true;
    try {
        await revertFireSession();
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await refresh();
    } finally {
        loading.value = false;
    }
};

onMounted(() => {
    refresh();
    pollTimer = setInterval(refresh, 3000);
    tickTimer = setInterval(() => {
        if (session.value.active && remain.value > 0) {
            remain.value--;
            if (remain.value === 0) {
                onCountdownZero();
            }
        }
    }, 1000);
});

onUnmounted(() => {
    if (pollTimer) clearInterval(pollTimer);
    if (tickTimer) clearInterval(tickTimer);
    if (applyTimer) clearTimeout(applyTimer);
});

defineExpose({
    enterApplying,
});
</script>
