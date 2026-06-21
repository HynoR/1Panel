<template>
    <el-alert v-if="session.active" :closable="false" type="warning" class="firewall-confirm card-interval">
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
import { Host } from '@/api/interface/host';
import { confirmFireSession, loadFireSession, revertFireSession } from '@/api/modules/host';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';

const session = ref<Host.FirewallSession>({ active: false, changes: [], remainSeconds: 0, since: '', snapshot: '' });
const remain = ref(0);
const loading = ref(false);
let pollTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;

const refresh = async () => {
    try {
        const res = await loadFireSession();
        session.value = res.data;
        remain.value = res.data.remainSeconds;
    } catch (error) {
        session.value.active = false;
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
        }
    }, 1000);
});

onUnmounted(() => {
    if (pollTimer) clearInterval(pollTimer);
    if (tickTimer) clearInterval(tickTimer);
});
</script>
