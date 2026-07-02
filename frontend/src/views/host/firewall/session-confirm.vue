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
import { onMounted, onUnmounted } from 'vue';
import { Loading } from '@element-plus/icons-vue';
import { useFireSession } from '@/views/host/firewall/composables/useFireSession';

// 仅负责会话轮询与倒计时；状态与 confirm/revert 动作由 useFireSession 单例持有，
// overview 内联确认卡与全局横幅共用同一份，避免重复拉取与动作逻辑分叉。
const { session, remain, applying, loading, refresh, onConfirm, onRevert, onCountdownZero } = useFireSession();

let pollTimer: ReturnType<typeof setInterval> | null = null;
let tickTimer: ReturnType<typeof setInterval> | null = null;
let pollTick = 0;

onMounted(() => {
    refresh();
    // 自适应轮询：会话激活/应用中保持 3s，空闲退避到 12s，减少无谓请求。
    pollTimer = setInterval(() => {
        pollTick++;
        if (!session.value.active && !applying.value && pollTick % 4 !== 0) return;
        refresh();
    }, 3000);
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
});
</script>
