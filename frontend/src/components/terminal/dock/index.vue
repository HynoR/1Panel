<template>
    <!-- Right edge handle: open a terminal from any page without leaving it. Hidden on the terminal page itself. -->
    <div v-if="!onTerminalPage" class="terminal-dock-handle" @click="show">
        <el-badge :value="store.entries.length" :hidden="store.entries.length === 0" type="primary">
            <svg-icon iconName="p-terminal2" class="terminal-dock-icon" />
        </el-badge>
        <span class="terminal-dock-label">{{ $t('menu.terminal') }}</span>
    </div>

    <el-dialog
        v-model="open"
        :title="$t('menu.terminal')"
        width="70%"
        draggable
        :close-on-click-modal="false"
        :modal="false"
        class="terminal-dock-dialog"
        @closed="park"
    >
        <div class="flex items-center gap-1 mb-1">
            <el-tabs v-model="active" type="card" closable class="flex-1 terminal-dock-tabs" @tab-remove="store.remove">
                <el-tab-pane v-for="item in store.entries" :key="item.key" :name="item.key">
                    <template #label>
                        <span :style="{ color: item.status === 'online' ? '#69db7c' : '#d9480f' }">●</span>
                        &nbsp;{{ item.title }}
                    </template>
                </el-tab-pane>
            </el-tabs>
            <el-tooltip :content="$t('terminal.localhost')" placement="top">
                <el-button icon="Plus" circle size="small" @click="newLocal" />
            </el-tooltip>
        </div>
        <div v-if="store.entries.length === 0" class="terminal-dock-empty">{{ $t('terminal.emptyTerminal') }}</div>
        <!-- one slot per entry; the active one claims its Terminal from the host, the rest stay parked -->
        <div
            v-for="item in store.entries"
            v-show="item.key === active"
            :key="item.key"
            class="terminal-dock-slot"
            :ref="(el: any) => onSlot(item.key, el)"
            @click="store.instances[item.key]?.refit()"
        ></div>
    </el-dialog>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import i18n from '@/lang';
import { TerminalSessionStore } from '@/store';
import { testLocalConn } from '@/api/modules/terminal';
import { MsgError } from '@/utils/message';

const store = TerminalSessionStore();
const route = useRoute();
const onTerminalPage = computed(() => route.path.startsWith('/terminal'));

const open = ref(false);
const active = ref('');
let timer: ReturnType<typeof setInterval> | null = null;

const show = async () => {
    if (!store.find(active.value)) active.value = store.entries[0]?.key || '';
    open.value = true;
    await nextTick();
    claim();
    store.sync();
    timer = setInterval(store.sync, 5000);
};

// park releases every slot so the Terminals go back to the off-screen host.
const park = () => {
    if (timer) clearInterval(timer);
    timer = null;
    claim();
};

// The dialog keeps its content mounted while hidden, so slots are claimed explicitly:
// only the visible pane owns its Terminal (claiming a hidden one would fit it to 0x0).
const slotEls: Record<string, HTMLElement> = {};
const onSlot = (key: string, el: HTMLElement | null) => {
    if (el) slotEls[key] = el;
    else delete slotEls[key];
};
// Slots not ours (the terminal page's) are left alone.
const claim = () => {
    for (const item of store.entries) {
        if (open.value && item.key === active.value) {
            store.setSlot(item.key, slotEls[item.key] || null);
        } else if (store.slots[item.key] && store.slots[item.key] === slotEls[item.key]) {
            store.setSlot(item.key, null);
        }
    }
};
watch(active, () => nextTick(claim));
watch(
    () => store.entries.length,
    () => {
        if (!store.find(active.value)) active.value = store.entries[0]?.key || '';
    },
);

const newLocal = async () => {
    const res = await testLocalConn();
    if (!res.data) {
        MsgError(i18n.global.t('terminal.connLocalErr'));
        return;
    }
    active.value = await store.open({ title: i18n.global.t('terminal.localhost'), wsID: 0 });
};

// the terminal page claims the slots itself; give ours up when navigating there
watch(onTerminalPage, (v) => {
    if (v) open.value = false;
});
</script>

<style scoped lang="scss">
.terminal-dock-handle {
    position: fixed;
    right: 0;
    bottom: 96px;
    z-index: 100;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding: 10px 6px;
    border-radius: 8px 0 0 8px;
    background: var(--el-bg-color);
    box-shadow: var(--el-box-shadow-light);
    color: var(--el-color-primary);
    cursor: pointer;
    user-select: none;
}
.terminal-dock-icon {
    width: 20px;
    height: 20px;
}
.terminal-dock-label {
    writing-mode: vertical-rl;
    font-size: 12px;
    letter-spacing: 2px;
}
.terminal-dock-slot {
    height: 60vh;
    background-color: var(--panel-logs-bg-color);
}
.terminal-dock-empty {
    height: 60vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--el-text-color-secondary);
}
</style>
