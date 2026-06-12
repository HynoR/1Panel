<template>
    <el-drawer
        v-model="open"
        :title="$t('firewall.snapshotsTitle')"
        size="640px"
        :close-on-click-modal="false"
    >
        <div v-loading="loading">
            <el-alert type="info" :closable="false" class="mb-4">
                {{ $t('firewall.snapshotsHelper') }}
            </el-alert>

            <el-empty v-if="!snapshots.length" :description="$t('firewall.noSnapshots')" />

            <el-table v-else :data="snapshots" size="small">
                <el-table-column :label="$t('firewall.snapshotTag')">
                    <template #default="{ row }">
                        <div class="font-mono text-xs">{{ row.tag || '-' }}</div>
                        <div class="text-xs text-gray-400 truncate">{{ row.name }}</div>
                    </template>
                </el-table-column>
                <el-table-column
                    :label="$t('firewall.snapshotCreatedAt')"
                    width="170"
                    prop="createdAt"
                >
                    <template #default="{ row }">
                        <span>{{ formatTime(row.createdAt) }}</span>
                    </template>
                </el-table-column>
                <el-table-column :label="$t('firewall.snapshotSize')" width="110">
                    <template #default="{ row }">
                        <span class="text-xs">
                            v4 {{ formatSize(row.sizeV4) }}
                            <span v-if="row.sizeV6 > 0">/ v6 {{ formatSize(row.sizeV6) }}</span>
                        </span>
                    </template>
                </el-table-column>
                <el-table-column :label="$t('commons.table.operate')" width="100" fixed="right">
                    <template #default="{ row }">
                        <el-button
                            type="primary"
                            link
                            size="small"
                            @click="onRestore(row)"
                        >
                            {{ $t('firewall.restoreSnapshot') }}
                        </el-button>
                    </template>
                </el-table-column>
            </el-table>
        </div>

        <template #footer>
            <span>
                <el-button @click="open = false">{{ $t('commons.button.close') }}</el-button>
                <el-button @click="load" :loading="loading">
                    {{ $t('commons.button.refresh') }}
                </el-button>
            </span>
        </template>
    </el-drawer>
</template>

<script lang="ts" setup>
import { ref } from 'vue';
import { ElMessageBox } from 'element-plus';
import { Host } from '@/api/interface/host';
import { listFirewallSnapshots, restoreFirewallSnapshot } from '@/api/modules/host';
import i18n from '@/lang';
import { MsgSuccess } from '@/utils/message';
import { dateFormat } from '@/utils/date';

const emit = defineEmits<{ (e: 'refresh'): void }>();

const open = ref(false);
const loading = ref(false);
const snapshots = ref<Host.FirewallSnapshot[]>([]);

const acceptParams = async () => {
    open.value = true;
    await load();
};

const load = async () => {
    loading.value = true;
    try {
        const res = await listFirewallSnapshots();
        snapshots.value = (res.data || []) as Host.FirewallSnapshot[];
    } finally {
        loading.value = false;
    }
};

const onRestore = (row: Host.FirewallSnapshot) => {
    ElMessageBox.confirm(
        i18n.global.t('firewall.restoreSnapshotConfirm', [row.tag || row.name]),
        i18n.global.t('firewall.restoreSnapshot'),
        {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
            type: 'warning',
        },
    ).then(async () => {
        await restoreFirewallSnapshot(row.name);
        MsgSuccess(i18n.global.t('firewall.restoreSnapshotSuccess'));
        emit('refresh');
        await load();
    });
};

const formatTime = (iso: string): string => {
    if (!iso) return '-';
    try {
        return dateFormat('', '', new Date(iso));
    } catch {
        return iso;
    }
};

const formatSize = (bytes: number): string => {
    if (!bytes || bytes <= 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
};

defineExpose({ acceptParams });
</script>
