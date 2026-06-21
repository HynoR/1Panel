<template>
    <DrawerPro v-model="drawerVisible" :header="$t('firewall.snapshot')" size="large">
        <el-alert class="mb-2" :closable="false" type="info" :title="$t('firewall.snapshotHelper')" />
        <el-table :data="data" v-loading="loading">
            <el-table-column :label="$t('commons.table.name')" prop="name" show-overflow-tooltip />
            <el-table-column :label="$t('firewall.snapshotTag')" prop="tag" />
            <el-table-column label="IPv6" width="80">
                <template #default="{ row }">
                    <el-tag v-if="row.hasV6" type="success" size="small">v6</el-tag>
                    <span v-else>-</span>
                </template>
            </el-table-column>
            <el-table-column :label="$t('commons.table.operate')" width="120">
                <template #default="{ row }">
                    <el-button link type="primary" @click="onRestore(row)">
                        {{ $t('commons.button.recover') }}
                    </el-button>
                </template>
            </el-table-column>
        </el-table>
    </DrawerPro>
</template>

<script lang="ts" setup>
import { ref } from 'vue';
import i18n from '@/lang';
import { Host } from '@/api/interface/host';
import { listFireSnapshot, restoreFireSnapshot } from '@/api/modules/host';
import { MsgSuccess } from '@/utils/message';
import { ElMessageBox } from 'element-plus';

const drawerVisible = ref(false);
const loading = ref(false);
const data = ref<Host.FirewallSnapshot[]>([]);

const acceptParams = (): void => {
    drawerVisible.value = true;
    search();
};

const search = async () => {
    loading.value = true;
    try {
        const res = await listFireSnapshot();
        data.value = res.data || [];
    } finally {
        loading.value = false;
    }
};

const onRestore = (row: Host.FirewallSnapshot) => {
    // 恢复走提交-确认事务：恢复后若锁外，60 秒未确认会自动回到恢复前（设计稿 §3.5）。
    ElMessageBox.confirm(i18n.global.t('firewall.snapshotRestoreHelper'), i18n.global.t('commons.button.recover'), {
        confirmButtonText: i18n.global.t('commons.button.confirm'),
        cancelButtonText: i18n.global.t('commons.button.cancel'),
        type: 'warning',
    }).then(async () => {
        await restoreFireSnapshot(row.name);
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        drawerVisible.value = false;
    });
};

defineExpose({
    acceptParams,
});
</script>
