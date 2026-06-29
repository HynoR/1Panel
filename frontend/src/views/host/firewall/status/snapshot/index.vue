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
    // 无后端 preview 接口：用文案把后果讲清楚——恢复会用此快照覆盖当前 1Panel 链，
    // 当前未保存到快照的规则变更会被移除；恢复走提交-确认事务，若锁外 60 秒未确认会自动回退（设计稿 §3.5）。
    const label = row.tag ? `${row.name}（${row.tag}）` : row.name;
    ElMessageBox.confirm(
        `<div class="leading-6">
            <p>${i18n.global.t('firewall.snapshotRestoreTarget', [label])}</p>
            <p>${i18n.global.t('firewall.snapshotRestoreHelper')}</p>
        </div>`,
        i18n.global.t('commons.button.recover'),
        {
            confirmButtonText: i18n.global.t('commons.button.confirm'),
            cancelButtonText: i18n.global.t('commons.button.cancel'),
            dangerouslyUseHTMLString: true,
            type: 'warning',
        },
    ).then(async () => {
        await restoreFireSnapshot(row.name);
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        drawerVisible.value = false;
    });
};

defineExpose({
    acceptParams,
});
</script>
