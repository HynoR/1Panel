<template>
    <el-dialog
        v-model="visible"
        :title="data.mode === 'redline' ? $t('firewall.redlineTitle') : $t('firewall.riskTitle')"
        width="500px"
        :close-on-click-modal="false"
    >
        <el-alert
            v-if="data.mode === 'redline'"
            :title="$t('firewall.redlineTitle')"
            type="error"
            :closable="false"
            show-icon
        >
            <div>{{ data.message }}</div>
        </el-alert>
        <template v-else>
            <el-alert :title="$t('firewall.riskTitle')" type="warning" :closable="false" show-icon>
                <div>{{ data.message }}</div>
            </el-alert>
            <el-checkbox class="mt-3" v-model="ack">{{ $t('firewall.riskAck') }}</el-checkbox>
        </template>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="visible = false">{{ $t('commons.button.cancel') }}</el-button>
                <el-button v-if="data.mode === 'warn'" type="warning" :disabled="!ack" @click="onConfirm">
                    {{ $t('firewall.riskProceed') }}
                </el-button>
            </span>
        </template>
    </el-dialog>
</template>

<script lang="ts" setup>
import { ref } from 'vue';

interface RiskParams {
    mode: 'warn' | 'redline';
    message: string;
}

const visible = ref(false);
const ack = ref(false);
const data = ref<RiskParams>({ mode: 'warn', message: '' });

const emit = defineEmits<{ (e: 'confirm'): void }>();

const acceptParams = (params: RiskParams): void => {
    data.value = params;
    ack.value = false;
    visible.value = true;
};

const onConfirm = () => {
    visible.value = false;
    emit('confirm');
};

defineExpose({
    acceptParams,
});
</script>
