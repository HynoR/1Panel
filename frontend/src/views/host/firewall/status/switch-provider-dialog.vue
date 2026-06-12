<template>
    <el-dialog
        v-model="open"
        :title="$t('firewall.switchProviderTitle')"
        width="560px"
        :close-on-click-modal="false"
    >
        <div v-loading="loading">
            <el-alert v-if="nativeInCharge" type="warning" :closable="false" class="mb-3">
                {{ $t('firewall.nativeFirewallInCharge', [result.current]) }}
            </el-alert>
            <el-alert v-else-if="!hasChoice" type="info" :closable="false" class="mb-3">
                {{ $t('firewall.noProviderChoice') }}
            </el-alert>
            <el-alert v-else type="info" :closable="false" class="mb-3">
                {{ $t('firewall.switchProviderHelper') }}
            </el-alert>

            <el-table :data="result.providers" size="small" :show-header="true">
                <el-table-column prop="name" :label="$t('firewall.providerName')" width="140">
                    <template #default="{ row }">
                        <span class="font-semibold">{{ row.name }}</span>
                        <el-tag v-if="row.isCurrent" type="success" size="small" class="ml-2">
                            {{ $t('firewall.providerCurrent') }}
                        </el-tag>
                    </template>
                </el-table-column>
                <el-table-column :label="$t('firewall.providerStatus')">
                    <template #default="{ row }">
                        <el-tag v-if="!row.available" type="info" size="small">
                            {{ $t('firewall.providerNotAvailable') }}
                        </el-tag>
                        <template v-else>
                            <el-tag type="success" size="small">{{ $t('firewall.providerAvailable') }}</el-tag>
                            <el-tag
                                v-if="row.isInitialized"
                                type="warning"
                                size="small"
                                class="ml-2"
                            >
                                {{ $t('firewall.providerInitialized') }}
                            </el-tag>
                        </template>
                    </template>
                </el-table-column>
                <el-table-column :label="$t('firewall.providerAction')" width="110">
                    <template #default="{ row }">
                        <el-button
                            v-if="canSwitchTo(row)"
                            type="primary"
                            link
                            size="small"
                            @click="selectTarget(row)"
                        >
                            {{ $t('firewall.switchTo') }}
                        </el-button>
                    </template>
                </el-table-column>
            </el-table>

            <el-alert v-if="target" type="warning" :closable="false" class="mt-4">
                <template #default>
                    <div class="flex flex-col gap-2">
                        <span>
                            {{
                                $t('firewall.switchConfirmTitle', [
                                    $t('firewall.providerNameValue.' + result.current),
                                    $t('firewall.providerNameValue.' + target),
                                ])
                            }}
                        </span>
                        <span v-if="needsForce">
                            {{ $t('firewall.switchForceHint') }}
                        </span>
                        <el-checkbox v-if="needsForce" v-model="force">
                            {{ $t('firewall.switchForceAccept') }}
                        </el-checkbox>
                    </div>
                </template>
            </el-alert>
        </div>

        <template #footer>
            <span>
                <el-button @click="open = false">{{ $t('commons.button.cancel') }}</el-button>
                <el-button
                    type="primary"
                    :disabled="!canSubmit"
                    :loading="submitting"
                    @click="onSubmit"
                >
                    {{ $t('commons.button.confirm') }}
                </el-button>
            </span>
        </template>
    </el-dialog>
</template>

<script lang="ts" setup>
import { computed, ref } from 'vue';
import { Host } from '@/api/interface/host';
import { listFirewallProviders, switchFirewallProvider } from '@/api/modules/host';
import i18n from '@/lang';
import { MsgSuccess, MsgError } from '@/utils/message';

const emit = defineEmits<{ (e: 'refresh'): void }>();

const open = ref(false);
const loading = ref(false);
const submitting = ref(false);
const force = ref(false);
const target = ref('');
const result = ref<Host.FirewallProvidersResult>({ providers: [], current: '', preferred: '' });

const nativeInCharge = computed(() => result.value.current === 'ufw' || result.value.current === 'firewalld');

const hasChoice = computed(() => {
    const managed = result.value.providers.filter(
        (p) => (p.name === 'iptables' || p.name === 'nftables') && p.available,
    );
    return managed.length >= 2;
});

const needsForce = computed(() => {
    if (!target.value) return false;
    const current = result.value.providers.find((p) => p.isCurrent);
    return current?.isInitialized ?? false;
});

const canSubmit = computed(() => {
    if (!target.value) return false;
    if (needsForce.value && !force.value) return false;
    return true;
});

const acceptParams = async () => {
    open.value = true;
    target.value = '';
    force.value = false;
    await load();
};

const load = async () => {
    loading.value = true;
    try {
        const res = await listFirewallProviders();
        result.value = res.data;
    } finally {
        loading.value = false;
    }
};

const canSwitchTo = (p: Host.FirewallProvider): boolean => {
    if (nativeInCharge.value) return false;
    if (!p.available) return false;
    if (p.isCurrent) return false;
    if (p.name !== 'iptables' && p.name !== 'nftables') return false;
    return true;
};

const selectTarget = (p: Host.FirewallProvider) => {
    target.value = p.name;
    force.value = false;
};

const onSubmit = async () => {
    if (!canSubmit.value) return;
    submitting.value = true;
    try {
        await switchFirewallProvider(target.value, needsForce.value && force.value);
        MsgSuccess(i18n.global.t('firewall.switchProviderSuccess'));
        open.value = false;
        emit('refresh');
    } catch (err: any) {
        MsgError(
            i18n.global.t('firewall.switchProviderBlocked', [
                err?.response?.data?.message || err?.message || 'unknown error',
            ]),
        );
    } finally {
        submitting.value = false;
    }
};

defineExpose({ acceptParams });
</script>
