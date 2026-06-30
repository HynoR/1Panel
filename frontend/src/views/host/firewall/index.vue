<template>
    <div>
        <RouterButton :buttons="buttons" />
        <SessionConfirm />
        <LayoutContent>
            <router-view></router-view>
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import i18n from '@/lang';
import SessionConfirm from '@/views/host/firewall/session-confirm.vue';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';
import { computed, onMounted } from 'vue';

const { capabilities, hasAdvancedRules, loadBaseInfo, probeAdvancedRules } = useFireBaseInfo('base');

const buttons = computed(() => {
    const list = [
        {
            label: i18n.global.t('firewall.overview'),
            path: '/hosts/firewall/overview',
        },
        {
            label: i18n.global.t('firewall.inboundRule', 2),
            path: '/hosts/firewall/inbound',
        },
        {
            label: i18n.global.t('firewall.forwardRule', 2),
            path: '/hosts/firewall/forward',
        },
    ];
    if (capabilities.value.filter && hasAdvancedRules.value) {
        list.push({
            label: 'iptables ' + i18n.global.t('firewall.advancedControl'),
            path: '/hosts/firewall/advance',
        });
    }
    return list;
});

onMounted(() => {
    loadBaseInfo('base');
    probeAdvancedRules();
});
</script>
