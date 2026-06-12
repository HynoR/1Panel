<template>
    <div>
        <RouterButton :buttons="visibleButtons" />
        <LayoutContent>
            <router-view></router-view>
        </LayoutContent>
    </div>
</template>

<script lang="ts" setup>
import i18n from '@/lang';
import { computed, onMounted, ref } from 'vue';
import { listFirewallProviders } from '@/api/modules/host';

// The "iptables advanced" tab exposes controls that only make sense under
// the iptables backend (chain bind / unbind, raw filter rules). Probe the
// active provider on mount and drop the tab when the host is running with
// firewalld / ufw / nftables so operators are not funnelled into a page
// that would only error out.
const currentProvider = ref('');

const buttons = [
    {
        label: i18n.global.t('firewall.portRule', 2),
        path: '/hosts/firewall/port',
    },
    {
        label: i18n.global.t('firewall.forwardRule', 2),
        path: '/hosts/firewall/forward',
    },
    {
        label: i18n.global.t('firewall.ipRule', 2),
        path: '/hosts/firewall/ip',
    },
    {
        label: 'iptables ' + i18n.global.t('firewall.advancedControl'),
        path: '/hosts/firewall/advance',
        requires: 'iptables',
    } as any,
];

const visibleButtons = computed(() =>
    buttons.filter((b: any) => !b.requires || b.requires === currentProvider.value),
);

onMounted(async () => {
    try {
        const res = await listFirewallProviders();
        currentProvider.value = res.data?.current || '';
    } catch {
        currentProvider.value = '';
    }
});
</script>