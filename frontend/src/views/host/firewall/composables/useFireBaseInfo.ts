import { computed, reactive, ref } from 'vue';
import { Host } from '@/api/interface/host';
import { loadFireBaseInfo, loadFireDockerStatus, searchFilterRules } from '@/api/modules/host';

type FireTab = 'base' | 'forward' | 'advance';

const defaultBase = (): Host.FirewallBase => ({
    isActive: false,
    isExist: true,
    isInit: false,
    isBind: false,
    name: '',
    mode: '',
    version: '',
    pingStatus: '',
    capabilities: {
        rules: false,
        forward: false,
        forwardImpl: '',
        filter: false,
        baseline: false,
        snapshot: '',
        ipv6Rules: false,
        defaultDrop: false,
    },
    conflict: { hasConflict: false, providers: [], message: '' },
    bootStatus: '',
    consistent: true,
    strictMode: false,
});

// Module-level cache, keyed by tab. The backend returns tab-dependent init/bind state,
// so every visible firewall page pins reads to its own tab instead of racing on one object.
const baseInfoMap = reactive<Record<FireTab, Host.FirewallBase>>({
    base: defaultBase(),
    forward: defaultBase(),
    advance: defaultBase(),
});
const existFlag = ref(true);
const activeTab = ref<FireTab>('base');

const hasAdvancedRules = ref(false);
const dockerAvailable = ref(false);
const dockerRules = ref<Host.FirewallDockerRule[]>([]);

const loadBaseInfo = async (tab: FireTab = 'base'): Promise<void> => {
    activeTab.value = tab;
    try {
        const res = await loadFireBaseInfo(tab);
        baseInfoMap[tab] = res.data;
        existFlag.value = res.data.isExist;
    } catch {
        existFlag.value = false;
        baseInfoMap[tab] = { ...defaultBase(), isExist: false };
    }
};

const probeAdvancedRules = async (): Promise<void> => {
    try {
        const results = await Promise.all(
            ['1PANEL_INPUT', '1PANEL_OUTPUT'].map((chain) =>
                searchFilterRules({ type: chain, info: '', page: 1, pageSize: 1 }),
            ),
        );
        hasAdvancedRules.value = results.some((res) => (res.data?.total || 0) > 0);
    } catch {
        hasAdvancedRules.value = false;
    }
};

const loadDockerStatus = async (): Promise<void> => {
    try {
        const res = await loadFireDockerStatus();
        dockerAvailable.value = res.data.available;
        dockerRules.value = res.data.rules || [];
    } catch {
        dockerAvailable.value = false;
        dockerRules.value = [];
    }
};

const reset = (): void => {
    baseInfoMap.base = defaultBase();
    baseInfoMap.forward = defaultBase();
    baseInfoMap.advance = defaultBase();
    existFlag.value = true;
    activeTab.value = 'base';
    hasAdvancedRules.value = false;
    dockerAvailable.value = false;
    dockerRules.value = [];
};

export function useFireBaseInfo(tab?: FireTab) {
    const currentBaseInfo = computed(() => baseInfoMap[tab || activeTab.value] || baseInfoMap.base);
    const isExist = computed(() => existFlag.value);
    const isActive = computed(() => currentBaseInfo.value.isActive);
    const isReady = computed(() => existFlag.value && !!currentBaseInfo.value.isInit);
    const isReadyFor = (target: FireTab) => computed(() => existFlag.value && !!baseInfoMap[target].isInit);
    const capabilities = computed(() => currentBaseInfo.value.capabilities);
    const mode = computed(() => currentBaseInfo.value.mode);
    const name = computed(() => currentBaseInfo.value.name);
    const version = computed(() => currentBaseInfo.value.version);
    const pingStatus = computed(() => currentBaseInfo.value.pingStatus);
    const conflict = computed(() => currentBaseInfo.value.conflict);
    const strictMode = computed(() => currentBaseInfo.value.strictMode);
    const bootDegraded = computed(() => {
        const s = currentBaseInfo.value.bootStatus || '';
        return s.startsWith('degraded') || s.startsWith('failed');
    });

    return {
        baseInfo: currentBaseInfo,
        loadBaseInfo,
        isExist,
        isActive,
        isReady,
        isReadyFor,
        capabilities,
        mode,
        name,
        version,
        pingStatus,
        conflict,
        strictMode,
        bootDegraded,
        hasAdvancedRules,
        probeAdvancedRules,
        dockerAvailable,
        dockerRules,
        loadDockerStatus,
        reset,
    };
}
