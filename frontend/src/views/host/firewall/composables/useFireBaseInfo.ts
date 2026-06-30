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

// MODULE-LEVEL shared singleton state: /firewall/base is fetched once and shared by the
// tab bar, overview and every list page — replaces the per-page FireStatus v-model dance.
const baseInfo = ref<Host.FirewallBase>(defaultBase());
const existFlag = ref(true);
// isInit is tab-dependent; keep it keyed per tab so concurrent loadBaseInfo calls
// (tab bar uses 'base', the active page uses its own tab) cannot corrupt each other.
const activeTab = ref<FireTab>('base');
const initMap = reactive<Record<string, boolean>>({});

const hasAdvancedRules = ref(false);
const dockerAvailable = ref(false);
const dockerRules = ref<Host.FirewallDockerRule[]>([]);

const isExist = computed(() => existFlag.value);
const isActive = computed(() => baseInfo.value.isActive);
// isReady 跟随最后一次 loadBaseInfo 设置的 activeTab：会话确认等全局刷新也用 'base'，
// 概览页可见时与 base 一致，故现状可用。多 tab keep-alive 并发加载时其它 tab 会改写 activeTab，
// 因此提供 isReadyFor(tab) 让调用方按自身 tab 钉住就绪态，不被后台 tab 的加载覆写。
const isReady = computed(() => existFlag.value && !!initMap[activeTab.value]);
const isReadyFor = (tab: FireTab) => computed(() => existFlag.value && !!initMap[tab]);
const capabilities = computed(() => baseInfo.value.capabilities);
const mode = computed(() => baseInfo.value.mode);
const name = computed(() => baseInfo.value.name);
const version = computed(() => baseInfo.value.version);
const pingStatus = computed(() => baseInfo.value.pingStatus);
const conflict = computed(() => baseInfo.value.conflict);
const strictMode = computed(() => baseInfo.value.strictMode);
const bootDegraded = computed(() => {
    const s = baseInfo.value.bootStatus || '';
    return s.startsWith('degraded') || s.startsWith('failed');
});

const loadBaseInfo = async (tab: FireTab = 'base'): Promise<void> => {
    activeTab.value = tab;
    try {
        const res = await loadFireBaseInfo(tab);
        baseInfo.value = res.data;
        existFlag.value = res.data.isExist;
        initMap[tab] = res.data.isInit;
    } catch {
        existFlag.value = false;
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
    baseInfo.value = defaultBase();
    existFlag.value = true;
    activeTab.value = 'base';
    Object.keys(initMap).forEach((k) => delete initMap[k]);
    hasAdvancedRules.value = false;
    dockerAvailable.value = false;
    dockerRules.value = [];
};

export function useFireBaseInfo() {
    return {
        baseInfo,
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
