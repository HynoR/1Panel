<template>
    <div class="flow-bar flex flex-wrap items-center gap-2 py-2">
        <template v-for="(seg, idx) in segments" :key="seg.key">
            <el-icon v-if="idx > 0" class="text-gray-400"><ArrowRight /></el-icon>
            <el-tooltip :content="seg.tip" :disabled="!seg.tip" placement="top">
                <el-tag
                    :type="seg.type"
                    :effect="seg.active ? 'dark' : 'light'"
                    :class="seg.clickable ? 'cursor-pointer select-none' : 'select-none'"
                    @click="onSegClick(seg)"
                >
                    <span class="inline-flex items-center gap-1">
                        <el-icon v-if="seg.icon"><component :is="seg.icon" /></el-icon>
                        {{ seg.label }}
                        <span v-if="seg.count !== undefined">({{ seg.count }})</span>
                    </span>
                </el-tag>
            </el-tooltip>
        </template>
    </div>
</template>

<script lang="ts" setup>
import { computed } from 'vue';
import { ArrowRight, Lock } from '@element-plus/icons-vue';
import i18n from '@/lang';

const props = withDefaults(
    defineProps<{
        // capabilities.defaultDrop → 默认严格/宽松 段
        defaultDrop?: boolean;
        // '' | 'deny' | 'baseline' | 'allow' — 当前过滤高亮
        activeLevel?: string;
        // 可选的各层级规则数量徽标
        counts?: { deny: number; baseline: number; allow: number };
    }>(),
    {
        defaultDrop: false,
        activeLevel: '',
        counts: undefined,
    },
);

const emit = defineEmits<{ (e: 'filter', level: string): void }>();

const t = (key: string) => i18n.global.t(key);

interface Segment {
    key: string;
    label: string;
    level?: string;
    type: 'success' | 'info' | 'warning' | 'danger' | 'primary';
    icon?: any;
    tip?: string;
    count?: number;
    clickable: boolean;
    active: boolean;
}

const segments = computed<Segment[]>(() => {
    const lv = props.activeLevel || '';
    return [
        {
            key: 'inbound',
            label: t('firewall.flowInbound'),
            type: 'info',
            clickable: true,
            active: lv === '',
        },
        {
            key: 'rescue',
            label: t('firewall.flowRescue'),
            type: 'primary',
            tip: t('firewall.riskBlockSelf'),
            clickable: false,
            active: false,
        },
        {
            key: 'deny',
            label: t('firewall.flowDeny'),
            level: 'deny',
            type: 'danger',
            count: props.counts?.deny,
            clickable: true,
            active: lv === 'deny',
        },
        {
            key: 'baseline',
            label: t('firewall.flowBaseline'),
            level: 'baseline',
            type: 'info',
            icon: Lock,
            count: props.counts?.baseline,
            clickable: true,
            active: lv === 'baseline',
        },
        {
            key: 'allow',
            label: t('firewall.flowAllow'),
            level: 'allow',
            type: 'success',
            count: props.counts?.allow,
            clickable: true,
            active: lv === 'allow',
        },
        {
            key: 'default',
            label: props.defaultDrop ? t('firewall.flowDefaultStrict') : t('firewall.flowDefaultLoose'),
            type: props.defaultDrop ? 'warning' : 'info',
            clickable: false,
            active: false,
        },
    ];
});

const onSegClick = (seg: Segment) => {
    if (!seg.clickable) return;
    // 再次点击当前激活段则清除过滤；'入站' 段始终回到全部
    emit('filter', seg.active ? '' : seg.level || '');
};
</script>
