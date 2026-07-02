// 会话型确认窗口的共享状态与动作（模块级单例）。
//
// <SessionConfirm /> 挂在共享头部 firewall/index.vue（FireRouter）里负责轮询与倒计时；
// overview / inbound 列表 / inbound operate 抽屉 / 快照恢复 等处只需 enterFireApplying() 即可
// 即时进入「应用中…」过渡态。把 session/remain/applying/loading 与 confirm/revert 动作上提到
// 单例，overview 可直接复用同一份会话状态渲染内联确认卡，无需重复拉取或重写动作逻辑。
import { ref } from 'vue';
import { Host } from '@/api/interface/host';
import { confirmFireSession, loadFireSession, revertFireSession } from '@/api/modules/host';
import i18n from '@/lang';
import { MsgSuccess, MsgWarning } from '@/utils/message';
import { useFireBaseInfo } from '@/views/host/firewall/composables/useFireBaseInfo';

const { loadBaseInfo } = useFireBaseInfo('base');

const session = ref<Host.FirewallSession>({
    active: false,
    changes: [],
    remainSeconds: 0,
    since: '',
    snapshot: '',
});
const remain = ref(0);
// 保存成功后立即进入的「应用中…」过渡态：禁用确认/撤销，约 2s 或拿到确认窗口为止。
const applying = ref(false);
const loading = ref(false);
let applyTimer: ReturnType<typeof setTimeout> | null = null;

const refresh = async (): Promise<void> => {
    try {
        const res = await loadFireSession();
        session.value = res.data;
        remain.value = res.data.remainSeconds;
    } catch {
        session.value.active = false;
    }
    // 已拿到确认窗口，提前结束过渡态。
    if (applying.value && session.value.active) {
        applying.value = false;
        if (applyTimer) {
            clearTimeout(applyTimer);
            applyTimer = null;
        }
    }
};

// 由保存成功的调用方触发：统一弹「应用中…」提示并显示 spinner，
// 再主动刷新拿确认窗口；约 2s 后兜底退出。
const enterApplying = (): void => {
    MsgWarning(i18n.global.t('firewall.applying'));
    applying.value = true;
    refresh();
    if (applyTimer) clearTimeout(applyTimer);
    applyTimer = setTimeout(() => {
        applying.value = false;
        applyTimer = null;
        refresh();
    }, 2000);
};

// 供会话型保存成功方调用：立即进入应用中过渡态。若当前无 <SessionConfirm />（未注册轮询），
// 后续 3s 轮询仍会兜底拉起确认卡（轮询由 SessionConfirm 持有，仅防火墙页打开时运行）。
export const enterFireApplying = enterApplying;

// 倒计时归 0：后端会自动撤销，前端主动刷新并据结果提示。
const onCountdownZero = async (): Promise<void> => {
    await refresh();
    await loadBaseInfo('base');
    if (!session.value.active) {
        MsgWarning(i18n.global.t('firewall.autoReverted'));
    }
};

const onConfirm = async (): Promise<void> => {
    loading.value = true;
    try {
        await confirmFireSession();
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await refresh();
        await loadBaseInfo('base');
    } finally {
        loading.value = false;
    }
};

const onRevert = async (): Promise<void> => {
    loading.value = true;
    try {
        await revertFireSession();
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
        await refresh();
        await loadBaseInfo('base');
    } finally {
        loading.value = false;
    }
};

export function useFireSession() {
    return {
        session,
        remain,
        applying,
        loading,
        refresh,
        enterApplying,
        onConfirm,
        onRevert,
        onCountdownZero,
    };
}
