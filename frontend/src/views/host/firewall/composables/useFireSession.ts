// 会话型确认窗口的共享状态与动作（模块级单例）。
//
// <SessionConfirm /> 挂在共享头部 firewall/index.vue（FireRouter）里负责轮询与倒计时；
// 会话型变更（drop / 开启白名单模式等）的保存方成功后调 notifyFireChange() 统一反馈。
// 把 session/remain/loading 与 confirm/revert 动作上提到单例，各调用方复用同一份
// 会话状态，无需重复拉取或重写动作逻辑。
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
});
const remain = ref(0);
const loading = ref(false);

const refresh = async (): Promise<void> => {
    try {
        const res = await loadFireSession();
        session.value = res.data;
        remain.value = res.data.remainSeconds;
    } catch {
        session.value.active = false;
    }
};

// 会话型保存成功后的统一反馈：后端在请求内同步武装确认窗口（BeginSessionGuard），
// 刷新一次即可判定——武装了则由确认条接管提示，未武装则补一条常规成功提示。
export const notifyFireChange = async (): Promise<void> => {
    await refresh();
    if (!session.value.active) {
        MsgSuccess(i18n.global.t('commons.msg.operationSuccess'));
    }
};

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
        loading,
        refresh,
        onConfirm,
        onRevert,
        onCountdownZero,
    };
}
