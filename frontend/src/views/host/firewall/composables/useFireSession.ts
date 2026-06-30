// 会话型保存成功后立即进入「应用中…」过渡态的桥接单例。
//
// <SessionConfirm /> 挂在共享头部 firewall/index.vue（FireRouter）里，而会话型保存发生在
// overview / inbound 列表 / inbound operate 抽屉 / 快照恢复 等处。operate 抽屉是 inbound 的
// 子组件，够不到 FireRouter 内 <SessionConfirm /> 的 ref，逐层透传 ref 过于繁琐且易漏。
// 这里采用与 useFireBaseInfo 一致的模块级单例：SessionConfirm 挂载时注册自己的 enterApplying，
// 卸载时注销；任一页面保存成功后调 enterFireApplying() 即可即时显示过渡态，无需等 3s 轮询。

let enterApplyingFn: (() => void) | null = null;

export const registerFireApplying = (fn: (() => void) | null): void => {
    enterApplyingFn = fn;
};

// 供会话型保存成功方调用：立即进入应用中过渡态。若当前页无 <SessionConfirm />（未注册）则为 no-op，
// 后续 3s 轮询仍会兜底拉起确认卡。
export const enterFireApplying = (): void => {
    enterApplyingFn?.();
};
