import { ref, reactive, shallowReactive, markRaw } from 'vue';
import { defineStore } from 'pinia';
import { newUUID } from '@/utils/id';

// A web terminal session is bound to the browser tab, not to the route.
// Entries live here for as long as the SPA does; the Terminal components that
// own the websocket and xterm are rendered by components/terminal/host.vue and
// teleported into the terminal page whenever it is mounted.
export interface TerminalSessionEntry {
    key: string;
    title: string;
    wsID: number; // 0 = local shell
    endpoint: string;
    args: string;
    sessionId: string; // agent side id, known once the hello arrived
    pinned: boolean; // survives leaving the terminal page and a page refresh
    status: 'online' | 'closed';
    latency: number;
    refresh: number; // bump to remount the Terminal component
}

interface PinnedRecord {
    key: string;
    title: string;
    wsID: number;
    endpoint: string;
    args: string;
    sessionId: string;
}

const PINNED_KEY = 'terminal.pinnedSessions';

const loadPinned = (): PinnedRecord[] => {
    try {
        const raw = sessionStorage.getItem(PINNED_KEY);
        const list = raw ? JSON.parse(raw) : [];
        return Array.isArray(list) ? list.filter((s) => s && s.key && s.sessionId) : [];
    } catch {
        return [];
    }
};

const TerminalSessionStore = defineStore('TerminalSessionStore', () => {
    const entries = ref<TerminalSessionEntry[]>(
        loadPinned().map((s) => ({
            key: s.key,
            title: s.title,
            wsID: s.wsID,
            endpoint: s.endpoint,
            args: s.args,
            sessionId: s.sessionId,
            pinned: true,
            status: 'online',
            latency: 0,
            refresh: 0,
        })),
    );
    // Terminal component instances and page slot elements, keyed by entry key.
    const instances = reactive<Record<string, any>>({});
    const slots = shallowReactive<Record<string, HTMLElement | undefined>>({});

    const savePinned = () => {
        const list: PinnedRecord[] = entries.value
            .filter((e) => e.pinned && e.sessionId)
            .map(({ key, title, wsID, endpoint, args, sessionId }) => ({
                key,
                title,
                wsID,
                endpoint,
                args,
                sessionId,
            }));
        try {
            sessionStorage.setItem(PINNED_KEY, JSON.stringify(list));
        } catch {}
    };

    const find = (key: string) => entries.value.find((e) => e.key === key);

    const add = (init: Omit<TerminalSessionEntry, 'key' | 'sessionId' | 'pinned' | 'latency' | 'refresh'>) => {
        const key = newUUID();
        entries.value.push({ ...init, key, sessionId: '', pinned: false, latency: 0, refresh: 0 });
        return key;
    };

    // removeWhere drops matching entries; the host unmounts their Terminals, which closes the websockets with 1000.
    const removeWhere = (match: (e: TerminalSessionEntry) => boolean) => {
        for (const e of entries.value.filter(match)) {
            delete instances[e.key];
            delete slots[e.key];
        }
        entries.value = entries.value.filter((e) => !match(e));
        savePinned();
    };

    const remove = (key: string) => removeWhere((e) => e.key === key);
    const closeUnpinned = () => removeWhere((e) => !e.pinned);
    // closeAll runs on logout (or an expired login): every session ends, pinned or not.
    const closeAll = () => removeWhere(() => true);

    const setPinned = (key: string, pinned: boolean) => {
        const e = find(key);
        if (!e) return;
        e.pinned = pinned;
        savePinned();
    };

    const setSessionId = (key: string, id: string) => {
        const e = find(key);
        if (!e) return;
        e.sessionId = id;
        e.status = 'online';
        savePinned();
    };

    // onExpired: the agent no longer has the session; the next reconnect opens a fresh one.
    const onExpired = (key: string) => {
        const e = find(key);
        if (!e) return;
        e.sessionId = '';
        e.status = 'closed';
        savePinned();
    };

    const setInstance = (key: string, inst: any) => {
        if (inst) {
            instances[key] = markRaw(inst);
        } else {
            delete instances[key];
        }
    };

    const setSlot = (key: string, el: HTMLElement | null) => {
        slots[key] = el || undefined;
    };

    return {
        entries,
        instances,
        slots,
        find,
        add,
        remove,
        closeUnpinned,
        closeAll,
        setPinned,
        setSessionId,
        onExpired,
        setInstance,
        setSlot,
    };
});

export default TerminalSessionStore;
