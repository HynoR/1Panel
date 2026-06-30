# Firewall Frontend Improvement List

Date: 2026-06-29
Branch reviewed: `feat/dev2`
Scope: new firewall overview, inbound rules, forwarding, initialization, strict mode, and rule operation drawers; backend session/snapshot/iptables strict-mode semantics.

This note intentionally excludes the "only zh/en translations were added" concern. That is acceptable for this workflow because the remaining language packs are expected to be filled by CI.

Note (from a separate review pass): measured against the other 8 language packs (ko, ru, pt-br, ms, ja, es-es, zh-Hant, tr), the ~80 newly added firewall keys (overview, inboundRule, flowInbound, whitelistMode, rescueChannel, wizardStep1-3, riskTitle, redlineBlockBoth, snapshotRestoreTarget, …) are entirely absent, including zh-Hant. The new overview/inbound/init-wizard/strict-mode/risk-precheck/flow-bar pages will render raw key paths (e.g. `firewall.overview`) in those locales. If CI does not auto-fill these packs, they must be backfilled manually (at minimum zh-Hant and primary languages) — treat as conditional P1.

## Product Direction

The firewall UI is an operational security console, not a marketing page. It should be dense, quiet, and explicit. Every screen should answer four questions without forcing the user to infer from scattered tags:

1. What is the current effective firewall state?
2. What traffic is protected, allowed, denied, or forwarded?
3. What is the next safe action?
4. How can the user recover if the action goes wrong?

The current redesign does not yet meet that bar. It introduces new concepts such as strict mode, rescue ports, snapshots, Docker protection, and merged inbound rules, but the UI does not make those concepts coherent. Several functional states also do not round-trip correctly.

## P0 Backend Safety and Session Semantics

The frontend redesign assumes the backend session/snapshot machinery is a reliable safety net for lockout-class changes. A separate review pass found several backend race and error-handling gaps that can defeat that net and permanently lock the operator out, so these are ranked above the frontend P0 items.

### B1. `RevertSession` lock/release asymmetry causes permanent lockout (High)

Current behavior:

- `agent/utils/firewall/session.go:118-142` `RevertSession` acquires the lock at 119-122, reads the snapshot, then releases the lock and runs the long `RestoreSnapshot` (1-2s) and `persistManagedChains()` without holding it. It only re-acquires the lock at line 138 to call `clearLocked()`.
- `ConfirmSession` (`session.go:105-115`) holds the lock for its entire body. The two paths are asymmetric.
- During the unlocked restore window, a concurrent reachability-reducing change (e.g. deleting the SSH accept rule) calls `BeginSession` (`session.go:63-86`), sees `active == true`, so it does not take a new snapshot, only appends the change and reinstalls T2 — the rule is deleted.
- The subsequent `clearLocked()` then clears that new session too: SSH accept is gone but there is no longer any auto-rollback. The operator is permanently locked out.

Root causes to address:

- `RevertSession` performs state-mutating work outside the lock, while `BeginSession` trusts `active` to decide whether to snapshot.
- There is no `reverting`/`restoring` flag that `BeginSession` could observe to block or reject concurrent changes during a revert.

Required changes:

- Hold the lock for the entire `RevertSession` body (consistent with `ConfirmSession`), or
- Introduce a `reverting` flag and make `BeginSession` block/reject new sessions while a revert is in progress.

Acceptance checks:

- While a revert is running, a concurrent delete of the SSH accept rule either waits for the revert to finish (and snapshots the restored state) or is rejected; it must not silently delete the rule and leave no rollback.
- After the revert completes, exactly one session state remains and it is the restored one.

### B2. `RestoreSnapshot` swallows IPv6 restore errors, contradicting the v4 fail-fast philosophy (High)

Current behavior:

- `agent/utils/firewall/snapshot.go:165-170`: the v6 branch only `global.LOG.Warnf`s the error and then `return nil`.
- The v4 side (`runScopedStrict`, `snapshot.go:255-262`) was already changed to fail-fast.
- Result: when v6 restore fails, the function still reports success, so `persistManagedChains()` writes the dangerous v6 kernel state to disk and deletes the marker, permanently losing the retry opportunity.

Root causes to address:

- v6 `restoreScoped` failure is logged but downgraded to `nil`, breaking the "keep marker, do not persist, retry" contract that v4 already follows.

Required changes:

- On v6 `restoreScoped` failure, `return err` so the upper layer keeps the marker, skips persistence, and retries.

Acceptance checks:

- Force a v6 restore failure (e.g. no ip6tables). The session stays active, the marker stays on disk, nothing is persisted, and a later retry can succeed.
- v4 and v6 restore failures produce the same outer behavior.

### B3. After a restore failure the session is stuck active and the timer is not re-armed (Medium)

Current behavior:

- Automatic rollback is driven by `time.AfterFunc` calling `RevertSession` (`session.go:126-133`).
- If `RestoreSnapshot` fails and returns `err`, the one-shot timer has already fired and is never re-armed, but the session is still `active` and the marker is still on disk.
- `ReclaimSession` only runs on process restart, so until then the operator is forced to click "confirm keep" — and `ConfirmSession` persists the current dangerous state.

Root causes to address:

- Failed revert leaves the session active with no scheduled retry and no path back to a safe state except manual confirm.

Required changes:

- On restore failure, re-arm the timer (`armTimerLocked()`) for a bounded number of automatic retries; or
- Prompt the operator that a manual revert is required and forbid `ConfirmSession` until the revert succeeds.

Acceptance checks:

- A transient restore failure self-heals within a few retries without operator intervention.
- A persistent failure never offers "confirm keep" as the only forward action.

### B4. `migrateLegacyChains` renames old files to `.bak` even when a new write failed, permanently losing chain rules (Medium)

Current behavior:

- `agent/init/firewall/migrate.go:54-66`: if any `writeChainRules` fails (disk full, permission denied), it only `Errorf`s and does not return; the loop continues and still renames the old file to `.bak`.
- On the next start, `legacyMigrationPending` (`migrate.go:132-140`) sees the GuardFileName already exists and returns `false`, so migration never retries — that chain's rules are permanently lost.

Root causes to address:

- Write failure does not abort the migration or preserve the source file for a later retry.

Required changes:

- On any `writeChainRules` failure, return immediately without renaming the old file (leave it for retry); or
- Write all new files first, and only rename the old files to `.bak` after every write succeeds.

Acceptance checks:

- Simulate a write failure mid-migration. The old file is still present on next boot and migration retries; no chain rules are lost.

### B5. Strict mode does not verify the AFTER chain is bound to INPUT — can show "strict" while not effective (Medium)

Current behavior:

- `agent/app/service/iptables.go:290-302` `enableStrictMode` and `335-338` `isStrictMode`.
- `isStrictMode()` only checks whether the chain contains a DROP rule; it does not check whether the chain is actually jumped to from INPUT.
- `unbind-base` (`iptables.go:253-257`) only removes the jump and does not flush the chain.
- `LoadBaseInfo` (`firewall.go:96-98`) unconditionally assigns the result to `baseInfo.StrictMode`.

Root causes to address:

- Strictness is inferred from chain contents, not from the chain being wired into the live packet path.

Required changes:

- `isStrictMode()` additionally require "the AFTER chain is bound to INPUT"; or
- `enableStrictMode` precondition-check that the base chain is bound before activating.

Acceptance checks:

- Unbind the base chain while the AFTER chain still contains DROP. `isStrictMode()` returns false and the UI no longer claims strict mode is active.

### B6. Strict mode v4/v6 dual-write errors are silently swallowed, allowing v4-strict/v6-loose asymmetry (Medium)

Current behavior:

- `agent/app/service/iptables.go:312-315` `disableStrictMode` v6 and `328-330` `ensureAfterDropRules` v6 use `_ = iptables.AddRule6 / ClearChain6 / SaveRulesToFile6` and discard errors.
- `isStrictMode()` (`336-338`) only inspects v4.

Root causes to address:

- v6 critical operations cannot fail, yet strictness is only verified on v4.

Required changes:

- v6 critical operations should return errors on failure.
- `isStrictMode()` should also verify v6 (when `HasIP6tables()`).

Acceptance checks:

- With ip6tables present, a v6 strict operation failure surfaces an error and `isStrictMode()` reports false until v4 and v6 are both strict.

### B7. `enableStrictMode` writes the DB setting before confirmation and never rolls it back (Medium)

Current behavior:

- `agent/app/service/iptables.go:300`: after `BeginSession` + injecting DROP, it immediately calls `settingRepo.Update("IptablesStrictMode", enable)` before the user has confirmed.
- On 60s timeout the AFTER chain is reverted to empty, but the DB still says `enable`.

Root causes to address:

- The "do not finalize before confirmation" promise is violated: the persisted setting and the kernel state diverge after a revert.

Required changes:

- Move the setting write to the `ConfirmSession` path; or
- On successful `RevertSession`, write the setting back to `disable`.

Acceptance checks:

- Enable strict mode, let it time out. DB `IptablesStrictMode` is `disable` and matches the kernel state.
- Enable strict mode and confirm. DB is `enable` and matches the kernel state.

## P0 Functional Closure

### 1. Fix `family` and Docker protection round-trip

User testing reports that IP version and Docker protection appear ineffective: after selecting them, the backend response looks like they were not selected.

Root causes to address:

- `FireInfo` has `family`, but persistence and metadata paths still hard-code `Family: "ipv4"` in several places.
- `FireInfo` has no `applyToDocker`, so list and edit screens reconstruct Docker state through `/firewall/docker/status`.
- The current frontend `matchDocker()` only supports port rows and matches only port/protocol, not address/strategy.
- Address rules can be applied to Docker by the backend, but the frontend always displays address rows as not Docker-protected.
- Edit, delete, batch delete, status switch, export, and import paths can drop `family` or Docker state.
- `inbound/operate/index.vue:67-77`: the `family` selector is hidden under `v-if="dialogMode==='managed' && capabilities.ipv6Rules"`; the old behavior displayed it purely by capability, so external-mode users cannot specify IPv4/IPv6 at all.
- `inbound/index.vue:841-872` `onExport` only exports `family/address/port/protocol/strategy/description`, omitting `ruleType` and `applyToDocker`. The import side (`inbound/import/index.vue:185-199` `normalizeRule`) infers the rule type from "has port → port rule", so an address-only rule (no port but with address) is misclassified as an address rule and Docker policy cannot be restored.

Required changes:

- Add an explicit `applyToDocker` field to the rule list response or compute it in `SearchWithPage` before returning rows.
- Match Docker state for both rule types:
  - port: `port + protocol + strategy + normalized address`
  - address: `address + strategy`
- Normalize `Anywhere`, empty source, and CIDR values consistently in backend and frontend.
- Preserve requested `family` in firewall metadata and description fingerprints instead of defaulting to IPv4.
- Ensure edit drawers receive the true existing `family` and `applyToDocker` values.
- Ensure update and batch paths pass the old rule fields required to remove stale v4/v6 and Docker rules.
- Export `ruleType` and `applyToDocker`; on import, dispatch by `ruleType` first instead of inferring from the port field.
- Confirm whether hiding `family` in external mode is intentional; if not, restore capability-based display.

Acceptance checks:

- Create a `drop` port rule with IPv4 only and Docker protection enabled. Refresh list, reopen edit drawer, both values remain selected.
- Create a `drop` address rule with Docker protection enabled. Refresh list, row shows Docker protection and edit drawer remains selected.
- Change a rule from Docker protected to not protected. `/firewall/docker/status` no longer contains that rule.
- Create IPv6-only and both-family rules. Refresh list and descriptions still attach to the correct rows.

### 2. Fix forwarding initialization

Current behavior:

- The frontend calls `operateFilterChain('1PANEL_FORWARD', 'init-forward')`.
- Backend DTO validation for `IptablesOp.Name` does not allow `1PANEL_FORWARD`.
- The request is rejected before reaching service code.

Required changes:

- Add `1PANEL_FORWARD` to the allowed backend DTO values, or change the operation API so `init-forward` does not require an invalid chain name.
- Keep the frontend initialization CTA disabled or hidden when forwarding is natively supported and no panel NAT chain is needed.

Acceptance checks:

- On a fresh panel-NAT forwarding setup, click Initialize on the forwarding page and confirm the chain becomes ready.
- The same flow must not show a generic validation error.

### 3. Refresh shared state after strict-mode confirm, revert, and timeout

Current behavior:

- `session-confirm.vue` refreshes only the session.
- `strictMode` lives in shared `useFireBaseInfo()` state.
- After revert or timeout, overview and inbound still show stale strict-mode state.
- `composables/useFireBaseInfo.ts:34,62-73`: the shared singleton `baseInfo` is overwritten wholesale by each tab's `loadBaseInfo(tab)`. `isReady`/`isBind` are already keyed per tab, but `mode/name/version/capabilities/strictMode` are shared overwrites, so with multiple firewall tabs kept alive, calling `loadBaseInfo('base')` can still have its display fields clobbered by another tab's load — a cross-tab race on the very field strict-mode refresh depends on.

Required changes:

- After confirm, manual revert, and automatic timeout refresh, call `loadBaseInfo('base')`.
- Trigger the active page to reload derived state such as FlowBar counts and default policy labels.
- Avoid showing a final success message for strict-mode enablement before the user confirms the session.
- Isolate display fields (`mode/name/version/capabilities/strictMode`) per tab as well, or confirm there is no keep-alive across firewall tabs.

Acceptance checks:

- Enable strict mode, then revert. Overview policy, strict switch, and inbound FlowBar return to loose mode.
- Enable strict mode, wait for timeout. UI returns to loose mode without requiring a manual page refresh.

### 4. Block rule CRUD when firewall is inactive

Current behavior:

- Forwarding page has inactive masking.
- Inbound page only checks `isReady`, so a stopped firewall can still expose CRUD, import, export, and rule queries.

Required changes:

- Inbound page should follow the same inactive behavior as forwarding.
- When inactive, show a clear state with a primary action to start the firewall from overview.
- `loadData()` should stop querying rules when `!isActive`.

Acceptance checks:

- Stop firewall, open inbound rules. No create/delete/import action is available.
- Start firewall, inbound rules reload normally.

### 14. Block inline strategy toggle on baseline rows and wire `RiskPrecheck` (High, self-lock risk)

Current behavior:

- `frontend/src/views/host/firewall/inbound/index.vue:87-110` (strategy column) and `724-791` (`onChangeStatus`).
- The strategy column "allow/deny" buttons are gated only by `v-permission v-node-admin`; they are not disabled for `row.level === 'baseline'` rows, even though the delete button on the same page disables baseline rows (`:891`).
- `onChangeStatus` only opens a generic `ElMessageBox.confirm`; it does not go through `RiskPrecheck`.
- Net effect: the SSH 22 accept baseline rule can be flipped to drop with a single click and one generic confirm. The create/edit drawer (`operate/index.vue`) runs `computeRisk` + `RiskPrecheck` redline blocking for the same class of dangerous operation, so protection is inconsistent across the two entry points. The backend 60s auto-revert is the only safety net, and during the 0–3s poll window the user sees no confirmation card and no self-lock warning.

Root causes to address:

- Inline strategy toggle bypasses the `RiskPrecheck` path that the drawer enforces.
- Baseline rows are not treated as readonly for strategy toggling, only for deletion.

Required changes:

- Disable the strategy toggle for `row.level === 'baseline'` rows; or
- Route `onChangeStatus` through `RiskPrecheck` (reuse `computeRisk`) and show a redline confirm when SSH or the panel port would be covered.

Acceptance checks:

- A baseline row's strategy toggle is disabled, or it goes through a redline confirm.
- It is not possible to flip an SSH accept rule to drop with a single generic confirm.

## P1 UX and Guidance Redesign

### 5. Rework overview into a real operations dashboard

Current issues visible in screenshots:

- Three isolated cards occupy only the top strip and leave most of the page blank.
- Status information is fragmented into tags without clear hierarchy.
- Snapshot card can display `NaN-NaN-NaN NaN:NaN:NaN`.
- Strict mode, default policy, ping blocking, rescue ports, and snapshots are all presented as unrelated controls.
- The page does not tell the user what they should check next.

Required changes:

- Replace the three loose cards with a compact operations layout:
  - top status strip: provider, active state, management mode, default policy, boot consistency
  - primary action area: start/restart/init, confirm/revert pending session, strict-mode action
  - protection summary: rescue ports, Docker protection availability, IPv6 support
  - recovery summary: latest snapshot, rollback action, current pending session
- Fix snapshot date formatting by using the correct timestamp formatter for compact UTC strings.
- Show actionable warnings before secondary details:
  - not initialized
  - inactive firewall
  - strict-mode pending confirmation
  - boot degraded
  - Docker protection unavailable
- Keep the rest of the page useful. If there are no more panels, do not leave a large empty blank area; add recent changes, quick links, or concise explanation bands.

Acceptance checks:

- A new user can identify the effective policy and next safe action within 5 seconds.
- No snapshot date renders as `NaN`.
- Pending confirmation is visually more important than static status tags.

### 6. Make inbound rule flow understandable

Current issues:

- The FlowBar is a row of clickable tags and arrows. It looks decorative and does not explain actual evaluation order well enough.
- "Baseline", "deny", "allow", and "default" are internal concepts exposed without enough context.
- The merged port/IP table is powerful, but users cannot easily tell whether they are managing service ports, source IPs, or system-protected rows.

Required changes:

- Rename the FlowBar area to an explicit "Inbound evaluation order" or similar concept in zh/en.
- Use compact segments with stable labels:
  - protected baseline
  - blocklist
  - allowlist/open ports
  - default policy
- Make each segment a filter with counts and a clear active state.
- Add a short one-line explanation only when it reduces risk, not as generic help text.
- In table rows, show rule type with badges: port rule, source IP rule, protected baseline, Docker protected, IPv4/IPv6/both.
- Baseline rows should have a distinct readonly affordance and a clear reason why they cannot be deleted.

Acceptance checks:

- A user can explain why SSH/panel rows are protected.
- Filtering by deny/baseline/allow is obvious from the active segment state.

### 7. Rebuild the create/edit drawer around user intent

Current issues visible in screenshots:

- The drawer opens with strategy and an IP textarea, while the "rule object" choice is hidden under Advanced Options.
- IP version and Docker protection are also hidden under Advanced Options even though they materially affect the rule.
- The drawer does not show a concrete final effect summary.
- It is unclear whether the user is creating "allow service port", "block source IP", or "block service port".

Required changes:

- Put the intent selector at the top:
  - Allow service port
  - Block service port
  - Block source IP / CIDR
  - Allow source IP / CIDR
- Derive strategy and object type from the selected intent by default.
- Show only fields relevant to that intent.
- Move "scope" fields out of hidden Advanced Options:
  - IP version
  - Docker protection
  - source restriction
- Add a computed effect summary before confirm, for example:
  - "Block TCP 22 from all IPv4 sources, including Docker published ports."
  - "Allow TCP 8080 from 10.0.0.0/8 only."
- Redline cases should disable the submit button. Warn cases should require explicit acknowledgement.
- `inbound/operate/index.vue:184-186` `acceptParams` fires `loadSSHPort()/loadPanelPort()/loadDocker()` without awaiting them, so `computeRisk` (`292-316`) judges `coversPanel` against the defaults `sshPort='22'`/`panelPort=''`. If the user opens the drawer and clicks confirm quickly, `panelPort` is still empty → `coversPanel=false` → the "block both SSH and panel" redline is downgraded to warn/none and `RiskPrecheck` never shows the redline. The exact panel-port scenario that most needs the redline is silently disabled. Change `acceptParams` to `await Promise.all([...])` (or re-await inside `onSubmit` after validation and before `computeRisk`).
- `RiskPrecheck`'s `detail` field is always empty: `computeRisk` (`inbound/operate/index.vue:292-316`) never sets `detail`, and `risk-precheck.vue:16,21` `v-if="data.detail"` is therefore never rendered. Either populate `detail` with the concrete port/source in redline scenarios, or delete the field.

Acceptance checks:

- The drawer can be filled without opening an Advanced section for normal tasks.
- The final summary changes immediately when protocol, port, address, IP version, or Docker protection changes.
- Backend-redline actions are not presented as confirmable warnings.
- The panel-port redline fires regardless of how fast the user clicks confirm after opening the drawer.

### 8. Improve empty and not-ready states

Current issues visible in screenshots:

- Forwarding empty state is generic and centered in a large blank table.
- The user sees a Create button but not when forwarding is useful or what defaults mean.
- Not-ready states send users to overview or init without explaining what will be initialized.

Required changes:

- Empty forwarding state should explain the concrete use case:
  - "Forward an external port to another internal IP or local service."
  - Include one concise example, such as `8080 -> 192.168.1.10:80`.
- If panel NAT initialization is required, show an initialization state instead of an empty list.
- Empty inbound state should be different from inactive or uninitialized states.
- Do not duplicate toolbar Create and empty-state Create unless the empty state is the only visible action.

Acceptance checks:

- Fresh forwarding page tells the user whether they need to initialize first or create a rule.
- Empty state does not look like an unfinished table.

### 9. Make commit-confirm visible as the primary safety workflow

Current issues:

- Strict-mode enablement returns an operation success message even though it is only pending confirmation.
- `SessionConfirm.enterApplying()` exists but is not wired into the operation pages.
- The confirmation banner may appear late due to polling.
- `session-confirm.vue:71-80,112-123` defines and `defineExpose`s `enterApplying`, but a repo-wide grep only matches its own definition. `<SessionConfirm />` is never bound to a ref, and the call sites `inbound/operate/index.vue:369-395` (`doSubmit`) and `overview/index.vue:368-394` (`onToggleStrict`) never invoke it — the applying transition is dead, and the confirmation card only surfaces via the 3s `pollTimer`.

Required changes:

- Operations that start a session should immediately show an applying/pending state.
- Replace premature success messages with "change applied temporarily, confirm to keep".
- The confirm/revert banner should be sticky enough to remain visible while the user moves across firewall tabs.
- After confirm or revert, reload the active tab and overview state.
- Bind `<SessionConfirm ref="sessionRef" />` and call `sessionRef.value?.enterApplying()` in each save-success callback so the applying state appears immediately instead of waiting for the next poll.

Acceptance checks:

- Strict mode and high-risk rule changes never appear as final success before confirmation.
- Revert immediately updates all visible state.

### 15. Restore base chain bind/unbind entry or remove dead composable code

Current behavior:

- The old `frontend/src/views/host/firewall/status/index.vue:60-78` exposed bind/unbind under managed + isInit + base conditions (`operateFilterChain(..., 'bind'/'unbind')`).
- The new `overview/index.vue` has no such entry (only `advance/index.vue:49-54` retains chain-level bind/unbind).
- The composable `useFireBaseInfo` still exports `isBind`, but overview does not use it.

Root causes to address:

- A user-facing "enable/disable 1Panel management of the base chain" affordance was dropped from overview without a replacement, while the supporting composable code remains dead.

Required changes:

- Confirm with product: if base-chain bind/unbind is still needed, add the entry back to the overview status card; if it is deprecated, clean up `isBind`/`bindMap` dead code in the composable.

Acceptance checks:

- Base-chain "enable/disable 1Panel management" has a clear UI entry, or the dead composable code is removed.

### 16. Use `Promise.allSettled` for batch delete and always refresh

Current behavior:

- `frontend/src/views/host/firewall/inbound/index.vue:814-823,808-835`: port and address batch deletes run in parallel via `Promise.all`, so if either rejects the whole batch rejects.
- `OpDialog` only emits `search` on success. If the address batch fails but the port batch already succeeded, the list is not refreshed and the user sees already-deleted port rules (stale data).

Root causes to address:

- `Promise.all` short-circuits on the first rejection and the refresh is gated on overall success.

Required changes:

- Switch to `Promise.allSettled`, always call `loadData` regardless of outcome, and aggregate success/failure counts into the result message.

Acceptance checks:

- When one category's batch fails, the other category's already-applied deletions still show up in the refreshed list.

## P2 Polish and Consistency

### 10. Normalize terminology

Current terms mix implementation and user language:

- strict mode
- whitelist mode
- default policy
- global management
- baseline
- rescue channel
- protected

Required changes:

- Choose one product vocabulary in zh/en and apply consistently:
  - "宽松模式 / 白名单模式" for default policy
  - "保底端口" for SSH/panel/80/443 protected entries
  - "入站规则" for user-managed allow/block rules
  - "高级规则" only for raw iptables filters
- Avoid exposing implementation chain names in primary UI unless the user opens advanced details.

Acceptance checks:

- The same concept is not named differently across overview, inbound, drawer, and session confirm.

### 11. Normalize forwarding interface values

Current behavior:

- Frontend maps `*` to empty string.
- Dialog maps "all" to empty string.
- Backend duplicate detection may compare against `*`.

Required changes:

- Define one canonical value for all inbound interfaces.
- Use that value in list, create, edit, import, export, duplicate checks, and deletion.

Acceptance checks:

- Creating the same "all interfaces" forwarding rule twice returns duplicate consistently.

### 12. Align import/export with normal CRUD

Current issues:

- Forward import lacks the same validation as create/edit.
- Inbound import identifies conflicts but does not update them.
- Import file-internal duplicates are not detected.
- Import preview statuses do not map to exact execution behavior.
- `inbound/import/index.vue:117-122` `acceptParams` fire-and-forgets `loadCurrentData()`, so if the user selects a file immediately after opening the dialog, `currentPortRules/currentAddrRules` are still empty and `compareRules` (`201-236`) judges every imported row as `new` — conflict and duplicate detection both fail, and existing rules can be imported again.
- The export omits `ruleType`/`applyToDocker` (see item 1), so import cannot faithfully reconstruct Docker policy or rule type.

Required changes:

- Share validation helpers between create/edit and import.
- Add import-internal duplicate detection.
- For conflict rows, either provide "replace existing" behavior or make conflicts unselectable.
- Keep preview status labels aligned with actual submit behavior.
- `acceptParams` should `await loadCurrentData()` (or disable the upload button until loading completes) so `compareRules` runs against real current rules.
- Export `ruleType` and `applyToDocker` and import by `ruleType` (see item 1).

Acceptance checks:

- Invalid port/IP cannot be submitted through import.
- A conflict row either updates correctly or cannot be selected.

### 13. Clean routing names and old compatibility labels

Current behavior:

- `/hosts/firewall/overview` still uses route name `FirewallPort`.
- `/hosts/firewall/port` redirects to inbound.
- Some code still calls `routerToName('FirewallPort')`.
- `routers/modules/host.ts:116-125`: `FirewallIP` is also reused as the redirect for `/hosts/firewall/ip → inbound`, so the same name carries two unrelated meanings (IP page vs. inbound redirect), compounding the semantic mismatch.
- The physical `status/` directory still exists and is still imported by `overview/index.vue` (see new item 17), so cleanup is incomplete.

Required changes:

- Introduce a real `FirewallOverview` route name.
- Keep old redirect routes for compatibility only.
- Update new code to use the new name/path.
- Rename `FirewallIP` to `FirewallIPRedirect` to align with the `FirewallPortRedirect` style, and update `inbound/index.vue:319-321` `routerToName('FirewallPort')` to use the new `FirewallOverview` name.

Acceptance checks:

- New frontend code no longer references `FirewallPort` when it means overview.
- No route name is reused for both a real page and a redirect.

### 17. Finish status→overview migration: remove zombie `status/` directory

Current behavior:

- `frontend/src/views/host/firewall/overview/index.vue:247-248` still imports the old `@/views/host/firewall/status/white-list/index.vue` and `status/snapshot/index.vue`.
- The route table no longer has `/hosts/firewall/status` (no dead link), but the physical `status/` directory is now just a component folder, detached from its name's semantics.

Root causes to address:

- The migration to overview was left half-done: routes moved, components did not.

Required changes:

- Move `white-list`/`snapshot` into `overview/` or `components/`, and delete the `status/` directory.

Acceptance checks:

- The `status/` directory no longer exists and overview no longer cross-references old status components.

### 18. Frontend cleanup, type safety, and i18n

Current behavior:

- Several new firewall files lean on `any`, untyped refs, and orphan i18n keys, and a few code paths are dead or race-prone.

Root causes to address (one line each):

- `any` abuse / untyped refs: `inbound/index.vue:267,272-275`, `inbound/import/index.vue:102-103,110,156`, `advance/index.vue:181-189`, `forward/index.vue:135-144` → use `Host.InboundRule[]` / `InstanceType<typeof OpDialog>` and similar concrete types.
- Description inline edit `@enter` + `@blur` can double-submit: `inbound/index.vue:206-213`, `advance/index.vue:133-139` → debounce or ignore during loading.
- `init-wizard` forward/advance branches are unreachable dead code: `overview/init-wizard.vue:80-88` supports them but `overview/index.vue:490-498` only passes `tab:'base'` → delete those branches or let forward/advance reuse the wizard.
- `init-wizard` apply failure surfaces no error detail: `overview/init-wizard.vue:113-117` catch only sets `checkPassed=false` with no `MsgError` → add an error toast.
- `RiskPrecheck`'s `detail` field is always empty: `inbound/operate/index.vue:292-316` (`computeRisk` never sets `detail`), `risk-precheck.vue:16,21` → delete `detail` or populate it in redline scenarios (see item 7).
- `flow-bar` rescue segment uses `type:'primary'` whose support in el-tag 2.11.x needs verification: `components/flow-bar.vue:73`.
- Overview baseline 80/443 toggles only edit a settings string with no immediate firewall action: `overview/index.vue:155-172,310-313,447-457` → add a tooltip explaining the toggle semantics depend on backend interpretation.
- `advance` search does not `await loadStatus()`, so first paint's `loadPrompt` may use a stale `isBind`: `advance/index.vue:237,249-254`.
- Shared singleton `baseInfo` is repeatedly overwritten by each tab's `loadBaseInfo`: `composables/useFireBaseInfo.ts:34,62-73` — `isReady/isBind` are per-tab but `mode/name/version/capabilities/strictMode` are shared overwrites, causing cross-tab races when tabs are kept alive (see item 3) → isolate display fields per tab too.
- `onChangeStatus` / `onExport` confirm chains have no `.catch`, so canceling raises an unhandled rejection: `inbound/index.vue:738-790,842-871`.
- `goOverview` uses the route name `FirewallPort` to point at overview, which is misleading: `inbound/index.vue:319-321` (same root cause as item 13; fold into item 13's fix).
- `cleanOrphan` i18n key is orphaned: `frontend/src/lang/modules/en.ts:3934`, `zh.ts:3652` — the matching API `cleanOrphanFireRecords` was removed and no `$t('firewall.cleanOrphan')` call remains → delete the key or restore the cleanup entry.
- `RescueChannel` interface is an unused export: `frontend/src/api/interface/host.ts:223-228`, no repo references → delete or add a typed reference.
- `portHelper2` / `addressHelper2` remain as orphan keys in 8 language packs (en/zh already removed) → remove from ko, ru, pt-br, ms, ja, es-es, zh-Hant, tr.
- en/zh firewall-block key drift (not introduced by this change): en has `whiteList` (`en.ts:3859`) and `changeStrategyHelper` that zh lacks, while zh's `whiteList` lives in another namespace (`zh.ts:3875`) → clean up dead keys or align zh's structure.

Required changes:

- Replace `any` with concrete types, debounce double-submit paths, delete dead branches, populate or remove `detail`, verify el-tag `primary`, add tooltips for deferred-action toggles, await status loads, isolate shared state per tab, add `.catch` to confirm chains, and clean up orphan i18n keys and unused interfaces per the list above.

Acceptance checks:

- No new `any` in the firewall views; no unhandled rejections on cancel; orphan i18n keys and unused interfaces removed; dead branches deleted.

### Backend low-priority follow-ups (B8–B13)

These are lower-severity backend issues found in the same pass; each is listed as one root cause + required change.

- **B8 Low**: L3 commit-confirm is armed only under `isManagedMode()` — `agent/app/service/firewall.go:323,546`; ufw/firewalld (external) users have no L3 auto-rollback safety net for lockout-class changes. Required change: for external mode, run stricter prechecks on high-risk changes, or disable + explain in the frontend.
- **B9 Low**: `addressChangeNeedsConfirm` arms only for CIDR ranges — `firewall.go:971-981`; banning the admin's own single IP does not trigger auto-rollback. Required change: also compare against the current request source IP and arm when it matches.
- **B10 Low**: `HasIP6tables` should use a `sync.Once` cache — `agent/utils/firewall/client/iptables/ipv6.go:21-33`; if ip6tables is installed at runtime, a restart is required before it takes effect. Required change: cache via `sync.Once` and log the detection result at startup.
- **B11 Low**: `BeginSession` comment contradicts the actual call order — `session.go:60-62`; the comment says "changes should already be applied before calling" but the code calls `BeginSession` first, then applies. Required change: fix the comment.
- **B12 Low**: The session is armed before the change is applied, so a rule-write failure leaves a "ghost confirmation card" — `firewall.go:323-327,546-550`. Required change: move `BeginSession` to after the rule is successfully applied, or actively clear the session on write failure.
- **B13 Low**: `disableStrictMode` writes AFTER to disk directly when a session is active, bypassing "do not persist before confirmation" — `iptables.go:305-318`. Required change: if an active session is detected, clear it first before operating.

### Frontend follow-ups (F-series)

Lower-severity frontend items deferred to keep Phase A scope tight.

- **F-1**: Phase A item 5 (overview four-zone refactor) added 14 new `firewall.*` i18n keys only to `en.ts` / `zh.ts` / `zh-Hant.ts`. The other 8 packs (ko, ru, ms, tr, es-ES, pt-BR, ja) were not backfilled to avoid scope creep. New keys: `sectionActions`, `sectionActionsTip`, `warnNotReady`, `warnNotReadyHelper`, `warnNotActive`, `warnNotActiveHelper`, `dockerProtection`, `ipv6RulesCap`, `capSupported`, `capNotSupported`, `pendingSessionLabel`, `pendingSessionActive`, `pendingSessionNone`, `overviewHint`. Required change: backfill these 14 keys into the 8 remaining packs (they currently fall back to the en label via vue-i18n fallback). Note: zh-Hant is also missing many pre-existing `firewall.*` keys (e.g. `statusCard`, `rescueChannel`, `snapshot*`, `bootCheck`) — backfill those is a separate, larger task.

## Suggested Implementation Order

1. Fix `RevertSession` lock asymmetry and `RestoreSnapshot` v6 error swallowing (B1/B2) — lockout risk.
2. Restore timer re-arm on revert failure and migrate-chain write-failure handling (B3/B4).
3. Block inline strategy toggle on baseline rows + wire `RiskPrecheck` (item 14) — one-click self-lock.
4. Fix `family/applyToDocker` backend and frontend round-trip.
5. Fix forwarding initialization validation.
6. Fix session confirm state refresh and inactive inbound masking.
7. Rework inbound drawer intent model and computed effect summary.
8. Rework overview layout and snapshot date formatting.
9. Rework empty/not-ready states.
10. Normalize import/export, forwarding interface values, and route names.
11. Backend strict-mode bind/v6/DB-setting semantics (B5/B6/B7) and low-priority backend follow-ups (B8–B13).
12. Frontend cleanup, type safety, and i18n (item 18), plus status→overview migration (item 17) and base-chain bind/unbind entry (item 15).

## Verification Commands

Frontend scoped lint:

```bash
cd frontend
./node_modules/.bin/eslint --ext .js,.ts,.vue src/views/host/firewall src/api/modules/host.ts src/api/interface/host.ts
```

Focused backend tests after adding coverage:

```bash
cd agent
go test ./app/service ./utils/firewall/...
```

Do not attempt a full project build on a personal development machine.
