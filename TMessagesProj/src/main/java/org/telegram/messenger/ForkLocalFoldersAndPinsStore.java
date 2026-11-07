package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.SparseArray;

import org.telegram.secureoverlay.RelativeOrderMerger;
import org.telegram.tgnet.TLRPC;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Persists local-only chat folders (beyond Telegram's 10/20 server limit) and over-limit pinned
 * dialogs (beyond Telegram's 5/10 main-list limit or 100/200 per-folder peer limit) with relative
 * neighbor anchors so server reorders from other clients (e.g., Desktop) propagate while local-only
 * folders and pins keep their relative position.
 */
public final class ForkLocalFoldersAndPinsStore {

    public static final int SERVER_FOLDERS_LIMIT_DEFAULT = 10;
    public static final int SERVER_FOLDERS_LIMIT_PREMIUM = 20;

    public static final int SERVER_MAIN_PINNED_LIMIT_DEFAULT = 5;
    public static final int SERVER_MAIN_PINNED_LIMIT_PREMIUM = 10;
    public static final int SERVER_ARCHIVE_PINNED_LIMIT = 100;

    public static final int SERVER_FILTER_PEERS_LIMIT_DEFAULT = 100;
    public static final int SERVER_FILTER_PEERS_LIMIT_PREMIUM = 200;

    private static final String PREFS_PREFIX = "fork_local_folders_pins_";

    private static final String KEY_FOLDER_LOCAL_ONLY = "folder_local_only_ids";
    private static final String KEY_FOLDER_SERVER_KNOWN = "folder_server_known_ids";
    private static final String KEY_FOLDER_FULL_ORDER = "folder_local_full_order";
    private static final String KEY_FOLDER_ANCHORS = "folder_anchors";

    private static final String KEY_PINS_LOCAL_ONLY_PREFIX = "pins_local_only_";
    private static final String KEY_PINS_FULL_ORDER_PREFIX = "pins_local_full_order_";
    private static final String KEY_PINS_ANCHORS_PREFIX = "pins_anchors_";

    private static final String KEY_FILTER_PIN_LOCAL_ONLY_PREFIX = "filter_pin_local_only_";
    private static final String KEY_FILTER_PIN_FULL_ORDER_PREFIX = "filter_pin_full_order_";
    private static final String KEY_FILTER_PIN_ANCHORS_PREFIX = "filter_pin_anchors_";

    private static final String KEY_FILTER_INC_LOCAL_ONLY_PREFIX = "filter_inc_local_only_";
    private static final String KEY_FILTER_INC_FULL_ORDER_PREFIX = "filter_inc_full_order_";
    private static final String KEY_FILTER_INC_ANCHORS_PREFIX = "filter_inc_anchors_";

    private static final Object LOCK = new Object();
    private static final SparseArray<AccountState> ACCOUNT_CACHE = new SparseArray<>();

    private static final class ScopeData {
        final Set<Long> localOnlyIds = new HashSet<>();
        final List<Long> fullOrder = new ArrayList<>();
        final List<RelativeOrderMerger.Anchor> anchors = new ArrayList<>();
    }

    private static final class AccountState {
        final Set<Long> folderLocalOnlyIds = new HashSet<>();
        final Set<Long> folderServerKnownIds = new HashSet<>();
        final List<Long> folderFullOrder = new ArrayList<>();
        final List<RelativeOrderMerger.Anchor> folderAnchors = new ArrayList<>();
        final Map<Integer, ScopeData> mainPinsByFolderId = new HashMap<>();
        final Map<Integer, ScopeData> filterPinsByFilterId = new HashMap<>();
        final Map<Integer, ScopeData> filterIncludesByFilterId = new HashMap<>();
    }

    private ForkLocalFoldersAndPinsStore() {
    }

    public static int getServerFoldersLimit(boolean isPremium) {
        return isPremium ? SERVER_FOLDERS_LIMIT_PREMIUM : SERVER_FOLDERS_LIMIT_DEFAULT;
    }

    public static int getServerMainPinnedLimit(int folderId, boolean isPremium) {
        if (folderId == 1) {
            return SERVER_ARCHIVE_PINNED_LIMIT;
        }
        return isPremium ? SERVER_MAIN_PINNED_LIMIT_PREMIUM : SERVER_MAIN_PINNED_LIMIT_DEFAULT;
    }

    public static int getServerFilterPeersLimit(boolean isPremium) {
        return isPremium ? SERVER_FILTER_PEERS_LIMIT_PREMIUM : SERVER_FILTER_PEERS_LIMIT_DEFAULT;
    }

    private static SharedPreferences getPrefs(int account) {
        Context ctx = ApplicationLoader.applicationContext;
        if (ctx == null) {
            return null;
        }
        return ctx.getSharedPreferences(PREFS_PREFIX + account, Context.MODE_PRIVATE);
    }

    private static AccountState getStateLocked(int account) {
        AccountState state = ACCOUNT_CACHE.get(account);
        if (state != null) {
            return state;
        }
        state = new AccountState();
        SharedPreferences prefs = getPrefs(account);
        if (prefs != null) {
            state.folderLocalOnlyIds.addAll(parseLongSet(prefs.getString(KEY_FOLDER_LOCAL_ONLY, "")));
            state.folderServerKnownIds.addAll(parseLongSet(prefs.getString(KEY_FOLDER_SERVER_KNOWN, "")));
            state.folderFullOrder.addAll(parseLongList(prefs.getString(KEY_FOLDER_FULL_ORDER, "")));
            state.folderAnchors.addAll(parseAnchors(prefs.getString(KEY_FOLDER_ANCHORS, "")));
        }
        ACCOUNT_CACHE.put(account, state);
        return state;
    }

    private static ScopeData getMainPinScopeLocked(int account, AccountState state, int folderId) {
        ScopeData data = state.mainPinsByFolderId.get(folderId);
        if (data != null) {
            return data;
        }
        data = new ScopeData();
        SharedPreferences prefs = getPrefs(account);
        if (prefs != null) {
            data.localOnlyIds.addAll(parseLongSet(prefs.getString(KEY_PINS_LOCAL_ONLY_PREFIX + folderId, "")));
            data.fullOrder.addAll(parseLongList(prefs.getString(KEY_PINS_FULL_ORDER_PREFIX + folderId, "")));
            data.anchors.addAll(parseAnchors(prefs.getString(KEY_PINS_ANCHORS_PREFIX + folderId, "")));
        }
        state.mainPinsByFolderId.put(folderId, data);
        return data;
    }

    private static ScopeData getFilterPinScopeLocked(int account, AccountState state, int filterId) {
        ScopeData data = state.filterPinsByFilterId.get(filterId);
        if (data != null) {
            return data;
        }
        data = new ScopeData();
        SharedPreferences prefs = getPrefs(account);
        if (prefs != null) {
            data.localOnlyIds.addAll(parseLongSet(prefs.getString(KEY_FILTER_PIN_LOCAL_ONLY_PREFIX + filterId, "")));
            data.fullOrder.addAll(parseLongList(prefs.getString(KEY_FILTER_PIN_FULL_ORDER_PREFIX + filterId, "")));
            data.anchors.addAll(parseAnchors(prefs.getString(KEY_FILTER_PIN_ANCHORS_PREFIX + filterId, "")));
        }
        state.filterPinsByFilterId.put(filterId, data);
        return data;
    }

    private static ScopeData getFilterIncScopeLocked(int account, AccountState state, int filterId) {
        ScopeData data = state.filterIncludesByFilterId.get(filterId);
        if (data != null) {
            return data;
        }
        data = new ScopeData();
        SharedPreferences prefs = getPrefs(account);
        if (prefs != null) {
            data.localOnlyIds.addAll(parseLongSet(prefs.getString(KEY_FILTER_INC_LOCAL_ONLY_PREFIX + filterId, "")));
            data.fullOrder.addAll(parseLongList(prefs.getString(KEY_FILTER_INC_FULL_ORDER_PREFIX + filterId, "")));
            data.anchors.addAll(parseAnchors(prefs.getString(KEY_FILTER_INC_ANCHORS_PREFIX + filterId, "")));
        }
        state.filterIncludesByFilterId.put(filterId, data);
        return data;
    }

    private static void saveFolderStateLocked(int account, AccountState state) {
        SharedPreferences prefs = getPrefs(account);
        if (prefs == null) {
            return;
        }
        prefs.edit()
                .putString(KEY_FOLDER_LOCAL_ONLY, serializeLongCollection(state.folderLocalOnlyIds))
                .putString(KEY_FOLDER_SERVER_KNOWN, serializeLongCollection(state.folderServerKnownIds))
                .putString(KEY_FOLDER_FULL_ORDER, serializeLongCollection(state.folderFullOrder))
                .putString(KEY_FOLDER_ANCHORS, serializeAnchors(state.folderAnchors))
                .apply();
    }

    private static void saveMainPinScopeLocked(int account, int folderId, ScopeData scope) {
        SharedPreferences prefs = getPrefs(account);
        if (prefs == null) {
            return;
        }
        prefs.edit()
                .putString(KEY_PINS_LOCAL_ONLY_PREFIX + folderId, serializeLongCollection(scope.localOnlyIds))
                .putString(KEY_PINS_FULL_ORDER_PREFIX + folderId, serializeLongCollection(scope.fullOrder))
                .putString(KEY_PINS_ANCHORS_PREFIX + folderId, serializeAnchors(scope.anchors))
                .apply();
    }

    private static void saveFilterScopesLocked(int account, int filterId, ScopeData pinScope, ScopeData incScope) {
        SharedPreferences prefs = getPrefs(account);
        if (prefs == null) {
            return;
        }
        prefs.edit()
                .putString(KEY_FILTER_PIN_LOCAL_ONLY_PREFIX + filterId, serializeLongCollection(pinScope.localOnlyIds))
                .putString(KEY_FILTER_PIN_FULL_ORDER_PREFIX + filterId, serializeLongCollection(pinScope.fullOrder))
                .putString(KEY_FILTER_PIN_ANCHORS_PREFIX + filterId, serializeAnchors(pinScope.anchors))
                .putString(KEY_FILTER_INC_LOCAL_ONLY_PREFIX + filterId, serializeLongCollection(incScope.localOnlyIds))
                .putString(KEY_FILTER_INC_FULL_ORDER_PREFIX + filterId, serializeLongCollection(incScope.fullOrder))
                .putString(KEY_FILTER_INC_ANCHORS_PREFIX + filterId, serializeAnchors(incScope.anchors))
                .apply();
    }

    // =============================================================================================
    // 1. FOLDERS ORDER & LOCAL-ONLY FOLDERS
    // =============================================================================================

    public static boolean isLocalOnlyFilter(int account, int filterId) {
        if (filterId == 0) {
            return false;
        }
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            return state.folderLocalOnlyIds.contains((long) filterId);
        }
    }

    public static void markLocalOnlyFilter(int account, int filterId, boolean localOnly, List<MessagesController.DialogFilter> currentFilters) {
        if (filterId == 0) {
            return;
        }
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            if (localOnly) {
                state.folderLocalOnlyIds.add((long) filterId);
                state.folderServerKnownIds.remove((long) filterId);
            } else {
                state.folderLocalOnlyIds.remove((long) filterId);
                state.folderServerKnownIds.add((long) filterId);
            }
            if (currentFilters != null && !currentFilters.isEmpty()) {
                updateFolderOrderInMemoryLocked(state, currentFilters);
            } else {
                state.folderAnchors.clear();
                state.folderAnchors.addAll(RelativeOrderMerger.computeAnchors(state.folderFullOrder, state.folderLocalOnlyIds));
            }
            saveFolderStateLocked(account, state);
        }
    }

    public static void removeFilter(int account, int filterId) {
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            long idLong = filterId;
            state.folderLocalOnlyIds.remove(idLong);
            state.folderServerKnownIds.remove(idLong);
            state.folderFullOrder.remove(idLong);
            state.folderAnchors.clear();
            state.folderAnchors.addAll(RelativeOrderMerger.computeAnchors(state.folderFullOrder, state.folderLocalOnlyIds));
            state.filterPinsByFilterId.remove(filterId);
            state.filterIncludesByFilterId.remove(filterId);
            SharedPreferences prefs = getPrefs(account);
            if (prefs != null) {
                prefs.edit()
                        .putString(KEY_FOLDER_LOCAL_ONLY, serializeLongCollection(state.folderLocalOnlyIds))
                        .putString(KEY_FOLDER_SERVER_KNOWN, serializeLongCollection(state.folderServerKnownIds))
                        .putString(KEY_FOLDER_FULL_ORDER, serializeLongCollection(state.folderFullOrder))
                        .putString(KEY_FOLDER_ANCHORS, serializeAnchors(state.folderAnchors))
                        .remove(KEY_FILTER_PIN_LOCAL_ONLY_PREFIX + filterId)
                        .remove(KEY_FILTER_PIN_FULL_ORDER_PREFIX + filterId)
                        .remove(KEY_FILTER_PIN_ANCHORS_PREFIX + filterId)
                        .remove(KEY_FILTER_INC_LOCAL_ONLY_PREFIX + filterId)
                        .remove(KEY_FILTER_INC_FULL_ORDER_PREFIX + filterId)
                        .remove(KEY_FILTER_INC_ANCHORS_PREFIX + filterId)
                        .apply();
            }
        }
    }

    private static void updateFolderOrderInMemoryLocked(AccountState state, List<MessagesController.DialogFilter> filters) {
        if (filters == null) {
            return;
        }
        LinkedHashSet<Long> deduplicated = new LinkedHashSet<>();
        for (int i = 0; i < filters.size(); i++) {
            MessagesController.DialogFilter f = filters.get(i);
            if (f == null) {
                continue;
            }
            long id = f.isDefault() ? 0L : (long) f.id;
            deduplicated.add(id);
        }
        state.folderFullOrder.clear();
        state.folderFullOrder.addAll(deduplicated);
        state.folderAnchors.clear();
        state.folderAnchors.addAll(RelativeOrderMerger.computeAnchors(state.folderFullOrder, state.folderLocalOnlyIds));
    }

    public static void recordLocalFolderOrder(int account, List<MessagesController.DialogFilter> filters) {
        if (filters == null || filters.isEmpty()) {
            return;
        }
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            updateFolderOrderInMemoryLocked(state, filters);
            saveFolderStateLocked(account, state);
        }
    }

    /**
     * Records the full local folder order and returns the server-compatible order list for
     * {@code TL_messages_updateDialogFiltersOrder} (excluding local-only folders and capped to the
     * server folder limit).
     */
    public static ArrayList<Integer> buildServerFolderOrderRequest(
            int account,
            List<MessagesController.DialogFilter> filters,
            boolean isPremium,
            boolean includeDefaultZero) {
        ArrayList<Integer> serverOrder = new ArrayList<>();
        if (filters == null) {
            return serverOrder;
        }
        final int serverLimit = getServerFoldersLimit(isPremium);
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            int serverNonDefaultCount = 0;
            for (int i = 0; i < filters.size(); i++) {
                MessagesController.DialogFilter f = filters.get(i);
                if (f == null) {
                    continue;
                }
                if (f.isDefault()) {
                    if (includeDefaultZero) {
                        serverOrder.add(0);
                    }
                    continue;
                }
                long idLong = f.id;
                if (state.folderLocalOnlyIds.contains(idLong)) {
                    continue;
                }
                if (serverNonDefaultCount >= serverLimit && !state.folderServerKnownIds.contains(idLong)) {
                    state.folderLocalOnlyIds.add(idLong);
                    continue;
                }
                serverOrder.add(f.id);
                serverNonDefaultCount++;
            }
            updateFolderOrderInMemoryLocked(state, filters);
            saveFolderStateLocked(account, state);
        }
        return serverOrder;
    }

    public static boolean shouldRetainMissingFilterOnSync(
            int account,
            int filterId,
            List<Integer> incomingServerOrder,
            int localTotalCount,
            int maxForkLimit) {
        if (filterId == 0) {
            return true;
        }
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            long idLong = filterId;
            if (state.folderLocalOnlyIds.contains(idLong)) {
                return true;
            }
            if (!state.folderServerKnownIds.contains(idLong)
                    && incomingServerOrder != null
                    && incomingServerOrder.size() >= SERVER_FOLDERS_LIMIT_DEFAULT
                    && localTotalCount <= maxForkLimit) {
                state.folderLocalOnlyIds.add(idLong);
                state.folderAnchors.clear();
                state.folderAnchors.addAll(RelativeOrderMerger.computeAnchors(state.folderFullOrder, state.folderLocalOnlyIds));
                saveFolderStateLocked(account, state);
                return true;
            }
            return false;
        }
    }

    public static List<Integer> mergeFolderOrderOnSync(
            int account,
            List<Integer> incomingServerOrder,
            List<MessagesController.DialogFilter> currentLocalFilters,
            boolean isPremium) {
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            List<Long> serverLongs = new ArrayList<>();
            if (incomingServerOrder != null) {
                for (Integer id : incomingServerOrder) {
                    if (id != null) {
                        serverLongs.add(id.longValue());
                    }
                }
            }
            if (!serverLongs.contains(0L)) {
                serverLongs.add(0, 0L);
            }

            // Update server-known set and promote any previously local-only folder that now exists on server.
            state.folderServerKnownIds.clear();
            for (Long serverId : serverLongs) {
                if (serverId != 0L) {
                    state.folderServerKnownIds.add(serverId);
                    state.folderLocalOnlyIds.remove(serverId);
                }
            }

            List<Long> currentLocalOrder = new ArrayList<>();
            if (currentLocalFilters != null) {
                for (int i = 0; i < currentLocalFilters.size(); i++) {
                    MessagesController.DialogFilter f = currentLocalFilters.get(i);
                    if (f == null) {
                        continue;
                    }
                    long idLong = f.isDefault() ? 0L : (long) f.id;
                    currentLocalOrder.add(idLong);
                    if (idLong != 0L && !serverLongs.contains(idLong)) {
                        state.folderLocalOnlyIds.add(idLong);
                    }
                }
            }

            // Remove stale local-only IDs that no longer exist in currentLocalFilters.
            if (!currentLocalOrder.isEmpty()) {
                state.folderLocalOnlyIds.retainAll(currentLocalOrder);
            }

            List<Long> baseLocalOrder = !state.folderFullOrder.isEmpty() ? state.folderFullOrder : currentLocalOrder;
            List<Long> mergedLongs = RelativeOrderMerger.mergeOrder(
                    serverLongs,
                    baseLocalOrder,
                    state.folderLocalOnlyIds,
                    state.folderAnchors);

            // Include any remaining local filters that were neither in serverLongs nor in localOnlyIds.
            for (Long localId : currentLocalOrder) {
                if (!mergedLongs.contains(localId)) {
                    mergedLongs.add(localId);
                }
            }

            if (!isPremium && mergedLongs.remove(0L)) {
                mergedLongs.add(0, 0L);
            }

            state.folderFullOrder.clear();
            state.folderFullOrder.addAll(mergedLongs);
            state.folderAnchors.clear();
            state.folderAnchors.addAll(RelativeOrderMerger.computeAnchors(state.folderFullOrder, state.folderLocalOnlyIds));
            saveFolderStateLocked(account, state);

            List<Integer> result = new ArrayList<>(mergedLongs.size());
            for (Long id : mergedLongs) {
                result.add(id.intValue());
            }
            return result;
        }
    }

    // =============================================================================================
    // 2. MAIN & ARCHIVE PINNED DIALOGS (folderId = 0 or 1)
    // =============================================================================================

    public static boolean isLocalOnlyPinnedDialog(int account, int folderId, long dialogId) {
        if (DialogObject.isEncryptedDialog(dialogId)) {
            return false;
        }
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData scope = getMainPinScopeLocked(account, state, folderId);
            return scope.localOnlyIds.contains(dialogId);
        }
    }

    public static int getFallbackPinnedNum(int account, int folderId, long dialogId) {
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData scope = getMainPinScopeLocked(account, state, folderId);
            int idx = scope.fullOrder.indexOf(dialogId);
            if (idx >= 0) {
                return Math.max(1, scope.fullOrder.size() - idx);
            }
            return 1;
        }
    }

    public static void markLocalOnlyPinnedDialog(int account, int folderId, long dialogId, boolean localOnly) {
        if (DialogObject.isEncryptedDialog(dialogId)) {
            return;
        }
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData scope = getMainPinScopeLocked(account, state, folderId);
            if (localOnly) {
                scope.localOnlyIds.add(dialogId);
                if (!scope.fullOrder.contains(dialogId)) {
                    scope.fullOrder.add(0, dialogId);
                }
            } else {
                scope.localOnlyIds.remove(dialogId);
            }
            scope.anchors.clear();
            scope.anchors.addAll(RelativeOrderMerger.computeAnchors(scope.fullOrder, scope.localOnlyIds));
            saveMainPinScopeLocked(account, folderId, scope);
        }
    }

    /**
     * Updates local pinned dialog state when a dialog is pinned or unpinned in main/archive list.
     *
     * @return {@code true} if {@code TL_messages_toggleDialogPin} should be sent to the server,
     *         {@code false} if the pin/unpin is strictly local-only (beyond server limit).
     */
    public static boolean onMainDialogPinToggled(
            int account,
            int folderId,
            long dialogId,
            boolean pinned,
            List<Long> currentPinnedTopToBottom,
            boolean isPremium) {
        if (DialogObject.isEncryptedDialog(dialogId)) {
            return false;
        }
        final int serverLimit = getServerMainPinnedLimit(folderId, isPremium);
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData scope = getMainPinScopeLocked(account, state, folderId);

            List<Long> cleanOrder = new ArrayList<>();
            if (currentPinnedTopToBottom != null) {
                for (Long id : currentPinnedTopToBottom) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !cleanOrder.contains(id)) {
                        cleanOrder.add(id);
                    }
                }
            }

            boolean shouldSendToServer;
            if (pinned) {
                if (!cleanOrder.contains(dialogId)) {
                    cleanOrder.add(0, dialogId);
                }
                int existingServerPinnedCount = 0;
                for (Long id : cleanOrder) {
                    if (id != dialogId && !scope.localOnlyIds.contains(id)) {
                        existingServerPinnedCount++;
                    }
                }
                if (existingServerPinnedCount >= serverLimit) {
                    scope.localOnlyIds.add(dialogId);
                    shouldSendToServer = false;
                } else {
                    scope.localOnlyIds.remove(dialogId);
                    shouldSendToServer = true;
                }
            } else {
                cleanOrder.remove(dialogId);
                boolean wasLocalOnly = scope.localOnlyIds.remove(dialogId);
                shouldSendToServer = !wasLocalOnly;
            }

            scope.fullOrder.clear();
            scope.fullOrder.addAll(cleanOrder);
            scope.anchors.clear();
            scope.anchors.addAll(RelativeOrderMerger.computeAnchors(scope.fullOrder, scope.localOnlyIds));
            saveMainPinScopeLocked(account, folderId, scope);
            return shouldSendToServer;
        }
    }

    /**
     * Records the full local pinned dialog order and returns the subset of dialog IDs that should
     * be sent in {@code TL_messages_reorderPinnedDialogs} (excluding local-only pins and capped to
     * the server limit).
     */
    public static Set<Long> recordMainPinnedOrderAndGetServerIds(
            int account,
            int folderId,
            List<Long> fullPinnedTopToBottom,
            boolean isPremium) {
        final int serverLimit = getServerMainPinnedLimit(folderId, isPremium);
        Set<Long> allowedServerIds = new LinkedHashSet<>();
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData scope = getMainPinScopeLocked(account, state, folderId);

            List<Long> cleanOrder = new ArrayList<>();
            if (fullPinnedTopToBottom != null) {
                for (Long id : fullPinnedTopToBottom) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !cleanOrder.contains(id)) {
                        cleanOrder.add(id);
                    }
                }
            }

            scope.localOnlyIds.retainAll(cleanOrder);
            for (Long id : cleanOrder) {
                if (scope.localOnlyIds.contains(id)) {
                    continue;
                }
                if (allowedServerIds.size() < serverLimit) {
                    allowedServerIds.add(id);
                } else {
                    scope.localOnlyIds.add(id);
                }
            }

            scope.fullOrder.clear();
            scope.fullOrder.addAll(cleanOrder);
            scope.anchors.clear();
            scope.anchors.addAll(RelativeOrderMerger.computeAnchors(scope.fullOrder, scope.localOnlyIds));
            saveMainPinScopeLocked(account, folderId, scope);
        }
        return allowedServerIds;
    }

    public static List<Long> mergeMainPinnedDialogsOnSync(
            int account,
            int folderId,
            List<Long> incomingServerPinnedIds,
            List<Long> currentLocalPinnedIds,
            boolean isPremium) {
        final int serverLimit = getServerMainPinnedLimit(folderId, isPremium);
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData scope = getMainPinScopeLocked(account, state, folderId);

            List<Long> serverClean = new ArrayList<>();
            if (incomingServerPinnedIds != null) {
                for (Long id : incomingServerPinnedIds) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !serverClean.contains(id)) {
                        serverClean.add(id);
                    }
                }
            }
            for (Long serverId : serverClean) {
                scope.localOnlyIds.remove(serverId);
            }

            List<Long> localClean = new ArrayList<>();
            if (currentLocalPinnedIds != null) {
                for (Long id : currentLocalPinnedIds) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !localClean.contains(id)) {
                        localClean.add(id);
                    }
                }
            }

            // If existing local pins had > serverLimit items before ForkLocalFoldersAndPinsStore
            // tracked them, automatically adopt overflow items not in serverClean as local-only.
            if (localClean.size() > serverLimit && serverClean.size() >= SERVER_MAIN_PINNED_LIMIT_DEFAULT) {
                for (int i = 0; i < localClean.size(); i++) {
                    Long id = localClean.get(i);
                    if (!serverClean.contains(id) && i >= SERVER_MAIN_PINNED_LIMIT_DEFAULT) {
                        scope.localOnlyIds.add(id);
                    }
                }
            }

            List<Long> baseLocal = !scope.fullOrder.isEmpty() ? scope.fullOrder : localClean;
            List<Long> merged = RelativeOrderMerger.mergeOrder(
                    serverClean,
                    baseLocal,
                    scope.localOnlyIds,
                    scope.anchors);

            scope.fullOrder.clear();
            scope.fullOrder.addAll(merged);
            scope.anchors.clear();
            scope.anchors.addAll(RelativeOrderMerger.computeAnchors(scope.fullOrder, scope.localOnlyIds));
            saveMainPinScopeLocked(account, folderId, scope);
            return merged;
        }
    }

    // =============================================================================================
    // 3. PER-FOLDER PINNED & INCLUDED PEERS (DialogFilter)
    // =============================================================================================

    public static void recordLocalFilterPeers(
            int account,
            int filterId,
            List<Long> orderedPinnedIds,
            List<Long> alwaysShowIds,
            boolean isPremium) {
        if (filterId == 0) {
            return;
        }
        final int serverLimit = getServerFilterPeersLimit(isPremium);
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData pinScope = getFilterPinScopeLocked(account, state, filterId);
            ScopeData incScope = getFilterIncScopeLocked(account, state, filterId);

            List<Long> cleanPins = new ArrayList<>();
            if (orderedPinnedIds != null) {
                for (Long id : orderedPinnedIds) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !cleanPins.contains(id)) {
                        cleanPins.add(id);
                    }
                }
            }

            pinScope.localOnlyIds.retainAll(cleanPins);
            int serverBudgetUsed = 0;
            for (Long id : cleanPins) {
                if (pinScope.localOnlyIds.contains(id)) {
                    continue;
                }
                if (serverBudgetUsed < serverLimit) {
                    serverBudgetUsed++;
                } else {
                    pinScope.localOnlyIds.add(id);
                }
            }
            pinScope.fullOrder.clear();
            pinScope.fullOrder.addAll(cleanPins);
            pinScope.anchors.clear();
            pinScope.anchors.addAll(RelativeOrderMerger.computeAnchors(pinScope.fullOrder, pinScope.localOnlyIds));

            List<Long> cleanInc = new ArrayList<>();
            if (alwaysShowIds != null) {
                for (Long id : alwaysShowIds) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !cleanInc.contains(id)) {
                        cleanInc.add(id);
                    }
                }
            }
            incScope.localOnlyIds.retainAll(cleanInc);
            for (Long pinLocalId : pinScope.localOnlyIds) {
                if (cleanInc.contains(pinLocalId)) {
                    incScope.localOnlyIds.add(pinLocalId);
                }
            }
            for (Long id : cleanInc) {
                if (cleanPins.contains(id) || incScope.localOnlyIds.contains(id)) {
                    continue;
                }
                if (serverBudgetUsed < serverLimit) {
                    serverBudgetUsed++;
                } else {
                    incScope.localOnlyIds.add(id);
                }
            }
            incScope.fullOrder.clear();
            incScope.fullOrder.addAll(cleanInc);
            incScope.anchors.clear();
            incScope.anchors.addAll(RelativeOrderMerger.computeAnchors(incScope.fullOrder, incScope.localOnlyIds));

            saveFilterScopesLocked(account, filterId, pinScope, incScope);
        }
    }

    public static boolean isLocalOnlyFilterPinnedPeer(int account, int filterId, long peerId) {
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData pinScope = getFilterPinScopeLocked(account, state, filterId);
            return pinScope.localOnlyIds.contains(peerId);
        }
    }

    public static boolean isLocalOnlyFilterIncludedPeer(int account, int filterId, long peerId) {
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData incScope = getFilterIncScopeLocked(account, state, filterId);
            return incScope.localOnlyIds.contains(peerId);
        }
    }

    public static List<Long> mergeFilterPinnedPeersOnSync(
            int account,
            int filterId,
            List<Long> incomingServerPinnedIds,
            List<Long> currentLocalPinnedIds) {
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData pinScope = getFilterPinScopeLocked(account, state, filterId);

            List<Long> serverClean = new ArrayList<>();
            if (incomingServerPinnedIds != null) {
                for (Long id : incomingServerPinnedIds) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !serverClean.contains(id)) {
                        serverClean.add(id);
                        pinScope.localOnlyIds.remove(id);
                    }
                }
            }
            List<Long> localClean = new ArrayList<>();
            if (currentLocalPinnedIds != null) {
                for (Long id : currentLocalPinnedIds) {
                    if (id != null && !DialogObject.isEncryptedDialog(id) && !localClean.contains(id)) {
                        localClean.add(id);
                    }
                }
            }
            List<Long> baseLocal = !pinScope.fullOrder.isEmpty() ? pinScope.fullOrder : localClean;
            List<Long> merged = RelativeOrderMerger.mergeOrder(
                    serverClean,
                    baseLocal,
                    pinScope.localOnlyIds,
                    pinScope.anchors);
            pinScope.fullOrder.clear();
            pinScope.fullOrder.addAll(merged);
            pinScope.anchors.clear();
            pinScope.anchors.addAll(RelativeOrderMerger.computeAnchors(pinScope.fullOrder, pinScope.localOnlyIds));
            ScopeData incScope = getFilterIncScopeLocked(account, state, filterId);
            saveFilterScopesLocked(account, filterId, pinScope, incScope);
            return merged;
        }
    }

    public static ArrayList<Long> mergeFilterAlwaysShowOnSync(
            int account,
            int filterId,
            List<Long> incomingServerAlwaysShowIds,
            List<Long> currentLocalAlwaysShowIds) {
        synchronized (LOCK) {
            AccountState state = getStateLocked(account);
            ScopeData pinScope = getFilterPinScopeLocked(account, state, filterId);
            ScopeData incScope = getFilterIncScopeLocked(account, state, filterId);

            List<Long> serverClean = new ArrayList<>();
            if (incomingServerAlwaysShowIds != null) {
                for (Long id : incomingServerAlwaysShowIds) {
                    if (id != null && !serverClean.contains(id)) {
                        serverClean.add(id);
                        incScope.localOnlyIds.remove(id);
                    }
                }
            }
            for (Long localPinId : pinScope.localOnlyIds) {
                incScope.localOnlyIds.add(localPinId);
            }
            List<Long> baseLocal = !incScope.fullOrder.isEmpty() ? incScope.fullOrder : currentLocalAlwaysShowIds;
            List<Long> merged = RelativeOrderMerger.mergeOrder(
                    serverClean,
                    baseLocal,
                    incScope.localOnlyIds,
                    incScope.anchors);
            incScope.fullOrder.clear();
            incScope.fullOrder.addAll(merged);
            incScope.anchors.clear();
            incScope.anchors.addAll(RelativeOrderMerger.computeAnchors(incScope.fullOrder, incScope.localOnlyIds));
            saveFilterScopesLocked(account, filterId, pinScope, incScope);
            return new ArrayList<>(merged);
        }
    }

    // =============================================================================================
    // SERIALIZATION HELPERS
    // =============================================================================================

    private static Set<Long> parseLongSet(String raw) {
        Set<Long> set = new HashSet<>();
        if (TextUtils.isEmpty(raw)) {
            return set;
        }
        String[] parts = raw.split(",");
        for (String p : parts) {
            if (!TextUtils.isEmpty(p)) {
                try {
                    set.add(Long.parseLong(p.trim()));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return set;
    }

    private static List<Long> parseLongList(String raw) {
        List<Long> list = new ArrayList<>();
        if (TextUtils.isEmpty(raw)) {
            return list;
        }
        String[] parts = raw.split(",");
        for (String p : parts) {
            if (!TextUtils.isEmpty(p)) {
                try {
                    list.add(Long.parseLong(p.trim()));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return list;
    }

    private static String serializeLongCollection(Iterable<Long> values) {
        if (values == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Long v : values) {
            if (v == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(',');
            }
            sb.append(v.longValue());
        }
        return sb.toString();
    }

    private static List<RelativeOrderMerger.Anchor> parseAnchors(String raw) {
        if (TextUtils.isEmpty(raw)) {
            return Collections.emptyList();
        }
        List<RelativeOrderMerger.Anchor> list = new ArrayList<>();
        String[] entries = raw.split(";");
        for (String entry : entries) {
            if (TextUtils.isEmpty(entry)) {
                continue;
            }
            String[] fields = entry.split(":");
            if (fields.length != 4) {
                continue;
            }
            try {
                long itemId = Long.parseLong(fields[0]);
                Long afterId = "_".equals(fields[1]) ? null : Long.parseLong(fields[1]);
                Long beforeId = "_".equals(fields[2]) ? null : Long.parseLong(fields[2]);
                int fallbackIdx = Integer.parseInt(fields[3]);
                list.add(new RelativeOrderMerger.Anchor(itemId, afterId, beforeId, fallbackIdx));
            } catch (NumberFormatException ignored) {
            }
        }
        return list;
    }

    private static String serializeAnchors(List<RelativeOrderMerger.Anchor> anchors) {
        if (anchors == null || anchors.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (RelativeOrderMerger.Anchor a : anchors) {
            if (a == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append(';');
            }
            sb.append(a.itemId)
                    .append(':')
                    .append(a.afterServerId != null ? a.afterServerId.toString() : "_")
                    .append(':')
                    .append(a.beforeServerId != null ? a.beforeServerId.toString() : "_")
                    .append(':')
                    .append(a.fallbackIndex);
        }
        return sb.toString();
    }
}
