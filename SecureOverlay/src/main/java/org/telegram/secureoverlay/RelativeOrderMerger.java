package org.telegram.secureoverlay;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Pure relative-anchor order merger used to preserve local-only folders and over-limit pinned
 * dialogs across server syncs while still honoring server-side reorders from other clients.
 */
public final class RelativeOrderMerger {

    public static final class Anchor {
        public final long itemId;
        public final Long afterServerId;
        public final Long beforeServerId;
        public final int fallbackIndex;

        public Anchor(long itemId, Long afterServerId, Long beforeServerId, int fallbackIndex) {
            this.itemId = itemId;
            this.afterServerId = afterServerId;
            this.beforeServerId = beforeServerId;
            this.fallbackIndex = Math.max(0, fallbackIndex);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Anchor)) {
                return false;
            }
            Anchor that = (Anchor) o;
            return itemId == that.itemId
                    && fallbackIndex == that.fallbackIndex
                    && Objects.equals(afterServerId, that.afterServerId)
                    && Objects.equals(beforeServerId, that.beforeServerId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(itemId, afterServerId, beforeServerId, fallbackIndex);
        }
    }

    private RelativeOrderMerger() {
    }

    /**
     * Computes relative anchors for each item in {@code localFullOrder} that belongs to
     * {@code localOnlyIds}, linking it to its nearest preceding and following server-synced items.
     */
    public static List<Anchor> computeAnchors(List<Long> localFullOrder, Set<Long> localOnlyIds) {
        if (localFullOrder == null || localFullOrder.isEmpty() || localOnlyIds == null || localOnlyIds.isEmpty()) {
            return Collections.emptyList();
        }
        List<Anchor> anchors = new ArrayList<>();
        final int size = localFullOrder.size();
        for (int i = 0; i < size; i++) {
            Long idObj = localFullOrder.get(i);
            if (idObj == null || !localOnlyIds.contains(idObj)) {
                continue;
            }
            Long afterServerId = null;
            for (int prev = i - 1; prev >= 0; prev--) {
                Long candidate = localFullOrder.get(prev);
                if (candidate != null && !localOnlyIds.contains(candidate)) {
                    afterServerId = candidate;
                    break;
                }
            }
            Long beforeServerId = null;
            for (int next = i + 1; next < size; next++) {
                Long candidate = localFullOrder.get(next);
                if (candidate != null && !localOnlyIds.contains(candidate)) {
                    beforeServerId = candidate;
                    break;
                }
            }
            anchors.add(new Anchor(idObj, afterServerId, beforeServerId, i));
        }
        return anchors;
    }

    /**
     * Merges an incoming authoritative server sequence with local-only items using their relative
     * neighbor anchors.
     *
     * @param incomingServerOrder Authoritative order of server-backed items from Telegram server.
     * @param localFullOrder      Current local order before sync (optional, used if savedAnchors is empty).
     * @param localOnlyIds        Set of item IDs that exist only locally (e.g., over server limits).
     * @param savedAnchors        Previously computed relative anchors for localOnlyIds.
     * @return Merged deduplicated sequence containing all incomingServerOrder items in server order
     *         plus all active localOnlyIds anchored beside their relative neighbors.
     */
    public static List<Long> mergeOrder(
            List<Long> incomingServerOrder,
            List<Long> localFullOrder,
            Set<Long> localOnlyIds,
            List<Anchor> savedAnchors) {
        LinkedHashSet<Long> dedupServer = new LinkedHashSet<>();
        if (incomingServerOrder != null) {
            for (Long id : incomingServerOrder) {
                if (id != null) {
                    dedupServer.add(id);
                }
            }
        }
        List<Long> result = new ArrayList<>(dedupServer);
        if (localOnlyIds == null || localOnlyIds.isEmpty()) {
            return result;
        }

        // Any item now present on the server is no longer local-only.
        Set<Long> effectiveLocalOnly = new HashSet<>(localOnlyIds);
        effectiveLocalOnly.removeAll(dedupServer);
        if (effectiveLocalOnly.isEmpty()) {
            return result;
        }

        List<Anchor> anchorsToUse;
        if (savedAnchors != null && !savedAnchors.isEmpty()) {
            anchorsToUse = new ArrayList<>();
            Set<Long> covered = new HashSet<>();
            for (Anchor anchor : savedAnchors) {
                if (anchor != null && effectiveLocalOnly.contains(anchor.itemId) && covered.add(anchor.itemId)) {
                    anchorsToUse.add(anchor);
                }
            }
            if (covered.size() < effectiveLocalOnly.size() && localFullOrder != null) {
                for (Anchor computed : computeAnchors(localFullOrder, effectiveLocalOnly)) {
                    if (covered.add(computed.itemId)) {
                        anchorsToUse.add(computed);
                    }
                }
            }
        } else {
            anchorsToUse = computeAnchors(localFullOrder, effectiveLocalOnly);
        }

        // Also cover any local-only IDs missing from both savedAnchors and localFullOrder.
        Set<Long> scheduled = new HashSet<>();
        for (Anchor anchor : anchorsToUse) {
            scheduled.add(anchor.itemId);
        }
        if (localFullOrder != null) {
            for (int i = 0; i < localFullOrder.size(); i++) {
                Long id = localFullOrder.get(i);
                if (id != null && effectiveLocalOnly.contains(id) && scheduled.add(id)) {
                    anchorsToUse.add(new Anchor(id, null, null, i));
                }
            }
        }

        Map<Long, Long> chainTailByAfterAnchor = new HashMap<>();
        for (Anchor anchor : anchorsToUse) {
            long itemId = anchor.itemId;
            if (result.contains(itemId)) {
                continue;
            }
            boolean inserted = false;
            if (anchor.afterServerId != null) {
                Long chainTail = chainTailByAfterAnchor.getOrDefault(anchor.afterServerId, anchor.afterServerId);
                int idx = result.indexOf(chainTail);
                if (idx < 0 && !chainTail.equals(anchor.afterServerId)) {
                    idx = result.indexOf(anchor.afterServerId);
                }
                if (idx >= 0) {
                    result.add(idx + 1, itemId);
                    chainTailByAfterAnchor.put(anchor.afterServerId, itemId);
                    inserted = true;
                }
            }
            if (!inserted && anchor.beforeServerId != null) {
                int idx = result.indexOf(anchor.beforeServerId);
                if (idx >= 0) {
                    result.add(idx, itemId);
                    inserted = true;
                }
            }
            if (!inserted) {
                int clampedIndex = Math.max(0, Math.min(anchor.fallbackIndex, result.size()));
                result.add(clampedIndex, itemId);
            }
        }
        return result;
    }
}
