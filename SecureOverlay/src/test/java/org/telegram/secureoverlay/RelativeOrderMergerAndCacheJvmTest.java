package org.telegram.secureoverlay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class RelativeOrderMergerAndCacheJvmTest {

    private static final class MapStateStorage implements KeystoreSignalProtocolStore.EncryptedStateStorage {
        private final Map<String, byte[]> map = new HashMap<>();

        @Override
        public byte[] get(String name) {
            byte[] val = map.get(name);
            return val != null ? val.clone() : null;
        }

        @Override
        public void put(String name, byte[] data) {
            map.put(name, data != null ? data.clone() : null);
        }

        @Override
        public void delete(String name) {
            map.remove(name);
        }

        @Override
        public void deleteRoots(String... roots) {
            for (String root : roots) {
                map.keySet().removeIf(k -> k.startsWith(root));
            }
        }

        @Override
        public void replaceRoots(Map<String, byte[]> replacements, String... roots) {
            deleteRoots(roots);
            if (replacements != null) {
                for (Map.Entry<String, byte[]> entry : replacements.entrySet()) {
                    put(entry.getKey(), entry.getValue());
                }
            }
        }

        @Override
        public boolean hasNameStartingWith(String... prefixes) {
            for (String k : map.keySet()) {
                for (String p : prefixes) {
                    if (k.startsWith(p)) {
                        return true;
                    }
                }
            }
            return false;
        }

        @Override
        public Map<String, byte[]> snapshotPrefixes(String... prefixes) {
            Map<String, byte[]> out = new HashMap<>();
            for (Map.Entry<String, byte[]> entry : map.entrySet()) {
                for (String p : prefixes) {
                    if (entry.getKey().startsWith(p)) {
                        out.put(entry.getKey(), entry.getValue().clone());
                        break;
                    }
                }
            }
            return out;
        }
    }

    @Before
    public void setUp() {
        SecureSavedMessagesKeyStore.clearMemoryCache();
        SecureSavedMessagesPinStore.clearMemoryCache();
        SecureLocalTextStore.clearMemoryCache();
    }

    @Test
    public void relativeOrderMerger_preservesLocalItemsAndFollowsDesktopReorder() {
        // Local order has 3 server folders (1, 2, 3) and 2 local-only folders (101 after 2, 102 after 3)
        List<Long> localFullOrder = Arrays.asList(0L, 1L, 2L, 101L, 3L, 102L);
        Set<Long> localOnlyIds = new HashSet<>(Arrays.asList(101L, 102L));

        List<RelativeOrderMerger.Anchor> anchors =
                RelativeOrderMerger.computeAnchors(localFullOrder, localOnlyIds);
        assertEquals(2, anchors.size());
        assertEquals(new RelativeOrderMerger.Anchor(101L, 2L, 3L, 3), anchors.get(0));
        assertEquals(new RelativeOrderMerger.Anchor(102L, 3L, null, 5), anchors.get(1));

        // Desktop reorders server folders from [0, 1, 2, 3] to [0, 3, 2, 1]:
        // 102 should move with 3, and 101 should stay right after 2!
        List<Long> incomingServerOrder = Arrays.asList(0L, 3L, 2L, 1L);
        List<Long> merged = RelativeOrderMerger.mergeOrder(
                incomingServerOrder,
                localFullOrder,
                localOnlyIds,
                anchors);

        assertEquals(Arrays.asList(0L, 3L, 102L, 2L, 101L, 1L), merged);
    }

    @Test
    public void relativeOrderMerger_preservesChainedLocalItemsWhenAnchorMoves() {
        // Two consecutive local-only pinned chats (201, 202) anchored after server pin 10
        List<Long> localFullOrder = Arrays.asList(10L, 201L, 202L, 20L, 30L);
        Set<Long> localOnlyIds = new HashSet<>(Arrays.asList(201L, 202L));

        List<RelativeOrderMerger.Anchor> anchors =
                RelativeOrderMerger.computeAnchors(localFullOrder, localOnlyIds);

        // Server reorders [10, 20, 30] -> [20, 30, 10]
        List<Long> merged = RelativeOrderMerger.mergeOrder(
                Arrays.asList(20L, 30L, 10L),
                localFullOrder,
                localOnlyIds,
                anchors);

        assertEquals(Arrays.asList(20L, 30L, 10L, 201L, 202L), merged);
    }

    @Test
    public void relativeOrderMerger_handlesLeadingLocalItemsAndDeletedAfterAnchor() {
        // Local order: [501 (local at head), 10, 502 (local between 10 and 20), 20, 30]
        List<Long> localFullOrder = Arrays.asList(501L, 10L, 502L, 20L, 30L);
        Set<Long> localOnlyIds = new HashSet<>(Arrays.asList(501L, 502L));
        List<RelativeOrderMerger.Anchor> anchors =
                RelativeOrderMerger.computeAnchors(localFullOrder, localOnlyIds);

        // Suppose server deletes item 10 -> incomingServerOrder is [20, 30].
        // 501 had beforeServerId=10 (deleted), so it falls back to index 0;
        // 502 had afterServerId=10 (deleted) and beforeServerId=20 (present!), so 502 anchors before 20.
        List<Long> merged = RelativeOrderMerger.mergeOrder(
                Arrays.asList(20L, 30L),
                localFullOrder,
                localOnlyIds,
                anchors);

        assertEquals(Arrays.asList(501L, 502L, 20L, 30L), merged);
    }

    @Test
    public void relativeOrderMerger_promotesItemWhenServerIncludesIt() {
        List<Long> localFullOrder = Arrays.asList(1L, 2L, 99L);
        Set<Long> localOnlyIds = new HashSet<>(Collections.singletonList(99L));
        List<RelativeOrderMerger.Anchor> anchors =
                RelativeOrderMerger.computeAnchors(localFullOrder, localOnlyIds);

        List<Long> merged = RelativeOrderMerger.mergeOrder(
                Arrays.asList(99L, 1L, 2L),
                localFullOrder,
                localOnlyIds,
                anchors);

        assertEquals(Arrays.asList(99L, 1L, 2L), merged);
    }

    @Test
    public void savedMessagesPinStore_cachesInMemoryAndEnforcesAntiRollback() {
        MapStateStorage storage = new MapStateStorage();
        SecureSavedMessagesPinStore pinStore = new SecureSavedMessagesPinStore(storage);
        long recId1 = 0x1122334455667788L;
        long recId2 = 0x2233445566778899L;

        assertFalse(pinStore.isAlreadyPinnedInMemory(0, 1001, 2, recId1));
        pinStore.verifyAndPinAuthenticated(0, 1001, 2, recId1, 0);
        assertTrue(pinStore.isAlreadyPinnedInMemory(0, 1001, 2, recId1));

        // Re-verifying the exact same pair succeeds from RAM without error.
        pinStore.verifyAndPinAuthenticated(0, 1001, 2, recId1, 0);

        // Reusing recId1 on a different message ID must fail closed (SA-20).
        try {
            pinStore.verifyAndPinAuthenticated(0, 1002, 2, recId1, 0);
            fail("Expected IllegalArgumentException for duplicate recordId across messages");
        } catch (IllegalArgumentException expected) {
            // expected
        }

        // Switching message 1001 to a different recordId without an edit record must also fail closed (SA-20).
        try {
            pinStore.verifyAndPinAuthenticated(0, 1001, 2, recId2, 0);
            fail("Expected IllegalArgumentException for message recordId rollback");
        } catch (IllegalArgumentException expected) {
            // expected
        }
    }
}
