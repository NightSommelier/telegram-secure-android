package org.telegram.secureoverlay;

import android.content.Context;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keystore-backed local pin store binding Saved Messages records to positive Telegram message IDs
 * to prevent server-side message duplication, cross-message splicing, and edit rollback (SA-20).
 */
public final class SecureSavedMessagesPinStore {
    static final String ROOT_PREFIX = "saved-pin-v1/account/";
    private static final byte ENTRY_FORMAT_VERSION = 1;
    private static final int MAX_RETIRED_IDS = 128;
    private static final Object LOCK = new Object();
    private static final ConcurrentHashMap<String, PinEntry> SHARED_MSG_CACHE =
            new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Integer> SHARED_REC_CACHE =
            new ConcurrentHashMap<>();

    private final KeystoreSignalProtocolStore.EncryptedStateStorage storage;
    private final byte[] maskKey;
    private final Map<String, PinEntry> msgCache;
    private final Map<String, Integer> recCache;

    public SecureSavedMessagesPinStore(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context is required for Saved Messages pin store");
        }
        Context app = context.getApplicationContext();
        this.storage = new KeystoreEncryptedBlobStore(app != null ? app : context);
        this.maskKey = SecureNameMask.getOrGenerateKey(this.storage);
        if (this.storage instanceof KeystoreEncryptedBlobStore
                && ((KeystoreEncryptedBlobStore) this.storage).isPersistent()) {
            this.msgCache = SHARED_MSG_CACHE;
            this.recCache = SHARED_REC_CACHE;
        } else {
            this.msgCache = new ConcurrentHashMap<>();
            this.recCache = new ConcurrentHashMap<>();
        }
    }

    SecureSavedMessagesPinStore(KeystoreSignalProtocolStore.EncryptedStateStorage storage) {
        if (storage == null) {
            throw new IllegalArgumentException("storage is required for Saved Messages pin store");
        }
        this.storage = storage;
        this.maskKey = SecureNameMask.getOrGenerateKey(storage);
        if (storage instanceof KeystoreEncryptedBlobStore
                && ((KeystoreEncryptedBlobStore) storage).isPersistent()) {
            this.msgCache = SHARED_MSG_CACHE;
            this.recCache = SHARED_REC_CACHE;
        } else {
            this.msgCache = new ConcurrentHashMap<>();
            this.recCache = new ConcurrentHashMap<>();
        }
    }

    public static void clearMemoryCache() {
        SHARED_MSG_CACHE.clear();
        SHARED_REC_CACHE.clear();
    }

    static void evictAccountFromCache(int account) {
        if (account < 0) {
            return;
        }
        String prefix = accountRoot(account) + "/";
        SHARED_MSG_CACHE.keySet().removeIf(k -> k.startsWith(prefix));
        SHARED_REC_CACHE.keySet().removeIf(k -> k.startsWith(prefix));
    }

    public boolean isAlreadyPinnedInMemory(
            int account, int messageId, int recordVersion, long recordId) {
        if (account < 0) {
            return false;
        }
        if (messageId <= 0 || recordVersion < 2) {
            return true;
        }
        String recName = recordKey(account, recordId);
        Integer cachedMsgId = recCache.get(recName);
        if (cachedMsgId == null || cachedMsgId != messageId) {
            return false;
        }
        PinEntry cachedEntry = msgCache.get(messageKey(account, messageId));
        return cachedEntry != null && cachedEntry.currentRecordId == recordId;
    }

    static String accountRoot(int account) {
        requireAccount(account);
        return ROOT_PREFIX + account;
    }

    void verifyAndPinAuthenticated(
            int account, int messageId, int recordVersion, long recordId, int targetMessageId) {
        requireAccount(account);
        if (messageId <= 0) {
            if (recordVersion == 3) {
                throw new IllegalArgumentException(
                        "Saved Messages edit record requires positive message ID");
            }
            return;
        }
        if (recordVersion < 2) {
            return;
        }
        if (recordVersion == 3 && targetMessageId != messageId) {
            throw new IllegalArgumentException(
                    "Saved Messages edit record bound to different message ID");
        }
        String recName = recordKey(account, recordId);
        String msgName = messageKey(account, messageId);
        Integer fastBoundId = recCache.get(recName);
        PinEntry fastEntry = msgCache.get(msgName);
        if (fastBoundId != null && fastBoundId == messageId
                && fastEntry != null && fastEntry.currentRecordId == recordId) {
            return;
        }
        synchronized (LOCK) {
            try {
                Integer cachedBoundId = recCache.get(recName);
                boolean hadRec = cachedBoundId != null;
                if (cachedBoundId != null) {
                    if (cachedBoundId != messageId) {
                        throw new IllegalArgumentException(
                                "Saved Messages record duplicated to another message ID");
                    }
                } else {
                    byte[] existingRec = storage.get(recName);
                    if (existingRec != null) {
                        hadRec = true;
                        int boundMessageId = decodeBoundMessageId(existingRec);
                        recCache.put(recName, boundMessageId);
                        if (boundMessageId != messageId) {
                            throw new IllegalArgumentException(
                                    "Saved Messages record duplicated to another message ID");
                        }
                    }
                }

                PinEntry current = msgCache.get(msgName);
                if (current == null) {
                    byte[] existingMsg = storage.get(msgName);
                    if (existingMsg == null) {
                        PinEntry initial = new PinEntry(
                                recordVersion, recordId, Collections.emptyList());
                        storage.put(msgName, encodePinEntry(initial));
                        storage.put(recName, encodeBoundMessageId(messageId));
                        msgCache.put(msgName, initial);
                        recCache.put(recName, messageId);
                        return;
                    }
                    current = decodePinEntry(existingMsg);
                    msgCache.put(msgName, current);
                }

                if (current.currentRecordId == recordId) {
                    if (!hadRec) {
                        storage.put(recName, encodeBoundMessageId(messageId));
                        recCache.put(recName, messageId);
                    }
                    return;
                }

                if (current.retiredRecordIds.contains(recordId)) {
                    throw new IllegalArgumentException("Saved Messages edit rollback detected");
                }
                if (recordVersion != 3 || targetMessageId != messageId) {
                    throw new IllegalArgumentException(
                            "Saved Messages unedited record cannot overwrite pinned message");
                }
                if (current.currentVersion == 3 && recordId <= current.currentRecordId) {
                    throw new IllegalArgumentException("Saved Messages edit rollback detected");
                }

                List<Long> updatedRetired = new ArrayList<>(current.retiredRecordIds.size() + 1);
                updatedRetired.addAll(current.retiredRecordIds);
                updatedRetired.add(current.currentRecordId);
                if (updatedRetired.size() > MAX_RETIRED_IDS) {
                    updatedRetired = new ArrayList<>(updatedRetired.subList(
                            updatedRetired.size() - MAX_RETIRED_IDS, updatedRetired.size()));
                }
                PinEntry next = new PinEntry(recordVersion, recordId, updatedRetired);
                storage.put(msgName, encodePinEntry(next));
                storage.put(recName, encodeBoundMessageId(messageId));
                msgCache.put(msgName, next);
                recCache.put(recName, messageId);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException("Saved Messages pin store failure", e);
            }
        }
    }

    public void clearForAccount(int account) {
        requireAccount(account);
        synchronized (LOCK) {
            try {
                String prefix = accountRoot(account) + "/";
                msgCache.keySet().removeIf(k -> k.startsWith(prefix));
                recCache.keySet().removeIf(k -> k.startsWith(prefix));
                storage.deleteRoots(accountRoot(account));
            } catch (Exception e) {
                throw new IllegalStateException("cannot clear Saved Messages pin store", e);
            }
        }
    }

    private String messageKey(int account, int messageId) {
        return accountRoot(account) + "/msg/"
                + SecureNameMask.mask(maskKey, "saved-msg:" + account + ":" + messageId);
    }

    private String recordKey(int account, long recordId) {
        return accountRoot(account) + "/rec/"
                + SecureNameMask.mask(maskKey, "saved-rec:" + account + ":" + recordId);
    }

    private static byte[] encodeBoundMessageId(int messageId) {
        return ByteBuffer.allocate(5)
                .order(ByteOrder.BIG_ENDIAN)
                .put(ENTRY_FORMAT_VERSION)
                .putInt(messageId)
                .array();
    }

    private static int decodeBoundMessageId(byte[] bytes) {
        if (bytes == null || bytes.length != 5) {
            throw new IllegalStateException("corrupted Saved Messages reverse pin");
        }
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        byte format = buf.get();
        if (format != ENTRY_FORMAT_VERSION) {
            throw new IllegalStateException("unsupported Saved Messages reverse pin version");
        }
        int id = buf.getInt();
        if (id <= 0) {
            throw new IllegalStateException("invalid Saved Messages reverse pin message ID");
        }
        return id;
    }

    private static byte[] encodePinEntry(PinEntry entry) {
        int count = entry.retiredRecordIds.size();
        ByteBuffer buf = ByteBuffer.allocate(1 + 1 + 8 + 4 + count * 8)
                .order(ByteOrder.BIG_ENDIAN);
        buf.put(ENTRY_FORMAT_VERSION);
        buf.put((byte) entry.currentVersion);
        buf.putLong(entry.currentRecordId);
        buf.putInt(count);
        for (int i = 0; i < count; i++) {
            buf.putLong(entry.retiredRecordIds.get(i));
        }
        return buf.array();
    }

    private static PinEntry decodePinEntry(byte[] bytes) {
        if (bytes == null || bytes.length < 14) {
            throw new IllegalStateException("corrupted Saved Messages forward pin");
        }
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
        byte format = buf.get();
        if (format != ENTRY_FORMAT_VERSION) {
            throw new IllegalStateException("unsupported Saved Messages forward pin version");
        }
        int currentVersion = buf.get() & 0xff;
        long currentRecordId = buf.getLong();
        int count = buf.getInt();
        if (count < 0 || count > MAX_RETIRED_IDS || buf.remaining() != count * 8) {
            throw new IllegalStateException("corrupted Saved Messages retired pin list");
        }
        List<Long> retired = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            retired.add(buf.getLong());
        }
        return new PinEntry(currentVersion, currentRecordId, retired);
    }

    private static void requireAccount(int account) {
        if (account < 0) {
            throw new IllegalArgumentException("account must be non-negative");
        }
    }

    private static final class PinEntry {
        final int currentVersion;
        final long currentRecordId;
        final List<Long> retiredRecordIds;

        PinEntry(int currentVersion, long currentRecordId, List<Long> retiredRecordIds) {
            this.currentVersion = currentVersion;
            this.currentRecordId = currentRecordId;
            this.retiredRecordIds = retiredRecordIds;
        }
    }
}
