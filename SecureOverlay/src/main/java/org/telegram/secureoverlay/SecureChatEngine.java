package org.telegram.secureoverlay;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Build;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.impl.InMemorySignalProtocolStore;

/**
 * Private-chat secure-text boundary for the MVP.
 *
 * <p>It intentionally handles only Telegram transport text and only positive user IDs. A recognized
 * secure carrier either decrypts completely or raises an error; callers must never render its ciphertext
 * as plaintext. Media, groups, calls, and account migration are outside this MVP.</p>
 */
public final class SecureChatEngine {
    private static final String PAIRING_ACK_PLAINTEXT =
            "\u0000fork-secure-control:pairing-ack:v1";
    private static final String PAIRING_ACK_DISPLAY =
            "\u0000fork-secure-display:pairing-ack:v1";
    private static final String PAIRING_READY_PLAINTEXT =
            "\u0000fork-secure-control:pairing-ready:v1";
    private static final String PAIRING_READY_DISPLAY =
            "\u0000fork-secure-display:pairing-ready:v1";
    private static final String PAIRING_REJECTED_PLAINTEXT =
            "\u0000fork-secure-control:pairing-rejected:v1";
    private static final String PAIRING_REJECTED_DISPLAY =
            "\u0000fork-secure-display:pairing-rejected:v1";
    private static final String STATIC_STICKER_DISPLAY =
            "\u0000fork-secure-display:static-sticker:v1";
    private static final String FILE_DISPLAY =
            "\u0000fork-secure-display:file:v1";
    private static final String PHOTO_DISPLAY =
            "\u0000fork-secure-display:photo:v1";
    public static final String CONTROL_DELETE_DISPLAY =
            "\u0000fork-secure-display:control-delete:v1";
    public static final String CONTACT_DISPLAY =
            "\u0000fork-secure-display:contact:v1";
    public static final String LOCATION_DISPLAY =
            "\u0000fork-secure-display:location:v1";
    public static final String GROUP_KEY_DISTRIBUTED_DISPLAY =
            "\u0000fork-secure-display:group-key-distributed:v1";
    public static final String GROUP_KEY_RECEIVED_DISPLAY =
            "\u0000fork-secure-display:group-key-received:v1";
    public static final String DUPLICATE_MESSAGE_DISPLAY =
            "\u0000fork-secure-display:duplicate-message:v1";
    private static final Object SESSION_LOCK = KeystoreSignalProtocolStore.PROTOCOL_STATE_LOCK;
    private static final long FAILED_DECRYPT_TTL_MS = 10 * 60 * 1000L; // 10 minutes
    private static final int FAILED_DECRYPT_CACHE_LIMIT = 512;

    private static final class FailedDecryptEntry {
        final long timestamp;
        FailedDecryptEntry(long timestamp) {
            this.timestamp = timestamp;
        }
    }

    private static final java.util.LinkedHashMap<String, FailedDecryptEntry> failedDecryptCarriers =
            new java.util.LinkedHashMap<String, FailedDecryptEntry>(FAILED_DECRYPT_CACHE_LIMIT, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(java.util.Map.Entry<String, FailedDecryptEntry> eldest) {
                    return size() > FAILED_DECRYPT_CACHE_LIMIT;
                }
            };

    static String failedDecryptKey(int account, long peerUserId, String carrier) {
        if (carrier == null) {
            return account + ":" + peerUserId + ":null";
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(carrier.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(account + ":" + peerUserId + ":");
            for (byte b : digest) {
                sb.append(Character.forDigit((b >>> 4) & 0x0f, 16));
                sb.append(Character.forDigit(b & 0x0f, 16));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new AssertionError("SHA-256 is unavailable", e);
        }
    }

    /**
     * The protocol-state key is intentionally unavailable while Android considers the device
     * locked. Callers must defer cryptographic work instead of treating that expected condition as
     * corrupt state.
     */
    public static boolean isStateTemporarilyUnavailable(Context context) {
        if (context == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false;
        }
        KeyguardManager keyguard =
                (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        return keyguard != null && keyguard.isDeviceLocked();
    }

    /**
     * Checks whether a direct peer has persisted secure state without opening Android Keystore or
     * a Signal session. Chat UI uses this to avoid spending work on ordinary conversations.
     */
    public static boolean hasLocalState(Context context, int account, long peerUserId) {
        if (context == null || account < 0 || peerUserId == 0) {
            return false;
        }
        Boolean peeked = SecureChatState.peekHasStateForPeer(account, peerUserId);
        if (peeked != null) {
            return peeked;
        }
        return new SecureChatState(context.getApplicationContext())
                .hasStateForPeer(account, peerUserId);
    }

    public static final class CachedText {
        public static final int STATE_HIT = 0;
        public static final int STATE_NEGATIVE = 1;
        public static final int STATE_FAILED = 2;
        public static final int STATE_COLD = 3;

        public static final CachedText NEGATIVE = new CachedText(STATE_NEGATIVE, null);
        public static final CachedText FAILED = new CachedText(STATE_FAILED, null);
        public static final CachedText COLD = new CachedText(STATE_COLD, null);

        public final int state;
        public final String text;

        private CachedText(int state, String text) {
            this.state = state;
            this.text = text;
        }

        public static CachedText hit(String text) {
            return new CachedText(STATE_HIT, text);
        }
    }

    public enum Mode {
        OFF,
        WAITING,
        PAUSED,
        INITIAL_PAIRING_PENDING,
        IDENTITY_CHANGED,
        RECOVERY_CHANGED,
        PROTECTED
    }

    public enum PairingOfferResult {
        ACCEPTED_INITIAL,
        INITIAL_OFFER_PENDING,
        SAME_IDENTITY,
        IDENTITY_CHANGE_PENDING,
        RECOVERY_CHANGE_PENDING,
        RECOVERY_REJECTED,
        STALE
    }

    public static final class AttachmentTransport {
        public final String attachmentCarrier;

        AttachmentTransport(String attachmentCarrier) {
            this.attachmentCarrier = attachmentCarrier;
        }
    }

    /**
     * A caption-edit carrier together with the ratchet checkpoint needed if Telegram rejects the
     * edit before it is accepted.  Editing a secure caption creates a new Signal message, but the
     * encrypted media bytes and manifest identity remain unchanged.
     */
    public static final class AttachmentEditTransport {
        public final String attachmentCarrier;
        private final byte[] previousSession;
        private final byte[] nextSession;

        AttachmentEditTransport(
                String attachmentCarrier, byte[] previousSession, byte[] nextSession) {
            this.attachmentCarrier = attachmentCarrier;
            this.previousSession = previousSession != null
                    ? Arrays.copyOf(previousSession, previousSession.length) : null;
            this.nextSession = nextSession != null
                    ? Arrays.copyOf(nextSession, nextSession.length) : null;
        }
    }

    public static final class TextEditTransport {
        public final String textCarrier;
        private final byte[] previousSession;
        private final byte[] nextSession;

        TextEditTransport(
                String textCarrier, byte[] previousSession, byte[] nextSession) {
            this.textCarrier = textCarrier;
            this.previousSession = previousSession != null
                    ? Arrays.copyOf(previousSession, previousSession.length) : null;
            this.nextSession = nextSession != null
                    ? Arrays.copyOf(nextSession, nextSession.length) : null;
        }
    }

    private final Context context;
    private final int account;
    private final long peerUserId;
    private final KeystoreSignalProtocolStore store;
    private final LibsignalSessionAdapter sessions;
    private final SecureChatState state;
    private final SecureRecoveryGenerationStore recoveryStore;
    private final SecureLocalTextStore localText;
    private final SecureLocalContentStore localContent;
    private final SignalProtocolAddress peerAddress;
    private final SignalProtocolAddress localAddress;
    private final long identityEpoch;

    public static SecureChatEngine get(Context context, int account, long peerUserId) {
        return SecureSessionManager.getEngine(context, account, peerUserId);
    }

    SecureChatEngine(Context context, int account, long peerUserId) {
        if (account < 0 || peerUserId == 0) throw new IllegalArgumentException("secure chats require an account and valid peer");
        if (peerUserId < 0 && !SecureSessionManager.GROUPS_ENABLED) {
            throw new SecureChatException("secure groups are disabled", null);
        }
        this.account = account;
        this.peerUserId = peerUserId;
        Context appContext = context.getApplicationContext();
        this.context = appContext;
        SecureSessionManager.getInstance(appContext, account).ensureInitialized();
        state = new SecureChatState(appContext);
        recoveryStore = new SecureRecoveryGenerationStore(appContext, account);
        store = new KeystoreSignalProtocolStore(appContext, account);
        peerAddress = new SignalProtocolAddress("telegram-user-" + peerUserId, 1);
        localAddress = new SignalProtocolAddress("local-account-" + account, 1);
        sessions = new LibsignalSessionAdapter(store, localAddress);
        localText = new SecureLocalTextStore(appContext, account, peerUserId);
        localContent =
                new SecureLocalContentStore(appContext, account, peerUserId);
        identityEpoch = state.getIdentityEpoch(account);
        repairBogusPairedStateIfNeeded();
    }

    private void repairBogusPairedStateIfNeeded() {
        if (peerUserId <= 0) {
            return;
        }
        synchronized (SESSION_LOCK) {
            if (state.isPaired(account, peerUserId)
                    && store.getIdentity(peerAddress) == null
                    && (!store.containsSession(peerAddress)
                            || !store.loadSession(peerAddress).hasSenderChain())) {
                if (store.containsSession(peerAddress)) {
                    store.deleteSession(peerAddress);
                }
                state.markWaiting(account, peerUserId);
                clearFailedDecryptCache(account, peerUserId);
            }
        }
    }

    /** Creates a participant-bound v3 public pairing offer to send as a normal Telegram text message. */
    public String createPairingOffer(long ownerUserId) {
        synchronized (SESSION_LOCK) {
            requireCurrentIdentity();
            if (peerUserId <= 0) {
                throw new IllegalArgumentException("pairing offer requires positive peer user ID");
            }
            if (ownerUserId <= 0) {
                throw new IllegalArgumentException("pairing offer requires positive owner user ID");
            }
            if (state.isIdentityPending(account, peerUserId)) {
                throw new SecureChatException("new contact identity requires verification", null);
            }
            if (ownerUserId == peerUserId) {
                throw new IllegalArgumentException("pairing offer owner cannot equal peer");
            }
            String carrier = SecureCarrierCodec.encode(
                    SecureCarrierCodec.TYPE_PREKEY_BUNDLE,
                    SecurePreKeyBundleCodec.encodeRecoveryOffer(
                        store, recoveryStore.getLocalIdentity(), ownerUserId, peerUserId));
            state.markWaiting(account, peerUserId);
            return carrier;
        }
    }

    /** Creates a SenderKey distribution carrier for a group (dialogId < 0) encrypted over this 1:1 pairwise channel. */
    public String createGroupSenderKeyDistributionCarrier(long groupChatId) {
        return createGroupSenderKeyDistributionCarrier(groupChatId, true);
    }

    /**
     * Creates a pairwise SenderKey distribution carrier only if this 1:1 peer has not yet been
     * sent the current local SenderKey chain for {@code groupChatId}. Returns {@code null} when
     * already up-to-date.
     */
    public String createGroupSenderKeyDistributionCarrierIfNeeded(long groupChatId) {
        return createGroupSenderKeyDistributionCarrier(groupChatId, false);
    }

    private String createGroupSenderKeyDistributionCarrier(long groupChatId, boolean force) {
        if (groupChatId >= 0) {
            throw new IllegalArgumentException("group dialog id must be negative");
        }
        if (peerUserId <= 0) {
            throw new SecureChatException(
                    "group sender key distribution requires a 1:1 peer session", null);
        }
        requireCurrentIdentity();
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        if (state.isPaused(account, peerUserId)) {
            throw new SecureChatException("secure chat is paused", null);
        }
        if (state.isIdentityPending(account, peerUserId)) {
            throw new SecureChatException("new contact identity requires verification", null);
        }
        synchronized (SESSION_LOCK) {
            if (!store.containsSession(peerAddress)) {
                throw new SecureChatException("1:1 session is missing for group key distribution", null);
            }
            try {
                java.util.UUID distributionId = groupDistributionId(groupChatId);
                byte[] distributionBytes = sessions.createGroupDistributionMessage(distributionId);
                byte[] senderKeyTag = senderKeyDistributionTag(distributionId, distributionBytes);
                if (!force && state.hasDistributedGroupSenderKey(
                        account, peerUserId, groupChatId, senderKeyTag)) {
                    return null;
                }
                byte[] content = SecureContentCodec.encodeSenderKeyDistribution(
                        groupChatId, distributionBytes);
                String carrier = encryptAndRemember(
                        sessions, content, GROUP_KEY_DISTRIBUTED_DISPLAY);
                localContent.rememberOutgoing(carrier, content);
                state.recordDistributedGroupSenderKey(
                        account, peerUserId, groupChatId, senderKeyTag);
                return carrier;
            } catch (SecureChatException e) {
                throw e;
            } catch (Exception e) {
                throw new SecureChatException(
                        "cannot create pairwise group sender key distribution", e);
            }
        }
    }

    public static java.util.UUID groupDistributionId(long groupChatId) {
        if (groupChatId >= 0) {
            throw new IllegalArgumentException("group dialog id must be negative");
        }
        return java.util.UUID.nameUUIDFromBytes(
                ("telegram-group-" + groupChatId).getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] senderKeyDistributionTag(
            java.util.UUID distributionId, byte[] serializedDistributionMessage)
            throws Exception {
        org.signal.libsignal.protocol.message.SenderKeyDistributionMessage msg =
                new org.signal.libsignal.protocol.message.SenderKeyDistributionMessage(
                        serializedDistributionMessage);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        ByteBuffer header = ByteBuffer.allocate(20);
        header.putLong(distributionId.getMostSignificantBits());
        header.putLong(distributionId.getLeastSignificantBits());
        header.putInt(msg.getChainId());
        sha256.update(header.array());
        sha256.update(msg.getSignatureKey().serialize());
        return sha256.digest();
    }

    /** Rejects unencrypted SenderKey distribution carriers; distribution must be 1:1 Double Ratchet encrypted. */
    public void processGroupSenderKeyDistributionCarrier(long senderUserId, String carrier) {
        throw new SecureChatException(
                "unencrypted group sender key distribution is rejected", null);
    }

    /** Enables encryption for a group dialog (dialogId < 0) and flags initial key distribution. */
    public void enableGroup() {
        if (peerUserId >= 0) {
            throw new IllegalArgumentException("peer dialog id must be negative for groups");
        }
        synchronized (SESSION_LOCK) {
            requireCurrentIdentity();
            state.markPaired(account, peerUserId);
            state.setGroupKeyNeedsDistribution(account, peerUserId, true);
        }
    }

    /** Rotates local SenderKey for this group chat, forcing generation of a new key upon next distribution. */
    public void rotateGroupSenderKey() {
        if (peerUserId >= 0) {
            throw new IllegalArgumentException("peer dialog id must be negative for groups");
        }
        synchronized (SESSION_LOCK) {
            store.deleteSenderKey(localAddress, groupDistributionId(peerUserId));
            state.setGroupKeyNeedsDistribution(account, peerUserId, true);
        }
    }

    /** Revokes a departed or removed member's inbound SenderKey for this group chat. */
    public void revokeGroupMemberSenderKey(long memberUserId) {
        if (peerUserId >= 0) {
            throw new IllegalArgumentException("peer dialog id must be negative for groups");
        }
        if (memberUserId <= 0) {
            return;
        }
        synchronized (SESSION_LOCK) {
            SignalProtocolAddress memberAddress =
                    new SignalProtocolAddress("telegram-user-" + memberUserId, 1);
            store.deleteSenderKey(memberAddress, groupDistributionId(peerUserId));
            state.clearDistributedGroupSenderKey(account, memberUserId, peerUserId);
        }
    }

    /** True when this group engine already holds a SenderKey state from {@code senderUserId}. */
    public boolean hasSenderKeyFrom(long senderUserId) {
        if (peerUserId >= 0 || senderUserId <= 0) {
            return false;
        }
        synchronized (SESSION_LOCK) {
            SignalProtocolAddress senderAddress =
                    new SignalProtocolAddress("telegram-user-" + senderUserId, 1);
            return store.loadSenderKey(senderAddress, groupDistributionId(peerUserId)) != null;
        }
    }

    /** True when the underlying 1:1 Double Ratchet session (or local group SenderKey) exists in the store. */
    public boolean hasActiveSession() {
        synchronized (SESSION_LOCK) {
            if (peerUserId < 0) {
                return store.loadSenderKey(localAddress, groupDistributionId(peerUserId)) != null;
            }
            return store.containsSession(peerAddress);
        }
    }

    public boolean isGroupKeyNeedsDistribution() {
        return peerUserId < 0 && state.isGroupKeyNeedsDistribution(account, peerUserId);
    }

    public void setGroupKeyNeedsDistribution(boolean needed) {
        if (peerUserId >= 0) {
            throw new IllegalArgumentException("peer dialog id must be negative for groups");
        }
        state.setGroupKeyNeedsDistribution(account, peerUserId, needed);
    }

    public void clearGroupKeyNeedsDistribution() {
        if (peerUserId < 0) {
            state.setGroupKeyNeedsDistribution(account, peerUserId, false);
        }
    }

    /**
     * Validates and classifies a received pairing offer.
     *
     * <p>An initial offer is persisted as pending and requires explicit user verification before a
     * session is established. A changed identity is similarly persisted as pending and secure
     * sending remains blocked until the user compares fingerprints and explicitly approves it.</p>
     */
    public PairingOfferResult receivePairingOffer(
            String carrier, int messageId, long senderUserId, long localUserId) {
        synchronized (SESSION_LOCK) {
            requireCurrentIdentity();
            repairBogusPairedStateIfNeeded();
            if (messageId <= 0) {
                throw new IllegalArgumentException("pairing message id must be positive");
            }
            requireValidInboundSender(peerUserId, senderUserId);
            SecureCarrierCodec.Decoded decoded = requireCarrier(carrier, SecureCarrierCodec.TYPE_PREKEY_BUNDLE);
            SecurePreKeyBundleCodec.DecodedOffer offer =
                    SecurePreKeyBundleCodec.decodeOffer(decoded.payload);
            requireValidOfferBinding(peerUserId, senderUserId, localUserId, offer);
            PreKeyBundle remote = offer.preKeyBundle;
            if (state.isIdentityPending(account, peerUserId)
                    && state.getPendingMessageId(account, peerUserId) == messageId
                    && carrier.equals(state.getPendingCarrier(account, peerUserId))) {
                SecureChatState.PendingKind pendingKind = state.getPendingKind(account, peerUserId);
                if (pendingKind == SecureChatState.PendingKind.RECOVERY_ADVANCE) {
                    return PairingOfferResult.RECOVERY_CHANGE_PENDING;
                }
                if (pendingKind == SecureChatState.PendingKind.INITIAL_OFFER) {
                    return PairingOfferResult.INITIAL_OFFER_PENDING;
                }
                return PairingOfferResult.IDENTITY_CHANGE_PENDING;
            }
            IdentityKey trusted = store.getIdentity(peerAddress);
            boolean sameIdentity = trusted != null && Arrays.equals(
                    trusted.serialize(), remote.getIdentityKey().serialize());
            int lastPairingMessageId = state.getLastPairingMessageId(account, peerUserId);
            if (messageId < lastPairingMessageId
                    || (messageId == lastPairingMessageId
                            && !(sameIdentity && getMode() == Mode.WAITING))) {
                return PairingOfferResult.STALE;
            }
            if (sameIdentity) {
                SecureRecoveryGenerationStore.Record trustedRecovery =
                        recoveryStore.getVerifiedPeer(account, peerUserId);
                boolean bootstrapRecovery = false;
                if (offer.recovery == null) {
                    if (trustedRecovery != null) {
                        return PairingOfferResult.RECOVERY_REJECTED;
                    }
                } else {
                    SecureRecoveryGenerationStore.Decision recoveryDecision =
                            recoveryStore.classifyPeer(account, peerUserId, offer.recovery);
                    if (recoveryDecision
                                    == SecureRecoveryGenerationStore.Decision.REJECT_ROLLBACK
                            || recoveryDecision
                                    == SecureRecoveryGenerationStore.Decision.REJECT_CLONE) {
                        return PairingOfferResult.RECOVERY_REJECTED;
                    }
                    if (recoveryDecision
                            == SecureRecoveryGenerationStore.Decision
                                    .ADVANCE_REQUIRES_VERIFICATION) {
                        state.markIdentityPending(
                                account,
                                peerUserId,
                                carrier,
                                messageId,
                                SecureChatState.PendingKind.RECOVERY_ADVANCE);
                        return PairingOfferResult.RECOVERY_CHANGE_PENDING;
                    }
                    if (recoveryDecision
                            == SecureRecoveryGenerationStore.Decision.FIRST_SEEN) {
                        bootstrapRecovery = true;
                    }
                }
                // Sending our own offer moves the local UI to WAITING without discarding the
                // established ratchet. A matching offer from the already trusted contact must
                // complete that state and produce an authenticated acknowledgement. Allow the
                // equal-id case as a one-time repair for clients that recorded the offer before
                // this transition existed; history reload then finishes pairing automatically.
                try {
                    if (bootstrapRecovery) {
                        recoveryStore.recordVerifiedPeer(account, peerUserId, offer.recovery);
                    }
                    boolean missingSession = !store.containsSession(peerAddress);
                    boolean freshBoundRepair = messageId > lastPairingMessageId
                            && (getMode() == Mode.WAITING
                                    || state.isPaused(account, peerUserId)
                                    || offer.ownerUserId == peerUserId);
                    if (getMode() == Mode.WAITING || missingSession || freshBoundRepair) {
                        if (missingSession || freshBoundRepair) {
                            store.saveIdentity(peerAddress, remote.getIdentityKey());
                            sessions.establish(peerAddress, remote);
                            state.clearMemberGroupKeyDistributions(account, peerUserId);
                            clearFailedDecryptCache(account, peerUserId);
                        }
                        if (getMode() == Mode.WAITING || isPaired() || freshBoundRepair) {
                            state.markPaired(account, peerUserId);
                        }
                    }
                    state.recordPairingMessage(account, peerUserId, messageId);
                } catch (Exception e) {
                    if (bootstrapRecovery) {
                        try {
                            recoveryStore.restoreVerifiedPeer(
                                    account, peerUserId, trustedRecovery);
                        } catch (RuntimeException rollbackError) {
                            e.addSuppressed(rollbackError);
                        }
                    }
                    throw new SecureChatException(
                            "cannot restore secure chat with trusted identity", e);
                }
                return PairingOfferResult.SAME_IDENTITY;
            }
            if (trusted != null) {
                state.markIdentityPending(
                        account,
                        peerUserId,
                        carrier,
                        messageId,
                        SecureChatState.PendingKind.IDENTITY_CHANGE);
                return PairingOfferResult.IDENTITY_CHANGE_PENDING;
            }
            if (!canStageInitialPairingOffer()) {
                return PairingOfferResult.STALE;
            }
            state.markIdentityPending(
                    account,
                    peerUserId,
                    carrier,
                    messageId,
                    SecureChatState.PendingKind.INITIAL_OFFER);
            return PairingOfferResult.INITIAL_OFFER_PENDING;
        }
    }

    static void requireValidOfferBinding(
            long peerUserId,
            long senderUserId,
            long localUserId,
            SecurePreKeyBundleCodec.DecodedOffer offer) {
        if (offer == null) {
            throw new IllegalArgumentException("pairing offer is required");
        }
        if (peerUserId <= 0) {
            throw new IllegalArgumentException("pairing offer requires a 1:1 peer dialog");
        }
        if (senderUserId <= 0) {
            throw new IllegalArgumentException("pairing offer requires positive sender user ID");
        }
        if (localUserId <= 0) {
            throw new IllegalArgumentException("pairing offer requires positive local user ID");
        }
        if (offer.ownerUserId <= 0 || offer.recipientUserId <= 0) {
            throw new IllegalArgumentException("pairing offer lacks participant user ID binding");
        }
        if (offer.ownerUserId != peerUserId) {
            throw new IllegalArgumentException("pairing offer owner does not match peer");
        }
        if (offer.ownerUserId != senderUserId) {
            throw new IllegalArgumentException("pairing offer owner does not match sender");
        }
        if (offer.recipientUserId != localUserId) {
            throw new IllegalArgumentException("pairing offer recipient does not match local user");
        }
        if (offer.recipientUserId == peerUserId) {
            throw new IllegalArgumentException("pairing offer recipient cannot equal peer");
        }
    }

    public boolean isPaired() {
        return state.isPaired(account, peerUserId);
    }

    public Mode getMode() {
        if (state.isIdentityPending(account, peerUserId)) {
            SecureChatState.PendingKind pendingKind = state.getPendingKind(account, peerUserId);
            if (pendingKind == SecureChatState.PendingKind.RECOVERY_ADVANCE) {
                return Mode.RECOVERY_CHANGED;
            }
            if (pendingKind == SecureChatState.PendingKind.INITIAL_OFFER) {
                return Mode.INITIAL_PAIRING_PENDING;
            }
            return Mode.IDENTITY_CHANGED;
        }
        if (isPaired()) {
            return Mode.PROTECTED;
        }
        if (state.isWaiting(account, peerUserId)) {
            return Mode.WAITING;
        }
        if (state.isPaused(account, peerUserId)) {
            return Mode.PAUSED;
        }
        return Mode.OFF;
    }

    /** Initial pairing offers always require explicit user verification (SA-03). */
    public boolean canAutoAcceptPairingOffer() {
        return false;
    }

    private boolean canStageInitialPairingOffer() {
        Mode mode = getMode();
        return mode == Mode.OFF || mode == Mode.WAITING;
    }

    public boolean isStale() {
        return identityEpoch != state.getIdentityEpoch(account);
    }

    /** Encrypts a nonempty text message only after an explicit pairing step. */
    public String encryptText(String plaintext) {
        if (!isPaired()) throw new SecureChatException("secure chat is not paired", null);
        if (plaintext == null || plaintext.isEmpty()) throw new IllegalArgumentException("secure plaintext is empty");
        return encryptAndRemember(SecureContentCodec.encodeText(plaintext), plaintext);
    }

    /** Encrypts only the authenticated key manifest; sticker bytes use per-file AES-GCM. */
    public String encryptStaticStickerManifest(
            SecureContentCodec.StaticSticker sticker) {
        return encryptStickerManifest(sticker);
    }

    public String encryptStickerManifest(
            SecureContentCodec.StaticSticker sticker) {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        byte[] content = SecureContentCodec.encodeSticker(sticker);
        String carrier = encryptAndRemember(content, STATIC_STICKER_DISPLAY);
        try {
            localContent.rememberOutgoing(carrier, content);
            return carrier;
        } catch (Exception e) {
            throw new SecureChatException("cannot cache secure sticker manifest", e);
        }
    }

    public SecureContentCodec.StaticSticker getOutgoingStaticSticker(String carrier) {
        try {
            return requireStaticSticker(localContent.loadOutgoing(carrier));
        } catch (Exception e) {
            throw new SecureChatException("cannot load outgoing secure sticker", e);
        }
    }

    public SecureContentCodec.StaticSticker decryptStaticStickerManifest(String carrier, long senderUserId) {
        synchronized (SESSION_LOCK) {
            SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
            if (decoded == null
                    || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE
                    || decoded.type == SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION) {
                throw new SecureChatException("secure sticker carrier is invalid", null);
            }
            if (peerUserId < 0 && decoded.type != SecureCarrierCodec.TYPE_SENDERKEY) {
                throw new SecureChatException("group chat requires sender key carrier", null);
            }
            if (peerUserId > 0 && decoded.type == SecureCarrierCodec.TYPE_SENDERKEY) {
                throw new SecureChatException("1:1 chat rejects group sender key carrier", null);
            }
            requireValidInboundSender(peerUserId, senderUserId);
            try {
                byte[] content = localContent.loadIncoming(carrier);
                if (content == null) {
                    content = decryptInboundPayload(decoded, senderUserId);
                    SecureContentCodec.StaticSticker sticker = requireStaticSticker(content);
                    localContent.rememberIncoming(carrier, content);
                    localText.rememberIncoming(carrier, STATIC_STICKER_DISPLAY);
                    if (peerUserId > 0 && state.isWaiting(account, peerUserId)) {
                        state.markPaired(account, peerUserId);
                    }
                    return sticker;
                }
                return requireStaticSticker(content);
            } catch (SecureChatException e) {
                throw e;
            } catch (Exception e) {
                throw new SecureChatException("cannot decrypt secure sticker manifest", e);
            }
        }
    }

    public String encryptAttachmentManifest(SecureContentCodec.Attachment attachment) {
        return encryptAttachmentForTransport(
                attachment, Integer.MAX_VALUE, Integer.MAX_VALUE).attachmentCarrier;
    }

    /**
     * Produces a caption-sized attachment carrier.
     *
     * <p>A PQ pre-key carrier cannot fit in a Telegram caption. Pairing therefore completes a
     * two-way encrypted confirmation before media is ready. This method still keeps its length
     * check inside a session rollback boundary so an old or incomplete session cannot be advanced
     * by a carrier that Telegram will reject.</p>
     */
    public AttachmentTransport encryptAttachmentForTransport(
            SecureContentCodec.Attachment attachment,
            int maxCaptionCharacters,
            int maxTextCharacters) {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        if (maxCaptionCharacters <= 0 || maxTextCharacters <= 0) {
            throw new IllegalArgumentException("secure carrier limits must be positive");
        }
        byte[] content = SecureContentCodec.encodeAttachment(attachment);
        String display = attachment.photo ? PHOTO_DISPLAY : FILE_DISPLAY;
        synchronized (SESSION_LOCK) {
            boolean hadSession = peerUserId >= 0 && store.containsSession(peerAddress);
            SessionRecord previousSession = null;
            String firstCarrier = null;
            try {
                if (hadSession) {
                    previousSession = new SessionRecord(
                            store.loadSession(peerAddress).serialize());
                }
                firstCarrier = encryptAndRemember(content, display);
                if (firstCarrier.length() > maxCaptionCharacters) {
                    throw new IllegalArgumentException(
                            "secure media session is awaiting its encrypted reply");
                }
                localContent.rememberOutgoing(firstCarrier, content);
                return new AttachmentTransport(firstCarrier);
            } catch (Exception error) {
                try {
                    if (peerUserId >= 0) {
                        if (hadSession && previousSession != null) {
                            store.storeSession(peerAddress, previousSession);
                        } else if (!hadSession && store.containsSession(peerAddress)) {
                            store.deleteSession(peerAddress);
                        }
                    }
                    if (firstCarrier != null) {
                        localText.forgetOutgoing(firstCarrier);
                    }
                } catch (Exception rollbackError) {
                    error.addSuppressed(rollbackError);
                }
                throw new SecureChatException(
                        "cannot create bounded secure attachment carrier", error);
            }
        }
    }

    /**
     * Encrypts a replacement attachment manifest for a caption edit.  The media ciphertext is
     * deliberately not regenerated: only the authenticated manifest caption/placement changes.
     */
    public AttachmentEditTransport encryptAttachmentForEdit(
            SecureContentCodec.Attachment attachment,
            int maxCaptionCharacters,
            int maxTextCharacters) {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        if (maxCaptionCharacters <= 0 || maxTextCharacters <= 0) {
            throw new IllegalArgumentException("secure carrier limits must be positive");
        }
        byte[] content = SecureContentCodec.encodeAttachment(attachment);
        String display = attachment.photo ? PHOTO_DISPLAY : FILE_DISPLAY;
        synchronized (SESSION_LOCK) {
            boolean hadSession = peerUserId >= 0 && store.containsSession(peerAddress);
            byte[] previousSession = null;
            String carrier = null;
            try {
                if (hadSession) {
                    previousSession = store.loadSession(peerAddress).serialize();
                }
                carrier = encryptAndRemember(content, display);
                if (carrier.length() > maxCaptionCharacters) {
                    throw new IllegalArgumentException(
                            "secure media session is awaiting its encrypted reply");
                }
                localContent.rememberOutgoing(carrier, content);
                byte[] nextSession = (peerUserId >= 0)
                        ? store.loadSession(peerAddress).serialize() : null;
                return new AttachmentEditTransport(carrier, previousSession, nextSession);
            } catch (Exception error) {
                try {
                    if (peerUserId >= 0) {
                        if (hadSession && previousSession != null) {
                            store.storeSession(peerAddress, new SessionRecord(previousSession));
                        } else if (!hadSession && store.containsSession(peerAddress)) {
                            store.deleteSession(peerAddress);
                        }
                    }
                    if (carrier != null) {
                        localText.forgetOutgoing(carrier);
                        localContent.forgetOutgoing(carrier);
                    }
                } catch (Exception rollbackError) {
                    error.addSuppressed(rollbackError);
                }
                throw new SecureChatException(
                        "cannot create secure attachment edit carrier", error);
            }
        }
    }

    /**
     * Post-dispatch ratchet rollback is intentionally a no-op (SA-05). Once an edit carrier leaves
     * {@link #encryptAttachmentForEdit}, its message key is treated as consumed so network timeouts
     * or server errors cannot cause message key reuse.
     */
    @Deprecated
    public void rollbackAttachmentEdit(AttachmentEditTransport transport) {
        // Intentionally no-op after pre-flight validation.
    }

    /**
     * Encrypts a replacement text carrier for editing an existing message. Pre-flight length bounds
     * are validated before returning; once returned, the ratchet step is never rolled back.
     */
    public TextEditTransport encryptTextForEdit(String plaintext, int maxTextCharacters) {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        if (plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("secure plaintext is empty");
        }
        if (maxTextCharacters <= 0) {
            throw new IllegalArgumentException("secure carrier limits must be positive");
        }
        byte[] content = SecureContentCodec.encodeText(plaintext);
        synchronized (SESSION_LOCK) {
            boolean hadSession = peerUserId >= 0 && store.containsSession(peerAddress);
            byte[] previousSession = null;
            String carrier = null;
            try {
                if (hadSession) {
                    previousSession = store.loadSession(peerAddress).serialize();
                }
                carrier = encryptAndRemember(content, plaintext);
                if (carrier.length() > maxTextCharacters) {
                    throw new IllegalArgumentException(
                            "secure text carrier exceeds maximum allowed characters");
                }
                byte[] nextSession = (peerUserId >= 0)
                        ? store.loadSession(peerAddress).serialize() : null;
                return new TextEditTransport(carrier, previousSession, nextSession);
            } catch (Exception error) {
                try {
                    if (peerUserId >= 0) {
                        if (hadSession && previousSession != null) {
                            store.storeSession(peerAddress, new SessionRecord(previousSession));
                        } else if (!hadSession && store.containsSession(peerAddress)) {
                            store.deleteSession(peerAddress);
                        }
                    }
                    if (carrier != null) {
                        localText.forgetOutgoing(carrier);
                    }
                } catch (Exception rollbackError) {
                    error.addSuppressed(rollbackError);
                }
                throw new SecureChatException(
                        "cannot create secure text edit carrier", error);
            }
        }
    }

    /**
     * Post-dispatch ratchet rollback is intentionally a no-op (SA-05). Once an edit carrier leaves
     * {@link #encryptTextForEdit}, its message key is treated as consumed so network timeouts or
     * server errors cannot cause message key reuse.
     */
    @Deprecated
    public void rollbackTextEdit(TextEditTransport transport) {
        // Intentionally no-op after pre-flight validation.
    }

    public String encryptDeleteControl(List<byte[]> carrierDigests) {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        byte[] content = SecureContentCodec.encodeDeleteControl(carrierDigests);
        String carrier = encryptAndRemember(content, CONTROL_DELETE_DISPLAY);
        try {
            localContent.rememberOutgoing(carrier, content);
        } catch (Exception ignore) {
        }
        return carrier;
    }

    public List<byte[]> getDeleteControlDigests(String carrier) {
        if (carrier == null || carrier.isEmpty()) {
            return null;
        }
        try {
            byte[] content = localContent.loadIncoming(carrier);
            if (content == null) {
                content = localContent.loadOutgoing(carrier);
            }
            if (content != null) {
                SecureContentCodec.Decoded decoded = SecureContentCodec.decode(content);
                if (decoded != null && decoded.type == SecureContentCodec.TYPE_CONTROL
                        && decoded.control != null
                        && decoded.control.action == SecureContentCodec.CONTROL_ACTION_DELETE) {
                    return decoded.control.carrierDigests;
                }
            }
        } catch (Exception ignore) {
        }
        return null;
    }

    /**
     * Verifies and refines a {@link SecureMediaIndex} kind against authenticated local caches
     * without advancing any cryptographic ratchet. Returns {@code -1} if the carrier is a
     * non-attachment (pairing offer, sender-key distribution, control event, sticker, text,
     * contact, or location) that must not appear in shared media/file tabs.
     */
    public int resolveCachedMediaIndexKind(String carrier, boolean outgoing, int currentKind) {
        if (carrier == null || carrier.isEmpty()) {
            return currentKind;
        }
        SecureCarrierCodec.Decoded carrierDecoded = SecureCarrierCodec.decode(carrier);
        if (carrierDecoded == null
                || carrierDecoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE
                || carrierDecoded.type == SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION) {
            return -1;
        }
        try {
            String display = outgoing
                    ? localText.loadOutgoing(carrier)
                    : localText.loadIncoming(carrier);
            if (display == null) {
                display = outgoing
                        ? localText.loadIncoming(carrier)
                        : localText.loadOutgoing(carrier);
            }
            if (display != null) {
                if (isStaticStickerDisplay(display)
                        || isControlDisplay(display)
                        || isPairingStatusDisplay(display)
                        || isContactDisplay(display)
                        || isLocationDisplay(display)) {
                    return -1;
                }
                if (isPhotoDisplay(display)) {
                    return SecureMediaIndex.KIND_PHOTO;
                }
                if (!isFileDisplay(display)) {
                    return -1;
                }
            }
        } catch (Exception ignore) {
        }
        try {
            byte[] raw = outgoing
                    ? localContent.loadOutgoing(carrier)
                    : localContent.loadIncoming(carrier);
            if (raw == null) {
                raw = outgoing
                        ? localContent.loadIncoming(carrier)
                        : localContent.loadOutgoing(carrier);
            }
            if (raw != null) {
                SecureContentCodec.Decoded decoded = SecureContentCodec.decode(raw);
                if (decoded != null) {
                    if (decoded.type == SecureContentCodec.TYPE_PHOTO) {
                        return SecureMediaIndex.KIND_PHOTO;
                    }
                    if (decoded.type != SecureContentCodec.TYPE_FILE || decoded.attachment == null) {
                        return -1;
                    }
                    SecureContentCodec.Attachment att = decoded.attachment;
                    if (att.photo) {
                        return SecureMediaIndex.KIND_PHOTO;
                    }
                    if (att.presentation == SecureContentCodec.ATTACHMENT_PRESENTATION_ANIMATION
                            || "image/gif".equalsIgnoreCase(att.mimeType)) {
                        return SecureMediaIndex.KIND_GIF;
                    }
                    if (att.presentation == SecureContentCodec.ATTACHMENT_PRESENTATION_ROUND_VIDEO) {
                        return SecureMediaIndex.KIND_ROUND_VIDEO;
                    }
                    if (att.presentation == SecureContentCodec.ATTACHMENT_PRESENTATION_VOICE) {
                        return SecureMediaIndex.KIND_VOICE;
                    }
                    if (att.presentation == SecureContentCodec.ATTACHMENT_PRESENTATION_AUDIO) {
                        return SecureMediaIndex.KIND_MUSIC;
                    }
                    if (att.presentation == SecureContentCodec.ATTACHMENT_PRESENTATION_VIDEO) {
                        return SecureMediaIndex.KIND_VIDEO;
                    }
                    return SecureMediaIndex.KIND_FILE;
                }
            }
        } catch (Exception ignore) {
        }
        return currentKind;
    }

    public String encryptContact(SecureContentCodec.Contact contact) {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        byte[] content = SecureContentCodec.encodeContact(contact);
        String carrier = encryptAndRemember(content, CONTACT_DISPLAY);
        try {
            localContent.rememberOutgoing(carrier, content);
            return carrier;
        } catch (Exception e) {
            throw new SecureChatException("cannot cache secure contact", e);
        }
    }

    public SecureContentCodec.Contact getOutgoingContact(String carrier) {
        try {
            return requireContact(localContent.loadOutgoing(carrier));
        } catch (Exception e) {
            throw new SecureChatException("cannot load outgoing secure contact", e);
        }
    }

    public SecureContentCodec.Contact getIncomingContact(String carrier) {
        try {
            return requireContact(localContent.loadIncoming(carrier));
        } catch (Exception e) {
            throw new SecureChatException("cannot load incoming secure contact", e);
        }
    }

    public String encryptLocation(SecureContentCodec.GeoLocation location) {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        byte[] content = SecureContentCodec.encodeLocation(location);
        String carrier = encryptAndRemember(content, LOCATION_DISPLAY);
        try {
            localContent.rememberOutgoing(carrier, content);
            return carrier;
        } catch (Exception e) {
            throw new SecureChatException("cannot cache secure location", e);
        }
    }

    public SecureContentCodec.GeoLocation getOutgoingLocation(String carrier) {
        try {
            return requireLocation(localContent.loadOutgoing(carrier));
        } catch (Exception e) {
            throw new SecureChatException("cannot load outgoing secure location", e);
        }
    }

    public SecureContentCodec.GeoLocation getIncomingLocation(String carrier) {
        try {
            return requireLocation(localContent.loadIncoming(carrier));
        } catch (Exception e) {
            throw new SecureChatException("cannot load incoming secure location", e);
        }
    }

    public SecureContentCodec.Attachment getOutgoingAttachment(String carrier) {
        try {
            return requireAttachment(localContent.loadOutgoing(carrier));
        } catch (Exception e) {
            throw new SecureChatException("cannot load outgoing secure attachment", e);
        }
    }

    public SecureContentCodec.Attachment decryptAttachmentManifest(String carrier, long senderUserId) {
        synchronized (SESSION_LOCK) {
            SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
            if (decoded == null
                    || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE
                    || decoded.type == SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION) {
                throw new SecureChatException("secure attachment carrier is invalid", null);
            }
            if (peerUserId < 0 && decoded.type != SecureCarrierCodec.TYPE_SENDERKEY) {
                throw new SecureChatException("group chat requires sender key carrier", null);
            }
            if (peerUserId > 0 && decoded.type == SecureCarrierCodec.TYPE_SENDERKEY) {
                throw new SecureChatException("1:1 chat rejects group sender key carrier", null);
            }
            requireValidInboundSender(peerUserId, senderUserId);
            try {
                byte[] content = localContent.loadIncoming(carrier);
                if (content == null) {
                    content = decryptInboundPayload(decoded, senderUserId);
                    SecureContentCodec.Attachment attachment =
                            requireAttachment(content);
                    localContent.rememberIncoming(carrier, content);
                    localText.rememberIncoming(
                            carrier, attachment.photo ? PHOTO_DISPLAY : FILE_DISPLAY);
                    if (peerUserId > 0 && state.isWaiting(account, peerUserId)) {
                        state.markPaired(account, peerUserId);
                    }
                    return attachment;
                }
                return requireAttachment(content);
            } catch (SecureChatException e) {
                throw e;
            } catch (Exception e) {
                throw new SecureChatException(
                        "cannot decrypt secure attachment manifest", e);
            }
        }
    }

    /** Creates an authenticated control message that completes pairing without user-authored text. */
    public String createPairingAcknowledgement() {
        if (!isPaired()) throw new SecureChatException("secure chat is not paired", null);
        return encryptAndRemember(
                sessions, SecureContentCodec.encodePairingAckControl(), PAIRING_ACK_DISPLAY);
    }

    /**
     * Answers the first encrypted pairing acknowledgement. This turns the initiator's next
     * outbound message into a compact Signal message instead of another PQ pre-key message.
     */
    public String createSessionReadyAcknowledgement() {
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        return encryptAndRemember(
                sessions, SecureContentCodec.encodePairingReadyControl(), PAIRING_READY_DISPLAY);
    }

    public boolean shouldAcknowledgeSessionReady(
            String plaintext, int messageId) {
        return peerUserId > 0
                && isPairingAcknowledgementDisplay(plaintext)
                && state.shouldAcknowledgeSessionReady(
                        account, peerUserId, messageId)
                && store.containsSession(peerAddress);
    }

    public void recordSessionReadyAcknowledgement(int messageId) {
        state.recordSessionReadyAcknowledgement(
                account, peerUserId, messageId);
    }

    /**
     * Creates an authenticated rejection for a pending changed identity without trusting or
     * persisting that identity.
     *
     * <p>The pending public bundle is used in an in-memory, one-message session. The durable old
     * trust record and session remain untouched. The caller must pause the chat only after this
     * method succeeds.</p>
     */
    public String createPairingRejection() {
        requireCurrentIdentity();
        String pendingCarrier = state.getPendingCarrier(account, peerUserId);
        if (!state.isIdentityPending(account, peerUserId) || pendingCarrier == null) {
            throw new SecureChatException("no pending contact identity", null);
        }
        SecureCarrierCodec.Decoded decoded =
                requireCarrier(pendingCarrier, SecureCarrierCodec.TYPE_PREKEY_BUNDLE);
        PreKeyBundle remote = SecurePreKeyBundleCodec.decode(decoded.payload);
        try {
            InMemorySignalProtocolStore temporaryStore = new InMemorySignalProtocolStore(
                    store.getIdentityKeyPair(), store.getLocalRegistrationId());
            LibsignalSessionAdapter temporarySessions = new LibsignalSessionAdapter(
                    temporaryStore,
                    new SignalProtocolAddress("local-account-" + account, 1));
            temporarySessions.establish(peerAddress, remote);
            return encryptAndRemember(
                    temporarySessions,
                    SecureContentCodec.encodePairingRejectControl(),
                    PAIRING_REJECTED_DISPLAY);
        } catch (Exception e) {
            throw new SecureChatException("cannot create secure pairing rejection", e);
        }
    }

    private String encryptAndRemember(String protocolPlaintext, String localDisplayText) {
        return encryptAndRemember(
                sessions, protocolPlaintext.getBytes(StandardCharsets.UTF_8), localDisplayText);
    }

    private String encryptAndRemember(byte[] protocolPlaintext, String localDisplayText) {
        return encryptAndRemember(sessions, protocolPlaintext, localDisplayText);
    }

    private String encryptAndRemember(
            LibsignalSessionAdapter sessionSource,
            String protocolPlaintext,
            String localDisplayText) {
        return encryptAndRemember(
                sessionSource,
                protocolPlaintext.getBytes(StandardCharsets.UTF_8),
                localDisplayText);
    }

    private String encryptAndRemember(
            LibsignalSessionAdapter sessionSource,
            byte[] protocolPlaintext,
            String localDisplayText) {
        synchronized (SESSION_LOCK) {
            repairBogusPairedStateIfNeeded();
            try {
                LibsignalSessionAdapter.EncryptedMessage encrypted;
                if (peerUserId < 0) {
                    java.util.UUID distributionId = java.util.UUID.nameUUIDFromBytes(
                            ("telegram-group-" + peerUserId).getBytes(StandardCharsets.UTF_8));
                    encrypted = sessionSource.encryptGroup(distributionId, protocolPlaintext);
                } else {
                    encrypted = sessionSource.encrypt(peerAddress, protocolPlaintext);
                }
                int carrierType;
                if (encrypted.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY) {
                    carrierType = SecureCarrierCodec.TYPE_PREKEY;
                } else if (encrypted.type == LibsignalSessionAdapter.MESSAGE_TYPE_SENDERKEY) {
                    carrierType = SecureCarrierCodec.TYPE_SENDERKEY;
                } else {
                    carrierType = SecureCarrierCodec.TYPE_WHISPER;
                }
                String carrier = SecureCarrierCodec.encode(carrierType, encrypted.serialized);
                // Persist before handing the carrier to Telegram. If this fails, do not send a message
                // that this client cannot render locally after a reload.
                localText.rememberOutgoing(carrier, localDisplayText);
                return carrier;
            } catch (Exception e) {
                throw new SecureChatException("cannot encrypt secure text", e);
            }
        }
    }

    /**
     * Returns this installation's encrypted local copy for an outbound carrier.
     *
     * <p>A missing result means the message was authored before this cache existed or by another
     * linked installation. It must not be passed to the inbound ratchet.</p>
     */
    public String getOutgoingText(String carrier) {
        synchronized (SESSION_LOCK) {
            try {
                String display = localText.loadOutgoing(carrier);
                // r24 paused after sending a rejection but retained the now-dead old session. Seeing
                // the locally cached rejection upgrades that state in place without rotating either
                // identity or deleting the old trusted fingerprint.
                if (isPairingRejectionDisplay(display)
                        && state.isPaused(account, peerUserId)) {
                    store.deleteSession(peerAddress);
                }
                return display;
            } catch (Exception e) {
                throw new SecureChatException("cannot load local outgoing secure text", e);
            }
        }
    }

    /**
     * Returns a previously authenticated inbound display copy without advancing the ratchet.
     *
     * <p>This is intentionally cache-only. Reply previews may be created from Telegram's
     * {@code quote_text} without a nested message object, and attempting a fresh decrypt there
     * could consume a message out of order.</p>
     */
    public String getIncomingText(String carrier) {
        try {
            return localText.loadIncoming(carrier);
        } catch (Exception e) {
            throw new SecureChatException("cannot load local incoming secure text", e);
        }
    }

    public CachedText peekOutgoingText(String carrier) {
        return peekOutgoingText(account, peerUserId, carrier, this);
    }

    public CachedText peekIncomingText(String carrier, boolean cacheOnly) {
        return peekIncomingText(account, peerUserId, carrier, this, cacheOnly);
    }

    public static CachedText peekOutgoingText(
            int account, long peerUserId, String carrier, SecureChatEngine engine) {
        SecureLocalTextStore.LookupResult res = engine != null
                ? engine.localText.peekOutgoing(carrier)
                : SecureLocalTextStore.peekStatic(account, peerUserId, true, carrier);
        if (res.state == SecureLocalTextStore.LookupResult.HIT) {
            if (isPairingRejectionDisplay(res.text)) {
                Mode mode = engine != null ? engine.getMode() : SecureChatState.peekMode(account, peerUserId);
                if (mode == null || mode == Mode.PAUSED) {
                    return CachedText.COLD;
                }
            }
            if (isContactDisplay(res.text)
                    || isLocationDisplay(res.text)
                    || isControlDeleteDisplay(res.text)) {
                if (engine == null || !engine.localContent.hasCachedOutgoing(carrier)) {
                    return CachedText.COLD;
                }
            }
            return CachedText.hit(res.text);
        }
        if (res.state == SecureLocalTextStore.LookupResult.NEGATIVE) {
            return CachedText.NEGATIVE;
        }
        return CachedText.COLD;
    }

    public static CachedText peekIncomingText(
            int account, long peerUserId, String carrier, SecureChatEngine engine, boolean cacheOnly) {
        SecureLocalTextStore.LookupResult res = engine != null
                ? engine.localText.peekIncoming(carrier)
                : SecureLocalTextStore.peekStatic(account, peerUserId, false, carrier);
        if (res.state == SecureLocalTextStore.LookupResult.HIT) {
            if (!cacheOnly) {
                Mode mode = engine != null ? engine.getMode() : SecureChatState.peekMode(account, peerUserId);
                if (mode == null) {
                    return CachedText.COLD;
                }
                if (isPairingAcknowledgementDisplay(res.text) && peerUserId > 0 && engine == null) {
                    return CachedText.COLD;
                }
            }
            if (isContactDisplay(res.text)
                    || isLocationDisplay(res.text)
                    || isControlDeleteDisplay(res.text)) {
                if (engine == null || !engine.localContent.hasCachedIncoming(carrier)) {
                    return CachedText.COLD;
                }
            }
            return CachedText.hit(res.text);
        }
        if (cacheOnly && res.state == SecureLocalTextStore.LookupResult.NEGATIVE) {
            return CachedText.NEGATIVE;
        }
        if (!cacheOnly && hasRecentFailedDecrypt(account, peerUserId, carrier)) {
            return CachedText.FAILED;
        }
        return CachedText.COLD;
    }

    public static boolean hasRecentFailedDecrypt(int account, long peerUserId, String carrier) {
        String cacheKey = failedDecryptKey(account, peerUserId, carrier);
        synchronized (failedDecryptCarriers) {
            FailedDecryptEntry entry = failedDecryptCarriers.get(cacheKey);
            if (entry == null) {
                return false;
            }
            if (System.currentTimeMillis() - entry.timestamp < FAILED_DECRYPT_TTL_MS) {
                return true;
            }
            failedDecryptCarriers.remove(cacheKey);
            return false;
        }
    }

    public void warmCachedContentForDisplay(String carrier, boolean outgoing, String displayText) {
        if (displayText == null) {
            return;
        }
        try {
            if (isContactDisplay(displayText)
                    || isLocationDisplay(displayText)
                    || isControlDeleteDisplay(displayText)) {
                if (outgoing) {
                    localContent.loadOutgoing(carrier);
                } else {
                    localContent.loadIncoming(carrier);
                }
            }
        } catch (Exception ignore) {
        }
    }

    public static void clearFailedDecryptCache() {
        synchronized (failedDecryptCarriers) {
            failedDecryptCarriers.clear();
        }
    }

    public static void clearFailedDecryptCache(int account, long peerUserId) {
        String prefix = account + ":" + peerUserId + ":";
        synchronized (failedDecryptCarriers) {
            java.util.Iterator<String> it = failedDecryptCarriers.keySet().iterator();
            while (it.hasNext()) {
                if (it.next().startsWith(prefix)) {
                    it.remove();
                }
            }
        }
    }

    /** Decrypts a recognized message. Successful first contact activates secure mode for the recipient. */
    public String decryptText(String carrier, long senderUserId) {
        synchronized (SESSION_LOCK) {
            SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
            if (decoded == null) return null;
            if (decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
                throw new SecureChatException("pairing offer requires explicit acceptance", null);
            }
            if (decoded.type == SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION) {
                throw new SecureChatException(
                        "unencrypted group sender key distribution is rejected", null);
            }
            if (peerUserId < 0 && decoded.type != SecureCarrierCodec.TYPE_SENDERKEY) {
                throw new SecureChatException("group chat requires sender key carrier", null);
            }
            if (peerUserId > 0 && decoded.type == SecureCarrierCodec.TYPE_SENDERKEY) {
                throw new SecureChatException("1:1 chat rejects group sender key carrier", null);
            }
            requireValidInboundSender(peerUserId, senderUserId);
            try {
                String cached = localText.loadIncoming(carrier);
                if (cached != null) {
                    return cached;
                }
                String cacheKey = failedDecryptKey(account, peerUserId, carrier);
                synchronized (failedDecryptCarriers) {
                    FailedDecryptEntry entry = failedDecryptCarriers.get(cacheKey);
                    if (entry != null) {
                        if (System.currentTimeMillis() - entry.timestamp < FAILED_DECRYPT_TTL_MS) {
                            throw new SecureChatException("cannot decrypt secure text (previously failed)", null);
                        } else {
                            failedDecryptCarriers.remove(cacheKey);
                        }
                    }
                }
                byte[] plain = decryptInboundPayload(decoded, senderUserId);
                String result;
                if (SecureContentCodec.isVersioned(plain)) {
                    SecureContentCodec.Decoded content = SecureContentCodec.decode(plain);
                    if (content.type == SecureContentCodec.TYPE_TEXT) {
                        result = content.text;
                        if (result != null && result.startsWith("\u0000fork-secure-display:")) {
                            result = " " + result;
                        }
                    } else if (content.type == SecureContentCodec.TYPE_STATIC_STICKER
                            || content.type == SecureContentCodec.TYPE_ANIMATED_STICKER
                            || content.type == SecureContentCodec.TYPE_VIDEO_STICKER) {
                        localContent.rememberIncoming(carrier, plain);
                        result = STATIC_STICKER_DISPLAY;
                    } else if (content.type == SecureContentCodec.TYPE_FILE
                            || content.type == SecureContentCodec.TYPE_PHOTO) {
                        localContent.rememberIncoming(carrier, plain);
                        result = content.type == SecureContentCodec.TYPE_PHOTO
                                ? PHOTO_DISPLAY : FILE_DISPLAY;
                    } else if (content.type == SecureContentCodec.TYPE_CONTROL) {
                        localContent.rememberIncoming(carrier, plain);
                        if (content.control != null) {
                            if (content.control.action == SecureContentCodec.CONTROL_ACTION_DELETE) {
                                SecureLocalMessageCache cache =
                                        new SecureLocalMessageCache(context, account, peerUserId);
                                SecureMediaIndex mediaIndex =
                                        new SecureMediaIndex(context, account, peerUserId);
                                for (byte[] digest : content.control.carrierDigests) {
                                    try {
                                        cache.forgetByDigest(digest);
                                    } catch (Exception error) {
                                    }
                                    try {
                                        mediaIndex.forgetByDigest(digest);
                                    } catch (Exception error) {
                                    }
                                }
                                result = CONTROL_DELETE_DISPLAY;
                            } else if (content.control.action == SecureContentCodec.CONTROL_ACTION_PAIRING_ACK) {
                                result = PAIRING_ACK_DISPLAY;
                            } else if (content.control.action == SecureContentCodec.CONTROL_ACTION_PAIRING_READY) {
                                result = PAIRING_READY_DISPLAY;
                            } else if (content.control.action == SecureContentCodec.CONTROL_ACTION_PAIRING_REJECT) {
                                result = PAIRING_REJECTED_DISPLAY;
                            } else {
                                throw new SecureChatException("unknown control action: " + content.control.action, null);
                            }
                        } else {
                            throw new SecureChatException("missing control body", null);
                        }
                    } else if (content.type == SecureContentCodec.TYPE_CONTACT) {
                        localContent.rememberIncoming(carrier, plain);
                        result = CONTACT_DISPLAY;
                    } else if (content.type == SecureContentCodec.TYPE_GEO_LOCATION) {
                        localContent.rememberIncoming(carrier, plain);
                        result = LOCATION_DISPLAY;
                    } else if (content.type == SecureContentCodec.TYPE_SENDER_KEY_DISTRIBUTION) {
                        if (peerUserId <= 0
                                || senderUserId != peerUserId
                                || content.senderKeyDistribution == null
                                || content.senderKeyDistribution.groupChatId >= 0) {
                            throw new SecureChatException(
                                    "sender key distribution requires 1:1 peer session", null);
                        }
                        sessions.processGroupDistributionMessage(
                                peerAddress,
                                groupDistributionId(content.senderKeyDistribution.groupChatId),
                                content.senderKeyDistribution.distributionBytes);
                        clearFailedDecryptCache(account, peerUserId);
                        clearFailedDecryptCache(account, content.senderKeyDistribution.groupChatId);
                        localContent.rememberIncoming(carrier, plain);
                        result = GROUP_KEY_RECEIVED_DISPLAY;
                    } else {
                        throw new SecureChatException("unsupported secure content", null);
                    }
                } else {
                    throw new SecureChatException("unsupported legacy unversioned content", null);
                }
                // Cache the verified plaintext before returning it to Telegram's in-memory message view.
                // A history reload then avoids replaying the same message through the ratchet.
                localText.rememberIncoming(carrier, result);
                if (isPairingRejectionDisplay(result)) {
                    pauseAfterPairingRejection();
                } else if (peerUserId > 0 && state.isWaiting(account, peerUserId)) {
                    state.markPaired(account, peerUserId);
                }
                return result;
            } catch (org.signal.libsignal.protocol.DuplicateMessageException duplicate) {
                try {
                    localText.rememberIncoming(carrier, DUPLICATE_MESSAGE_DISPLAY);
                } catch (Exception ignore) {
                }
                return DUPLICATE_MESSAGE_DISPLAY;
            } catch (SecureChatException e) {
                throw e;
            } catch (Exception e) {
                if (e instanceof org.signal.libsignal.protocol.InvalidMessageException
                        || e instanceof org.signal.libsignal.protocol.InvalidKeyIdException
                        || e instanceof org.signal.libsignal.protocol.UntrustedIdentityException) {
                    String cacheKey = failedDecryptKey(account, peerUserId, carrier);
                    synchronized (failedDecryptCarriers) {
                        failedDecryptCarriers.put(cacheKey, new FailedDecryptEntry(System.currentTimeMillis()));
                    }
                }
                throw new SecureChatException("cannot decrypt secure text", e);
            }
        }
    }

    /**
     * Resolves a secure carrier for a normal 1:1 dialog preview.
     *
     * <p>Inbound ciphertext uses the same decrypt-and-cache path as the open chat. Outbound
     * ciphertext is never fed to the inbound ratchet and can only use this installation's
     * Keystore-encrypted display copy.</p>
     */
    public DialogPreview resolveDialogPreview(String carrier, boolean outgoing, long senderUserId) {
        return resolveDialogPreview(carrier, outgoing, senderUserId, false);
    }

    public DialogPreview resolveDialogPreview(
            String carrier, boolean outgoing, long senderUserId, boolean cacheOnly) {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null) {
            return null;
        }
        if (decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
            if (!outgoing) {
                requireValidInboundSender(peerUserId, senderUserId);
            }
            return new DialogPreview(
                    outgoing
                            ? DialogPreview.Kind.PAIRING_OFFER_SENT
                            : DialogPreview.Kind.PAIRING_OFFER_RECEIVED,
                    null);
        }
        if (decoded.type == SecureCarrierCodec.TYPE_SENDERKEY_DISTRIBUTION) {
            throw new SecureChatException(
                    "unencrypted group sender key distribution is rejected", null);
        }
        if (outgoing) {
            String local = getOutgoingText(carrier);
            if (local == null) {
                return new DialogPreview(DialogPreview.Kind.OUTGOING_UNAVAILABLE, null);
            }
            return new DialogPreview(
                    controlPreviewKind(local),
                    isControlDisplay(local) ? null : local);
        }
        requireValidInboundSender(peerUserId, senderUserId);
        try {
            String cached = localText.loadIncoming(carrier);
            if (cached != null) {
                return new DialogPreview(
                        controlPreviewKind(cached),
                        isControlDisplay(cached) ? null : cached);
            }
        } catch (Exception ignore) {
        }
        if (cacheOnly) {
            return null;
        }
        String plaintext = decryptText(carrier, senderUserId);
        return new DialogPreview(
                controlPreviewKind(plaintext),
                isControlDisplay(plaintext) ? null : plaintext);
    }

    public static boolean isPairingAcknowledgementDisplay(String value) {
        return PAIRING_ACK_DISPLAY.equals(value);
    }

    public static boolean isPairingReadyDisplay(String value) {
        return PAIRING_READY_DISPLAY.equals(value);
    }

    public static boolean isGroupKeyDistributedDisplay(String value) {
        return GROUP_KEY_DISTRIBUTED_DISPLAY.equals(value);
    }

    public static boolean isGroupKeyReceivedDisplay(String value) {
        return GROUP_KEY_RECEIVED_DISPLAY.equals(value);
    }

    public static boolean isGroupKeyStatusDisplay(String value) {
        return isGroupKeyDistributedDisplay(value)
                || isGroupKeyReceivedDisplay(value);
    }

    /** True only for authenticated pairing lifecycle text rendered as a local service row. */
    public static boolean isPairingStatusDisplay(String value) {
        return isPairingAcknowledgementDisplay(value)
                || isPairingReadyDisplay(value)
                || isPairingRejectionDisplay(value)
                || isGroupKeyStatusDisplay(value);
    }

    public static boolean isPairingRejectionDisplay(String value) {
        return PAIRING_REJECTED_DISPLAY.equals(value);
    }

    public static boolean isStaticStickerDisplay(String value) {
        return STATIC_STICKER_DISPLAY.equals(value);
    }

    public static boolean isFileDisplay(String value) {
        return FILE_DISPLAY.equals(value);
    }

    public static boolean isPhotoDisplay(String value) {
        return PHOTO_DISPLAY.equals(value);
    }

    public static boolean isAttachmentDisplay(String value) {
        return isFileDisplay(value) || isPhotoDisplay(value);
    }

    public static boolean isControlDeleteDisplay(String value) {
        return CONTROL_DELETE_DISPLAY.equals(value);
    }

    public static boolean isDuplicateMessageDisplay(String value) {
        return DUPLICATE_MESSAGE_DISPLAY.equals(value);
    }

    public static boolean isContactDisplay(String value) {
        return CONTACT_DISPLAY.equals(value);
    }

    public static boolean isLocationDisplay(String value) {
        return LOCATION_DISPLAY.equals(value);
    }

    static boolean isControlDisplay(String value) {
        return isPairingAcknowledgementDisplay(value)
                || isPairingReadyDisplay(value)
                || isPairingRejectionDisplay(value)
                || isGroupKeyStatusDisplay(value)
                || isStaticStickerDisplay(value)
                || isAttachmentDisplay(value)
                || isControlDeleteDisplay(value)
                || isDuplicateMessageDisplay(value)
                || isContactDisplay(value)
                || isLocationDisplay(value);
    }

    static DialogPreview.Kind controlPreviewKind(String value) {
        if (isPairingAcknowledgementDisplay(value)
                || isPairingReadyDisplay(value)) {
            return DialogPreview.Kind.PAIRING_ACK;
        }
        if (isPairingRejectionDisplay(value)) {
            return DialogPreview.Kind.PAIRING_REJECTED;
        }
        if (GROUP_KEY_DISTRIBUTED_DISPLAY.equals(value)) {
            return DialogPreview.Kind.GROUP_KEY_DISTRIBUTED;
        }
        if (GROUP_KEY_RECEIVED_DISPLAY.equals(value)) {
            return DialogPreview.Kind.GROUP_KEY_RECEIVED;
        }
        if (isStaticStickerDisplay(value)) {
            return DialogPreview.Kind.STATIC_STICKER;
        }
        if (isPhotoDisplay(value)) {
            return DialogPreview.Kind.PHOTO;
        }
        if (isFileDisplay(value)) {
            return DialogPreview.Kind.FILE;
        }
        if (isControlDeleteDisplay(value)) {
            return DialogPreview.Kind.CONTROL_DELETE;
        }
        if (isDuplicateMessageDisplay(value)) {
            return DialogPreview.Kind.DUPLICATE_MESSAGE;
        }
        if (isContactDisplay(value)) {
            return DialogPreview.Kind.CONTACT;
        }
        if (isLocationDisplay(value)) {
            return DialogPreview.Kind.LOCATION;
        }
        return DialogPreview.Kind.PLAINTEXT;
    }

    public static final class DialogPreview {
        public enum Kind {
            PLAINTEXT,
            PAIRING_ACK,
            PAIRING_REJECTED,
            GROUP_KEY_DISTRIBUTED,
            GROUP_KEY_RECEIVED,
            STATIC_STICKER,
            FILE,
            PHOTO,
            CONTROL_DELETE,
            DUPLICATE_MESSAGE,
            CONTACT,
            LOCATION,
            PAIRING_OFFER_SENT,
            PAIRING_OFFER_RECEIVED,
            OUTGOING_UNAVAILABLE
        }

        public final Kind kind;
        public final String plaintext;

        DialogPreview(Kind kind, String plaintext) {
            this.kind = kind;
            this.plaintext = plaintext;
        }
    }

    private static SecureContentCodec.StaticSticker requireStaticSticker(byte[] content) {
        if (content == null) {
            return null;
        }
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(content);
        if (decoded.type != SecureContentCodec.TYPE_STATIC_STICKER
                        && decoded.type != SecureContentCodec.TYPE_ANIMATED_STICKER
                        && decoded.type != SecureContentCodec.TYPE_VIDEO_STICKER
                || decoded.staticSticker == null) {
            throw new SecureChatException("secure content is not a static sticker", null);
        }
        return decoded.staticSticker;
    }

    private static SecureContentCodec.Attachment requireAttachment(byte[] content) {
        if (content == null) {
            return null;
        }
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(content);
        if ((decoded.type != SecureContentCodec.TYPE_FILE
                        && decoded.type != SecureContentCodec.TYPE_PHOTO)
                || decoded.attachment == null) {
            throw new SecureChatException("secure content is not an attachment", null);
        }
        return decoded.attachment;
    }

    private static SecureContentCodec.Contact requireContact(byte[] content) {
        if (content == null) {
            return null;
        }
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(content);
        if (decoded.type != SecureContentCodec.TYPE_CONTACT || decoded.contact == null) {
            throw new SecureChatException("secure content is not a contact", null);
        }
        return decoded.contact;
    }

    private static SecureContentCodec.GeoLocation requireLocation(byte[] content) {
        if (content == null) {
            return null;
        }
        SecureContentCodec.Decoded decoded = SecureContentCodec.decode(content);
        if (decoded.type != SecureContentCodec.TYPE_GEO_LOCATION || decoded.location == null) {
            throw new SecureChatException("secure content is not a location", null);
        }
        return decoded.location;
    }

    /**
     * Disables secure sending on this installation. Existing sessions and encrypted display copies
     * remain available so inbound secure history can still be rendered.
     */
    public void disable() { state.pause(account, peerUserId); }

    /**
     * Re-enables a locally paused chat without rotating keys or sending another pairing offer.
     *
     * <p>If app data was cleared or the app was reinstalled, the old session is absent and this
     * method deliberately returns false. That recovery requires an explicitly approved re-pair.</p>
     */
    public boolean resumeIfPaused() {
        synchronized (SESSION_LOCK) {
            requireCurrentIdentity();
            if (!state.isPaused(account, peerUserId)) {
                return false;
            }
            if (peerUserId > 0 && !store.containsSession(peerAddress)) {
                return false;
            }
            state.markPaired(account, peerUserId);
            if (peerUserId < 0) {
                state.setGroupKeyNeedsDistribution(account, peerUserId, true);
            }
            return true;
        }
    }

    public String getOwnFingerprint() {
        requireCurrentIdentity();
        return fingerprint(store.getIdentityKeyPair().getPublicKey().serialize());
    }

    public String getTrustedFingerprint() {
        IdentityKey trusted = store.getIdentity(peerAddress);
        return trusted == null ? null : fingerprint(trusted.serialize());
    }

    public String getPendingFingerprint() {
        String carrier = state.getPendingCarrier(account, peerUserId);
        if (carrier == null) {
            return null;
        }
        SecureCarrierCodec.Decoded decoded =
                requireCarrier(carrier, SecureCarrierCodec.TYPE_PREKEY_BUNDLE);
        return fingerprint(SecurePreKeyBundleCodec.decode(decoded.payload)
                .getIdentityKey().serialize());
    }

    public long getTrustedRecoveryGeneration() {
        SecureRecoveryGenerationStore.Record recovery =
                recoveryStore.getVerifiedPeer(account, peerUserId);
        return recovery == null ? 0 : recovery.generation;
    }

    public long getPendingRecoveryGeneration() {
        SecureRecoveryGenerationStore.Record recovery = getPendingRecovery();
        return recovery == null ? 0 : recovery.generation;
    }

    public String getPendingRecoveryId() {
        SecureRecoveryGenerationStore.Record recovery = getPendingRecovery();
        return recovery == null ? null : recovery.recoveryId.toString();
    }

    private SecureRecoveryGenerationStore.Record getPendingRecovery() {
        String carrier = state.getPendingCarrier(account, peerUserId);
        if (carrier == null) {
            return null;
        }
        SecureCarrierCodec.Decoded decoded =
                requireCarrier(carrier, SecureCarrierCodec.TYPE_PREKEY_BUNDLE);
        return SecurePreKeyBundleCodec.decodeOffer(decoded.payload).recovery;
    }

    /** Replaces a changed remote identity only after an explicit fingerprint confirmation. */
    public void acceptPendingIdentity() {
        synchronized (SESSION_LOCK) {
            requireCurrentIdentity();
            String carrier = state.getPendingCarrier(account, peerUserId);
            if (!state.isIdentityPending(account, peerUserId) || carrier == null) {
                throw new SecureChatException("no pending contact identity", null);
            }
            SecureCarrierCodec.Decoded decoded =
                    requireCarrier(carrier, SecureCarrierCodec.TYPE_PREKEY_BUNDLE);
            SecurePreKeyBundleCodec.DecodedOffer offer =
                    SecurePreKeyBundleCodec.decodeOffer(decoded.payload);
            if (peerUserId <= 0
                    || offer.ownerUserId != peerUserId
                    || offer.recipientUserId <= 0
                    || offer.recipientUserId == peerUserId) {
                throw new SecureChatException("pending pairing offer failed participant binding", null);
            }
            PreKeyBundle remote = offer.preKeyBundle;
            SecureChatState.PendingKind pendingKind =
                    state.getPendingKind(account, peerUserId);
            IdentityKey oldIdentity = store.getIdentity(peerAddress);
            boolean hadSession = store.containsSession(peerAddress);
            SessionRecord oldSession = hadSession ? store.loadSession(peerAddress) : null;
            SecureRecoveryGenerationStore.Record oldRecovery =
                    recoveryStore.getVerifiedPeer(account, peerUserId);
            try {
                if (pendingKind == SecureChatState.PendingKind.RECOVERY_ADVANCE) {
                    if (offer.recovery == null) {
                        throw new SecurityException("recovery offer lost authenticated metadata");
                    }
                    recoveryStore.recordVerifiedPeer(account, peerUserId, offer.recovery);
                } else {
                    recoveryStore.replaceVerifiedPeerAfterIdentityChange(
                            account, peerUserId, offer.recovery);
                }
                store.deleteSession(peerAddress);
                if (oldIdentity != null) {
                    store.deleteIdentity(peerAddress);
                }
                store.saveIdentity(peerAddress, remote.getIdentityKey());
                sessions.establish(peerAddress, remote);
                state.approvePendingIdentity(account, peerUserId);
                state.clearMemberGroupKeyDistributions(account, peerUserId);
                clearFailedDecryptCache(account, peerUserId);
            } catch (Exception error) {
                try {
                    store.deleteSession(peerAddress);
                    store.deleteIdentity(peerAddress);
                    if (oldIdentity != null) {
                        store.saveIdentity(peerAddress, oldIdentity);
                    }
                    if (hadSession) {
                        store.storeSession(peerAddress, oldSession);
                    }
                    recoveryStore.restoreVerifiedPeer(account, peerUserId, oldRecovery);
                } catch (RuntimeException rollbackError) {
                    error.addSuppressed(rollbackError);
                }
                throw new SecureChatException("cannot replace contact secure identity", error);
            }
        }
    }

    public void rejectPendingIdentity() {
        synchronized (SESSION_LOCK) {
            requireCurrentIdentity();
            if (!state.isIdentityPending(account, peerUserId)) {
                return;
            }
            // The old ratchet cannot be resumed after the contact rotated their identity. Keep the
            // old trusted fingerprint for comparison, but force the next shield tap to send a fresh
            // pairing offer instead of promoting a dead session back to PROTECTED.
            store.deleteSession(peerAddress);
            state.rejectPendingIdentity(account, peerUserId);
        }
    }

    private void pauseAfterPairingRejection() {
        // A rejection answers the currently outstanding offer. Historical cached rejections must
        // not pause a newer successfully paired session every time Telegram rebuilds the chat or
        // dialog preview.
        if (!state.isWaiting(account, peerUserId)) {
            return;
        }
        // Decrypting the negative acknowledgement creates a responder session. The rejecting
        // device deliberately did not persist its matching temporary session, so retaining this
        // half-session would make "resume" appear successful while all later messages fail.
        store.deleteSession(peerAddress);
        state.pause(account, peerUserId);
    }

    /**
     * Destroys the installation-wide secure identity and every protocol session.
     * Telegram account data and Keystore-encrypted local display copies are not modified.
     */
    public static String resetOwnIdentity(Context context) {
        return resetOwnIdentity(context, 0);
    }

    public static String resetOwnIdentity(Context context, int account) {
        synchronized (SESSION_LOCK) {
            Context appContext = context.getApplicationContext();
            KeystoreSignalProtocolStore.resetProtocolState(appContext, account);
            SecureChatState chatState = new SecureChatState(appContext);
            chatState.resetForNewIdentity(account);
            clearFailedDecryptCache();
            SecureSessionManager.getInstance(appContext, account).clear();
            new SecureRecoveryGenerationStore(appContext, account)
                    .advanceLocalIdentity(generationForEpoch(chatState.getIdentityEpoch(account)));
            return fingerprint(new KeystoreSignalProtocolStore(appContext, account)
                    .getIdentityKeyPair().getPublicKey().serialize());
        }
    }

    static long generationForEpoch(long identityEpoch) {
        if (identityEpoch < 0 || identityEpoch == Long.MAX_VALUE) {
            throw new SecureChatException("invalid secure identity epoch", null);
        }
        return identityEpoch + 1;
    }

    private void requireCurrentIdentity() {
        if (isStale()) {
            throw new SecureChatException("secure identity was reset; recreate chat engine", null);
        }
    }

    private byte[] decryptInboundPayload(
            SecureCarrierCodec.Decoded decoded, long senderUserId) throws Exception {
        if (peerUserId < 0) {
            SignalProtocolAddress senderAddress =
                    new SignalProtocolAddress("telegram-user-" + senderUserId, 1);
            requireInboundGroupSenderAllowed(
                    state.isIdentityPending(account, senderUserId),
                    store.getIdentity(senderAddress) != null);
            return sessions.decryptGroup(
                    senderAddress, groupDistributionId(peerUserId), decoded.payload);
        }
        int libsignalType;
        if (decoded.type == SecureCarrierCodec.TYPE_PREKEY) {
            libsignalType = LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY;
        } else {
            libsignalType = LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
        }
        repairBogusPairedStateIfNeeded();
        requireInboundSessionAllowed(
                peerUserId,
                isPaired(),
                state.isWaiting(account, peerUserId),
                state.isIdentityPending(account, peerUserId),
                store.containsSession(peerAddress),
                store.getIdentity(peerAddress) != null);
        return sessions.decrypt(
                peerAddress,
                new LibsignalSessionAdapter.EncryptedMessage(libsignalType, decoded.payload));
    }

    static void requireInboundGroupSenderAllowed(
            boolean senderIdentityPending, boolean hasTrustedSenderIdentity) {
        if (senderIdentityPending) {
            throw new SecureChatException("group sender identity requires verification", null);
        }
        if (!hasTrustedSenderIdentity) {
            throw new SecureChatException("group sender identity is not verified", null);
        }
    }

    static void requireInboundSessionAllowed(
            long peerUserId,
            boolean paired,
            boolean waiting,
            boolean identityPending,
            boolean hasSession,
            boolean hasTrustedIdentity) {
        if (peerUserId <= 0) {
            return;
        }
        if (identityPending) {
            throw new SecureChatException("new contact identity requires verification", null);
        }
        if (!paired && !waiting && !hasSession && !hasTrustedIdentity) {
            throw new SecureChatException("unsolicited secure message before pairing", null);
        }
    }

    private static String fingerprint(byte[] serializedIdentity) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(serializedIdentity);
            StringBuilder compact = new StringBuilder(48);
            for (int i = 0; i < 24; i++) {
                compact.append(Character.forDigit((digest[i] >>> 4) & 0x0f, 16));
                compact.append(Character.forDigit(digest[i] & 0x0f, 16));
            }
            StringBuilder grouped = new StringBuilder(59);
            for (int i = 0; i < compact.length(); i += 4) {
                if (grouped.length() > 0) grouped.append(' ');
                grouped.append(compact, i, i + 4);
            }
            return grouped.toString();
        } catch (Exception e) {
            throw new AssertionError("SHA-256 is unavailable", e);
        }
    }

    static void requireValidInboundSender(long peerUserId, long senderUserId) {
        if (peerUserId == 0) {
            throw new SecureChatException("invalid peer dialog ID", null);
        }
        if (peerUserId < 0 && senderUserId <= 0) {
            throw new SecureChatException("group message requires positive sender user ID", null);
        }
        if (peerUserId > 0) {
            if (senderUserId <= 0) {
                throw new SecureChatException("1:1 message requires positive sender user ID", null);
            }
            if (senderUserId != peerUserId) {
                throw new SecureChatException("1:1 message sender does not match peer dialog", null);
            }
        }
    }

    private static SecureCarrierCodec.Decoded requireCarrier(String text, int type) {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(text);
        if (decoded == null || decoded.type != type) throw new IllegalArgumentException("expected secure pairing offer");
        return decoded;
    }

    private static String strictUtf8(byte[] value) throws CharacterCodingException {
        CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value));
        return chars.toString();
    }

    public static final class SecureChatException extends RuntimeException {
        SecureChatException(String message, Throwable cause) { super(message, cause); }
    }
}
