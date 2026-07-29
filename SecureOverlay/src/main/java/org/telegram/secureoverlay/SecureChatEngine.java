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
    private static final Object DECRYPT_LOCK = new Object();

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

    public enum Mode {
        OFF,
        WAITING,
        PAUSED,
        IDENTITY_CHANGED,
        PROTECTED
    }

    public enum PairingOfferResult {
        ACCEPTED_INITIAL,
        SAME_IDENTITY,
        IDENTITY_CHANGE_PENDING,
        STALE
    }

    private final int account;
    private final long peerUserId;
    private final KeystoreSignalProtocolStore store;
    private final LibsignalSessionAdapter sessions;
    private final SecureChatState state;
    private final SecureLocalTextStore localText;
    private final SecureLocalContentStore localContent;
    private final SignalProtocolAddress peerAddress;
    private final long identityEpoch;

    public SecureChatEngine(Context context, int account, long peerUserId) {
        if (account < 0 || peerUserId <= 0) throw new IllegalArgumentException("secure chats require an account and user peer");
        this.account = account;
        this.peerUserId = peerUserId;
        Context appContext = context.getApplicationContext();
        state = new SecureChatState(appContext);
        new SecureRecoveryGenerationStore(appContext)
                .ensureLocalIdentity(generationForEpoch(state.getIdentityEpoch()));
        store = new KeystoreSignalProtocolStore(appContext);
        peerAddress = new SignalProtocolAddress("telegram-user-" + peerUserId, 1);
        sessions = new LibsignalSessionAdapter(store, new SignalProtocolAddress("local-account-" + account, 1));
        localText = new SecureLocalTextStore(appContext, account, peerUserId);
        localContent =
                new SecureLocalContentStore(appContext, account, peerUserId);
        identityEpoch = state.getIdentityEpoch();
    }

    /** Creates a public pairing offer to send as a normal Telegram text message. */
    public String createPairingOffer() {
        requireCurrentIdentity();
        if (state.isIdentityPending(account, peerUserId)) {
            throw new SecureChatException("new contact identity requires verification", null);
        }
        String carrier = SecureCarrierCodec.encode(
                SecureCarrierCodec.TYPE_PREKEY_BUNDLE, SecurePreKeyBundleCodec.encode(store));
        state.markWaiting(account, peerUserId);
        return carrier;
    }

    /**
     * Validates and classifies a received pairing offer.
     *
     * <p>An initial offer may be accepted automatically only while secure mode is off. A changed
     * identity is persisted as pending and secure sending remains blocked until the user compares
     * fingerprints and explicitly approves it.</p>
     */
    public PairingOfferResult receivePairingOffer(String carrier, int messageId) {
        requireCurrentIdentity();
        if (messageId <= 0) {
            throw new IllegalArgumentException("pairing message id must be positive");
        }
        SecureCarrierCodec.Decoded decoded = requireCarrier(carrier, SecureCarrierCodec.TYPE_PREKEY_BUNDLE);
        PreKeyBundle remote = SecurePreKeyBundleCodec.decode(decoded.payload);
        if (state.isIdentityPending(account, peerUserId)
                && state.getPendingMessageId(account, peerUserId) == messageId
                && carrier.equals(state.getPendingCarrier(account, peerUserId))) {
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
            // Sending our own offer moves the local UI to WAITING without discarding the
            // established ratchet. A matching offer from the already trusted contact must
            // complete that state and produce an authenticated acknowledgement. Allow the
            // equal-id case as a one-time repair for clients that recorded the offer before
            // this transition existed; history reload then finishes pairing automatically.
            if (getMode() == Mode.WAITING) {
                try {
                    if (!store.containsSession(peerAddress)) {
                        sessions.establish(peerAddress, remote);
                    }
                    state.markPaired(account, peerUserId);
                } catch (Exception e) {
                    throw new SecureChatException(
                            "cannot restore secure chat with trusted identity", e);
                }
            }
            state.recordPairingMessage(account, peerUserId, messageId);
            return PairingOfferResult.SAME_IDENTITY;
        }
        if (trusted != null) {
            state.markIdentityPending(account, peerUserId, carrier, messageId);
            return PairingOfferResult.IDENTITY_CHANGE_PENDING;
        }
        if (!canAutoAcceptPairingOffer()) {
            return PairingOfferResult.STALE;
        }
        try {
            sessions.establish(peerAddress, remote);
            state.markPaired(account, peerUserId);
            state.recordPairingMessage(account, peerUserId, messageId);
            return PairingOfferResult.ACCEPTED_INITIAL;
        } catch (Exception e) {
            throw new SecureChatException("cannot establish secure chat", e);
        }
    }

    public boolean isPaired() { return state.isPaired(account, peerUserId); }

    public Mode getMode() {
        if (state.isIdentityPending(account, peerUserId)) {
            return Mode.IDENTITY_CHANGED;
        }
        if (state.isPaired(account, peerUserId)) {
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

    /** A locally paused chat never silently accepts a remote pairing offer. */
    public boolean canAutoAcceptPairingOffer() {
        return getMode() == Mode.OFF;
    }

    public boolean isStale() {
        return identityEpoch != state.getIdentityEpoch();
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

    public SecureContentCodec.StaticSticker decryptStaticStickerManifest(String carrier) {
        synchronized (DECRYPT_LOCK) {
            SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
            if (decoded == null || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
                throw new SecureChatException("secure sticker carrier is invalid", null);
            }
            try {
                byte[] content = localContent.loadIncoming(carrier);
                if (content == null) {
                    int libsignalType = decoded.type == SecureCarrierCodec.TYPE_PREKEY
                            ? LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                            : LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
                    content = sessions.decrypt(
                            peerAddress,
                            new LibsignalSessionAdapter.EncryptedMessage(
                                    libsignalType, decoded.payload));
                    SecureContentCodec.StaticSticker sticker = requireStaticSticker(content);
                    localContent.rememberIncoming(carrier, content);
                    localText.rememberIncoming(carrier, STATIC_STICKER_DISPLAY);
                    if (!state.isPaused(account, peerUserId)
                            && !state.isIdentityPending(account, peerUserId)) {
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
        if (!isPaired()) {
            throw new SecureChatException("secure chat is not paired", null);
        }
        byte[] content = SecureContentCodec.encodeAttachment(attachment);
        String display = attachment.photo ? PHOTO_DISPLAY : FILE_DISPLAY;
        String carrier = encryptAndRemember(content, display);
        try {
            localContent.rememberOutgoing(carrier, content);
            return carrier;
        } catch (Exception e) {
            throw new SecureChatException("cannot cache secure attachment manifest", e);
        }
    }

    public SecureContentCodec.Attachment getOutgoingAttachment(String carrier) {
        try {
            return requireAttachment(localContent.loadOutgoing(carrier));
        } catch (Exception e) {
            throw new SecureChatException("cannot load outgoing secure attachment", e);
        }
    }

    public SecureContentCodec.Attachment decryptAttachmentManifest(String carrier) {
        synchronized (DECRYPT_LOCK) {
            SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
            if (decoded == null || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
                throw new SecureChatException("secure attachment carrier is invalid", null);
            }
            try {
                byte[] content = localContent.loadIncoming(carrier);
                if (content == null) {
                    int libsignalType = decoded.type == SecureCarrierCodec.TYPE_PREKEY
                            ? LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                            : LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
                    content = sessions.decrypt(
                            peerAddress,
                            new LibsignalSessionAdapter.EncryptedMessage(
                                    libsignalType, decoded.payload));
                    SecureContentCodec.Attachment attachment =
                            requireAttachment(content);
                    localContent.rememberIncoming(carrier, content);
                    localText.rememberIncoming(
                            carrier, attachment.photo ? PHOTO_DISPLAY : FILE_DISPLAY);
                    if (!state.isPaused(account, peerUserId)
                            && !state.isIdentityPending(account, peerUserId)) {
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
        return encryptAndRemember(PAIRING_ACK_PLAINTEXT, PAIRING_ACK_DISPLAY);
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
                    PAIRING_REJECTED_PLAINTEXT,
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
        try {
            LibsignalSessionAdapter.EncryptedMessage encrypted = sessionSource.encrypt(
                    peerAddress, protocolPlaintext);
            int carrierType = encrypted.type == LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY
                    ? SecureCarrierCodec.TYPE_PREKEY : SecureCarrierCodec.TYPE_WHISPER;
            String carrier = SecureCarrierCodec.encode(carrierType, encrypted.serialized);
            // Persist before handing the carrier to Telegram. If this fails, do not send a message
            // that this client cannot render locally after a reload.
            localText.rememberOutgoing(carrier, localDisplayText);
            return carrier;
        } catch (Exception e) {
            throw new SecureChatException("cannot encrypt secure text", e);
        }
    }

    /**
     * Returns this installation's encrypted local copy for an outbound carrier.
     *
     * <p>A missing result means the message was authored before this cache existed or by another
     * linked installation. It must not be passed to the inbound ratchet.</p>
     */
    public String getOutgoingText(String carrier) {
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

    /** Decrypts a recognized message. Successful first contact activates secure mode for the recipient. */
    public String decryptText(String carrier) {
        synchronized (DECRYPT_LOCK) {
            SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
            if (decoded == null) return null;
            if (decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
                throw new SecureChatException("pairing offer requires explicit acceptance", null);
            }
            try {
                String cached = localText.loadIncoming(carrier);
                if (cached != null) {
                    if (isPairingRejectionDisplay(cached)) {
                        pauseAfterPairingRejection();
                    } else if (!isPaired()
                            && !state.isPaused(account, peerUserId)
                            && !state.isIdentityPending(account, peerUserId)) {
                        state.markPaired(account, peerUserId);
                    }
                    return cached;
                }
                int libsignalType = decoded.type == SecureCarrierCodec.TYPE_PREKEY
                        ? LibsignalSessionAdapter.MESSAGE_TYPE_PRE_KEY : LibsignalSessionAdapter.MESSAGE_TYPE_WHISPER;
                byte[] plain = sessions.decrypt(peerAddress, new LibsignalSessionAdapter.EncryptedMessage(libsignalType, decoded.payload));
                String result;
                if (SecureContentCodec.isVersioned(plain)) {
                    SecureContentCodec.Decoded content = SecureContentCodec.decode(plain);
                    if (content.type == SecureContentCodec.TYPE_TEXT) {
                        result = content.text;
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
                    } else {
                        throw new SecureChatException("unsupported secure content", null);
                    }
                } else {
                    // Backward compatibility for encrypted beta messages sent before FSC1.
                    result = strictUtf8(plain);
                }
                if (PAIRING_ACK_PLAINTEXT.equals(result)) {
                    result = PAIRING_ACK_DISPLAY;
                } else if (PAIRING_REJECTED_PLAINTEXT.equals(result)) {
                    result = PAIRING_REJECTED_DISPLAY;
                }
                // Cache the verified plaintext before returning it to Telegram's in-memory message view.
                // A history reload then avoids replaying the same message through the ratchet.
                localText.rememberIncoming(carrier, result);
                if (isPairingRejectionDisplay(result)) {
                    pauseAfterPairingRejection();
                } else if (!state.isPaused(account, peerUserId)
                        && !state.isIdentityPending(account, peerUserId)) {
                    state.markPaired(account, peerUserId);
                }
                return result;
            } catch (SecureChatException e) {
                throw e;
            } catch (Exception e) {
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
    public DialogPreview resolveDialogPreview(String carrier, boolean outgoing) {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null) {
            return null;
        }
        if (decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
            return new DialogPreview(
                    outgoing
                            ? DialogPreview.Kind.PAIRING_OFFER_SENT
                            : DialogPreview.Kind.PAIRING_OFFER_RECEIVED,
                    null);
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
        String plaintext = decryptText(carrier);
        return new DialogPreview(
                controlPreviewKind(plaintext),
                isControlDisplay(plaintext) ? null : plaintext);
    }

    public static boolean isPairingAcknowledgementDisplay(String value) {
        return PAIRING_ACK_DISPLAY.equals(value);
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

    private static boolean isControlDisplay(String value) {
        return isPairingAcknowledgementDisplay(value)
                || isPairingRejectionDisplay(value)
                || isStaticStickerDisplay(value)
                || isAttachmentDisplay(value);
    }

    private static DialogPreview.Kind controlPreviewKind(String value) {
        if (isPairingAcknowledgementDisplay(value)) {
            return DialogPreview.Kind.PAIRING_ACK;
        }
        if (isPairingRejectionDisplay(value)) {
            return DialogPreview.Kind.PAIRING_REJECTED;
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
        return DialogPreview.Kind.PLAINTEXT;
    }

    public static final class DialogPreview {
        public enum Kind {
            PLAINTEXT,
            PAIRING_ACK,
            PAIRING_REJECTED,
            STATIC_STICKER,
            FILE,
            PHOTO,
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
        requireCurrentIdentity();
        if (!state.isPaused(account, peerUserId) || !store.containsSession(peerAddress)) {
            return false;
        }
        state.markPaired(account, peerUserId);
        return true;
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

    /** Replaces a changed remote identity only after an explicit fingerprint confirmation. */
    public void acceptPendingIdentity() {
        requireCurrentIdentity();
        String carrier = state.getPendingCarrier(account, peerUserId);
        if (!state.isIdentityPending(account, peerUserId) || carrier == null) {
            throw new SecureChatException("no pending contact identity", null);
        }
        SecureCarrierCodec.Decoded decoded =
                requireCarrier(carrier, SecureCarrierCodec.TYPE_PREKEY_BUNDLE);
        PreKeyBundle remote = SecurePreKeyBundleCodec.decode(decoded.payload);
        IdentityKey oldIdentity = store.getIdentity(peerAddress);
        boolean hadSession = store.containsSession(peerAddress);
        SessionRecord oldSession = hadSession ? store.loadSession(peerAddress) : null;
        try {
            store.deleteSession(peerAddress);
            if (oldIdentity != null) {
                store.deleteIdentity(peerAddress);
            }
            sessions.establish(peerAddress, remote);
            state.approvePendingIdentity(account, peerUserId);
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
            } catch (RuntimeException rollbackError) {
                error.addSuppressed(rollbackError);
            }
            throw new SecureChatException("cannot replace contact secure identity", error);
        }
    }

    public void rejectPendingIdentity() {
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
        Context appContext = context.getApplicationContext();
        KeystoreSignalProtocolStore.resetProtocolState(appContext);
        SecureChatState chatState = new SecureChatState(appContext);
        chatState.resetForNewIdentity();
        new SecureRecoveryGenerationStore(appContext)
                .advanceLocalIdentity(generationForEpoch(chatState.getIdentityEpoch()));
        return fingerprint(new KeystoreSignalProtocolStore(appContext)
                .getIdentityKeyPair().getPublicKey().serialize());
    }

    private static long generationForEpoch(long identityEpoch) {
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
