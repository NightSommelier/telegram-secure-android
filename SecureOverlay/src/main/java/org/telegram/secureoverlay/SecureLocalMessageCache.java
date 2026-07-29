package org.telegram.secureoverlay;

import android.content.Context;

/**
 * Deletes device-local decrypted display and authenticated content copies for a Telegram carrier.
 *
 * <p>The four direction/type records are removed in one SharedPreferences commit. Protocol
 * identity, trust, and ratchet state are intentionally outside this boundary.</p>
 */
public final class SecureLocalMessageCache {
    private final int account;
    private final long peerUserId;
    private final KeystoreEncryptedBlobStore blobs;

    public SecureLocalMessageCache(Context context, int account, long peerUserId) {
        if (context == null || account < 0 || peerUserId <= 0) {
            throw new IllegalArgumentException(
                    "local secure cache requires an account and user peer");
        }
        this.account = account;
        this.peerUserId = peerUserId;
        blobs = new KeystoreEncryptedBlobStore(context.getApplicationContext());
    }

    /**
     * Removes all local copies for an encrypted carrier.
     *
     * @return {@code true} when the value was an encrypted carrier and cleanup was applied
     */
    public boolean forget(String carrier)
            throws KeystoreEncryptedBlobStore.StateStoreException {
        SecureCarrierCodec.Decoded decoded = SecureCarrierCodec.decode(carrier);
        if (decoded == null || decoded.type == SecureCarrierCodec.TYPE_PREKEY_BUNDLE) {
            return false;
        }
        String outgoingText = SecureLocalTextStore.key(
                SecureLocalTextStore.OUTGOING_PREFIX,
                account,
                peerUserId,
                carrier);
        String incomingText = SecureLocalTextStore.key(
                SecureLocalTextStore.INCOMING_PREFIX,
                account,
                peerUserId,
                carrier);
        String outgoingContent = SecureLocalContentStore.key(
                SecureLocalContentStore.OUTGOING_PREFIX,
                account,
                peerUserId,
                carrier);
        String incomingContent = SecureLocalContentStore.key(
                SecureLocalContentStore.INCOMING_PREFIX,
                account,
                peerUserId,
                carrier);
        blobs.deleteAll(
                outgoingText,
                incomingText,
                outgoingContent,
                incomingContent);
        SecureLocalTextStore.evictDisplayCopies(outgoingText, incomingText);
        return true;
    }

    /** Removes all local message copies for this account and peer, but preserves protocol state. */
    public void forgetPeer()
            throws KeystoreEncryptedBlobStore.StateStoreException {
        String outgoingText = scopedPrefix(SecureLocalTextStore.OUTGOING_PREFIX);
        String incomingText = scopedPrefix(SecureLocalTextStore.INCOMING_PREFIX);
        blobs.deletePrefixes(
                outgoingText,
                incomingText,
                scopedPrefix(SecureLocalContentStore.OUTGOING_PREFIX),
                scopedPrefix(SecureLocalContentStore.INCOMING_PREFIX));
        SecureLocalTextStore.evictDisplayPrefixes(outgoingText, incomingText);
    }

    private String scopedPrefix(String recordPrefix) {
        return recordPrefix + account + '.' + peerUserId + '.';
    }
}
