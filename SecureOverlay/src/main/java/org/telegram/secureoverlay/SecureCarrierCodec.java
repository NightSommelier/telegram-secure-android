package org.telegram.secureoverlay;

import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Strict, transport-neutral carrier for the private-chat MVP. */
public final class SecureCarrierCodec {
    public static final String PREFIX = "TGS1:";
    public static final int TYPE_PREKEY = 1;
    public static final int TYPE_WHISPER = 2;
    /** A public, signed one-time pre-key bundle used only to establish a chat. */
    public static final int TYPE_PREKEY_BUNDLE = 3;
    public static final int MAX_PAYLOAD_BYTES = 64 * 1024;

    private SecureCarrierCodec() {}

    public static boolean isMarked(String text) {
        return text != null && text.startsWith(PREFIX);
    }

    public static String encode(int type, byte[] payload) {
        if (!isKnownType(type)
                || payload == null || payload.length == 0 || payload.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("invalid secure carrier");
        }
        ByteBuffer bytes = ByteBuffer.allocate(6 + payload.length).order(ByteOrder.BIG_ENDIAN);
        bytes.put((byte) 1).put((byte) type).putInt(payload.length).put(payload);
        return PREFIX + Base64.encodeToString(bytes.array(), Base64.NO_WRAP | Base64.URL_SAFE);
    }

    public static Decoded decode(String text) {
        if (!isMarked(text)) return null;
        try {
            String encoded = text.substring(PREFIX.length());
            byte[] bytes = Base64.decode(encoded, Base64.NO_WRAP | Base64.URL_SAFE);
            if (!encoded.equals(Base64.encodeToString(bytes, Base64.NO_WRAP | Base64.URL_SAFE))) {
                throw new IllegalArgumentException("non-canonical secure carrier encoding");
            }
            if (bytes.length < 7) throw new IllegalArgumentException("truncated secure carrier");
            ByteBuffer in = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
            if (in.get() != 1) throw new IllegalArgumentException("unsupported secure carrier version");
            int type = in.get() & 0xff;
            int size = in.getInt();
            if (!isKnownType(type) || size <= 0 || size > MAX_PAYLOAD_BYTES || size != in.remaining()) {
                throw new IllegalArgumentException("invalid secure carrier fields");
            }
            byte[] payload = new byte[size];
            in.get(payload);
            return new Decoded(type, payload);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("malformed secure carrier", e);
        }
    }

    private static boolean isKnownType(int type) {
        return type == TYPE_PREKEY || type == TYPE_WHISPER || type == TYPE_PREKEY_BUNDLE;
    }

    public static final class Decoded {
        public final int type;
        public final byte[] payload;
        Decoded(int type, byte[] payload) { this.type = type; this.payload = payload; }
    }
}
