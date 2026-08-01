package org.telegram.secureoverlay;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Versioned application plaintext carried inside a libsignal message.
 *
 * <p>The outer {@link SecureCarrierCodec} describes the Signal message type. This codec describes
 * what that authenticated plaintext means. Keeping those layers separate lets media manifests be
 * added without changing the Telegram carrier or confusing media with control messages.</p>
 */
public final class SecureContentCodec {
    private static final String CAPTION_ABOVE_MARKER = "\u0001ForkSecureCaptionAbove\u0001";
    private static final String ALBUM_MARKER_PREFIX = "\u0002ForkSecureAlbum:";
    private static final String ALBUM_MARKER_SUFFIX = "\u0002";
    private static final byte[] MAGIC = new byte[] {'F', 'S', 'C', '1'};
    private static final int HEADER_BYTES = MAGIC.length + 1 + 4;
    private static final int MAX_CONTENT_BYTES = 16 * 1024;

    public static final int TYPE_TEXT = 1;
    public static final int TYPE_STATIC_STICKER = 2;
    public static final int TYPE_ANIMATED_STICKER = 3;
    public static final int TYPE_VIDEO_STICKER = 4;
    public static final int TYPE_FILE = 5;
    public static final int TYPE_PHOTO = 6;

    public static final int STICKER_FORMAT_WEBP = 1;
    public static final int STICKER_FORMAT_TGS = 2;
    public static final int STICKER_FORMAT_WEBM = 3;

    private SecureContentCodec() {}

    /** Encodes caption placement inside the authenticated manifest, never in Telegram plaintext. */
    public static String encodeCaption(String caption, boolean above) {
        return encodeCaption(caption, above, null);
    }

    /** Encodes caption placement and an optional encrypted-only album identifier. */
    public static String encodeCaption(String caption, boolean above, String albumId) {
        String value = caption == null ? "" : caption;
        String album = albumId == null || albumId.isEmpty()
                ? "" : ALBUM_MARKER_PREFIX + albumId + ALBUM_MARKER_SUFFIX;
        return (above ? CAPTION_ABOVE_MARKER : "") + album + value;
    }

    public static boolean isCaptionAbove(String caption) {
        return caption != null && caption.startsWith(CAPTION_ABOVE_MARKER);
    }

    public static String displayCaption(String caption) {
        if (caption == null) return "";
        String value = isCaptionAbove(caption)
                ? caption.substring(CAPTION_ABOVE_MARKER.length()) : caption;
        int markerEnd = albumMarkerEnd(value);
        return markerEnd < 0 ? value : value.substring(markerEnd);
    }

    /**
     * Rebuilds only the authenticated caption metadata while preserving the encrypted media
     * identity and ciphertext digest.  The album marker is intentionally carried forward so an
     * edited item remains in the same secure album.
     */
    public static Attachment withCaption(
            Attachment attachment, String caption, boolean above) {
        if (attachment == null) {
            throw new IllegalArgumentException("secure attachment is missing");
        }
        String albumId = albumId(attachment.caption);
        return new Attachment(
                attachment.mediaId,
                attachment.key,
                attachment.nonce,
                attachment.ciphertextSha256,
                attachment.plaintextSize,
                attachment.ciphertextSize,
                attachment.fileName,
                attachment.mimeType,
                encodeCaption(caption, above, albumId.isEmpty() ? null : albumId),
                attachment.width,
                attachment.height,
                attachment.photo);
    }

    /** Returns the authenticated album identifier, or an empty string for a standalone item. */
    public static String albumId(String caption) {
        if (caption == null) return "";
        String value = isCaptionAbove(caption)
                ? caption.substring(CAPTION_ABOVE_MARKER.length()) : caption;
        if (!value.startsWith(ALBUM_MARKER_PREFIX)) return "";
        int end = value.indexOf(ALBUM_MARKER_SUFFIX, ALBUM_MARKER_PREFIX.length());
        if (end < 0 || end == ALBUM_MARKER_PREFIX.length()
                || end - ALBUM_MARKER_PREFIX.length() > 64) {
            throw new IllegalArgumentException("invalid secure album marker");
        }
        String id = value.substring(ALBUM_MARKER_PREFIX.length(), end);
        if (!id.matches("[0-9a-fA-F]{32}")) {
            throw new IllegalArgumentException("invalid secure album identifier");
        }
        return id.toLowerCase(java.util.Locale.ROOT);
    }

    private static int albumMarkerEnd(String value) {
        if (!value.startsWith(ALBUM_MARKER_PREFIX)) return -1;
        int end = value.indexOf(ALBUM_MARKER_SUFFIX, ALBUM_MARKER_PREFIX.length());
        if (end < 0 || end - ALBUM_MARKER_PREFIX.length() != 32) return -1;
        String id = value.substring(ALBUM_MARKER_PREFIX.length(), end);
        return id.matches("[0-9a-fA-F]{32}") ? end + ALBUM_MARKER_SUFFIX.length() : -1;
    }

    public static byte[] encodeText(String text) {
        if (text == null || text.isEmpty()) {
            throw new IllegalArgumentException("secure text is empty");
        }
        byte[] payload = text.getBytes(StandardCharsets.UTF_8);
        return encode(TYPE_TEXT, payload);
    }

    public static byte[] encodeStaticSticker(StaticSticker sticker) {
        if (sticker == null || sticker.format != STICKER_FORMAT_WEBP) {
            throw new IllegalArgumentException("secure static sticker format is invalid");
        }
        return encodeSticker(sticker);
    }

    public static byte[] encodeSticker(StaticSticker sticker) {
        if (sticker == null) {
            throw new IllegalArgumentException("secure sticker is missing");
        }
        byte[] emoji = sticker.emoji.getBytes(StandardCharsets.UTF_8);
        validateStaticStickerFields(
                sticker.mediaId,
                sticker.key,
                sticker.nonce,
                sticker.ciphertextSha256,
                sticker.plaintextSize,
                sticker.ciphertextSize,
                sticker.width,
                sticker.height,
                emoji);
        ByteBuffer payload = ByteBuffer.allocate(
                        16 + 32 + 12 + 32 + 4 + 4 + 2 + 2 + 2 + emoji.length)
                .order(ByteOrder.BIG_ENDIAN);
        payload.put(sticker.mediaId);
        payload.put(sticker.key);
        payload.put(sticker.nonce);
        payload.put(sticker.ciphertextSha256);
        payload.putInt(sticker.plaintextSize);
        payload.putInt(sticker.ciphertextSize);
        payload.putShort((short) sticker.width);
        payload.putShort((short) sticker.height);
        payload.putShort((short) emoji.length);
        payload.put(emoji);
        return encode(contentTypeForStickerFormat(sticker.format), payload.array());
    }

    public static byte[] encodeAttachment(Attachment attachment) {
        if (attachment == null) {
            throw new IllegalArgumentException("secure attachment is missing");
        }
        byte[] fileName = attachment.fileName.getBytes(StandardCharsets.UTF_8);
        byte[] mimeType = attachment.mimeType.getBytes(StandardCharsets.US_ASCII);
        byte[] caption = attachment.caption.getBytes(StandardCharsets.UTF_8);
        validateAttachmentFields(
                attachment.mediaId,
                attachment.key,
                attachment.nonce,
                attachment.ciphertextSha256,
                attachment.plaintextSize,
                attachment.ciphertextSize,
                attachment.width,
                attachment.height,
                fileName,
                mimeType,
                caption,
                attachment.photo);
        ByteBuffer payload = ByteBuffer.allocate(
                        16 + 32 + 12 + 32 + 4 + 4 + 2 + 2 + 2 + 2 + 4
                                + fileName.length + mimeType.length + caption.length)
                .order(ByteOrder.BIG_ENDIAN);
        payload.put(attachment.mediaId);
        payload.put(attachment.key);
        payload.put(attachment.nonce);
        payload.put(attachment.ciphertextSha256);
        payload.putInt(attachment.plaintextSize);
        payload.putInt(attachment.ciphertextSize);
        payload.putShort((short) attachment.width);
        payload.putShort((short) attachment.height);
        payload.putShort((short) fileName.length);
        payload.putShort((short) mimeType.length);
        payload.putInt(caption.length);
        payload.put(fileName);
        payload.put(mimeType);
        payload.put(caption);
        return encode(attachment.photo ? TYPE_PHOTO : TYPE_FILE, payload.array());
    }

    public static Decoded decode(byte[] encoded) {
        if (encoded == null || encoded.length < HEADER_BYTES) {
            throw new IllegalArgumentException("truncated secure content");
        }
        ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        for (byte expected : MAGIC) {
            if (input.get() != expected) {
                throw new IllegalArgumentException("invalid secure content magic");
            }
        }
        int type = input.get() & 0xff;
        int size = input.getInt();
        if (!isKnownType(type)
                || size <= 0
                || size > MAX_CONTENT_BYTES
                || size != input.remaining()) {
            throw new IllegalArgumentException("invalid secure content fields");
        }
        byte[] payload = new byte[size];
        input.get(payload);
        if (type == TYPE_TEXT) {
            return Decoded.text(strictUtf8(payload));
        }
        if (isStickerType(type)) {
            return Decoded.sticker(decodeSticker(payload, stickerFormatForContentType(type)));
        }
        return Decoded.attachment(decodeAttachment(payload, type == TYPE_PHOTO));
    }

    /**
     * Old beta messages predate the typed inner envelope and contain plain UTF-8 directly.
     */
    public static boolean isVersioned(byte[] plaintext) {
        return plaintext != null
                && plaintext.length >= MAGIC.length
                && Arrays.equals(MAGIC, Arrays.copyOf(plaintext, MAGIC.length));
    }

    private static byte[] encode(int type, byte[] payload) {
        if (!isKnownType(type)
                || payload == null
                || payload.length == 0
                || payload.length > MAX_CONTENT_BYTES) {
            throw new IllegalArgumentException("invalid secure content payload");
        }
        ByteBuffer output = ByteBuffer.allocate(HEADER_BYTES + payload.length)
                .order(ByteOrder.BIG_ENDIAN);
        output.put(MAGIC);
        output.put((byte) type);
        output.putInt(payload.length);
        output.put(payload);
        return output.array();
    }

    private static boolean isKnownType(int type) {
        return type == TYPE_TEXT
                || type == TYPE_STATIC_STICKER
                || type == TYPE_ANIMATED_STICKER
                || type == TYPE_VIDEO_STICKER
                || type == TYPE_FILE
                || type == TYPE_PHOTO;
    }

    private static boolean isStickerType(int type) {
        return type == TYPE_STATIC_STICKER
                || type == TYPE_ANIMATED_STICKER
                || type == TYPE_VIDEO_STICKER;
    }

    private static StaticSticker decodeSticker(byte[] payload, int format) {
        final int fixedBytes = 16 + 32 + 12 + 32 + 4 + 4 + 2 + 2 + 2;
        if (payload.length < fixedBytes) {
            throw new IllegalArgumentException("truncated secure sticker manifest");
        }
        ByteBuffer input = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        byte[] mediaId = new byte[16];
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] digest = new byte[32];
        input.get(mediaId);
        input.get(key);
        input.get(nonce);
        input.get(digest);
        int plaintextSize = input.getInt();
        int ciphertextSize = input.getInt();
        int width = input.getShort() & 0xffff;
        int height = input.getShort() & 0xffff;
        int emojiSize = input.getShort() & 0xffff;
        if (emojiSize != input.remaining()) {
            throw new IllegalArgumentException("invalid secure sticker emoji length");
        }
        byte[] emoji = new byte[emojiSize];
        input.get(emoji);
        validateStaticStickerFields(
                mediaId,
                key,
                nonce,
                digest,
                plaintextSize,
                ciphertextSize,
                width,
                height,
                emoji);
        return new StaticSticker(
                mediaId,
                key,
                nonce,
                digest,
                plaintextSize,
                ciphertextSize,
                width,
                height,
                strictUtf8AllowEmpty(emoji),
                format);
    }

    private static void validateStaticStickerFields(
            byte[] mediaId,
            byte[] key,
            byte[] nonce,
            byte[] digest,
            int plaintextSize,
            int ciphertextSize,
            int width,
            int height,
            byte[] emoji) {
        if (mediaId == null
                || mediaId.length != 16
                || key == null
                || key.length != 32
                || nonce == null
                || nonce.length != 12
                || digest == null
                || digest.length != 32
                || plaintextSize <= 0
                || plaintextSize > SecureMediaCrypto.MAX_STATIC_STICKER_BYTES
                || ciphertextSize != plaintextSize + SecureMediaCrypto.GCM_TAG_BYTES
                || width <= 0
                || width > 512
                || height <= 0
                || height > 512
                || emoji == null
                || emoji.length > 64) {
            throw new IllegalArgumentException("invalid secure sticker manifest");
        }
        strictUtf8AllowEmpty(emoji);
    }

    private static Attachment decodeAttachment(byte[] payload, boolean photo) {
        final int fixedBytes = 16 + 32 + 12 + 32 + 4 + 4 + 2 + 2 + 2 + 2 + 4;
        if (payload.length < fixedBytes) {
            throw new IllegalArgumentException("truncated secure attachment manifest");
        }
        ByteBuffer input = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN);
        byte[] mediaId = new byte[16];
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] digest = new byte[32];
        input.get(mediaId);
        input.get(key);
        input.get(nonce);
        input.get(digest);
        int plaintextSize = input.getInt();
        int ciphertextSize = input.getInt();
        int width = input.getShort() & 0xffff;
        int height = input.getShort() & 0xffff;
        int fileNameSize = input.getShort() & 0xffff;
        int mimeTypeSize = input.getShort() & 0xffff;
        int captionSize = input.getInt();
        long variableSize = (long) fileNameSize + mimeTypeSize + captionSize;
        if (captionSize < 0 || variableSize != input.remaining()) {
            throw new IllegalArgumentException("invalid secure attachment metadata length");
        }
        byte[] fileName = new byte[fileNameSize];
        byte[] mimeType = new byte[mimeTypeSize];
        byte[] caption = new byte[captionSize];
        input.get(fileName);
        input.get(mimeType);
        input.get(caption);
        validateAttachmentFields(
                mediaId,
                key,
                nonce,
                digest,
                plaintextSize,
                ciphertextSize,
                width,
                height,
                fileName,
                mimeType,
                caption,
                photo);
        return new Attachment(
                mediaId,
                key,
                nonce,
                digest,
                plaintextSize,
                ciphertextSize,
                strictUtf8(fileName),
                new String(mimeType, StandardCharsets.US_ASCII),
                strictUtf8AllowEmpty(caption),
                width,
                height,
                photo);
    }

    private static void validateAttachmentFields(
            byte[] mediaId,
            byte[] key,
            byte[] nonce,
            byte[] digest,
            int plaintextSize,
            int ciphertextSize,
            int width,
            int height,
            byte[] fileName,
            byte[] mimeType,
            byte[] caption,
            boolean photo) {
        String decodedMimeType = mimeType == null
                ? "" : new String(mimeType, StandardCharsets.US_ASCII);
        boolean video = !photo && decodedMimeType.startsWith("video/");
        boolean dimensionsPresent = width != 0 || height != 0;
        boolean invalidDimensions = photo
                ? width <= 0 || width > 16384 || height <= 0 || height > 16384
                : dimensionsPresent && (!video
                        || width <= 0 || width > 16384 || height <= 0 || height > 16384);
        if (mediaId == null
                || mediaId.length != 16
                || key == null
                || key.length != 32
                || nonce == null
                || nonce.length != 12
                || digest == null
                || digest.length != 32
                || plaintextSize <= 0
                || plaintextSize > SecureMediaCrypto.MAX_ATTACHMENT_BYTES
                || ciphertextSize != plaintextSize + SecureMediaCrypto.GCM_TAG_BYTES
                || fileName == null
                || fileName.length == 0
                || fileName.length > 128
                || mimeType == null
                || mimeType.length == 0
                || mimeType.length > 127
                || caption == null
                || caption.length > 256
                || invalidDimensions) {
            throw new IllegalArgumentException("invalid secure attachment manifest");
        }
        String decodedFileName = strictUtf8(fileName);
        if (".".equals(decodedFileName)
                || "..".equals(decodedFileName)
                || decodedFileName.indexOf('/') >= 0
                || decodedFileName.indexOf('\\') >= 0
                || containsControl(decodedFileName)) {
            throw new IllegalArgumentException("unsafe secure attachment name");
        }
        if (!decodedMimeType.matches(
                "[a-z0-9][a-z0-9.+-]{0,62}/[a-z0-9][a-z0-9.+-]{0,62}")) {
            throw new IllegalArgumentException("invalid secure attachment MIME type");
        }
        strictUtf8AllowEmpty(caption);
    }

    private static boolean containsControl(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static int contentTypeForStickerFormat(int format) {
        if (format == STICKER_FORMAT_WEBP) {
            return TYPE_STATIC_STICKER;
        }
        if (format == STICKER_FORMAT_TGS) {
            return TYPE_ANIMATED_STICKER;
        }
        if (format == STICKER_FORMAT_WEBM) {
            return TYPE_VIDEO_STICKER;
        }
        throw new IllegalArgumentException("unknown secure sticker format");
    }

    private static int stickerFormatForContentType(int type) {
        if (type == TYPE_STATIC_STICKER) {
            return STICKER_FORMAT_WEBP;
        }
        if (type == TYPE_ANIMATED_STICKER) {
            return STICKER_FORMAT_TGS;
        }
        if (type == TYPE_VIDEO_STICKER) {
            return STICKER_FORMAT_WEBM;
        }
        throw new IllegalArgumentException("secure content is not a sticker");
    }

    private static String strictUtf8(byte[] value) {
        String result = strictUtf8AllowEmpty(value);
        if (result.isEmpty()) {
            throw new IllegalArgumentException("secure text is empty");
        }
        return result;
    }

    private static String strictUtf8AllowEmpty(byte[] value) {
        try {
            CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value));
            return chars.toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("secure text is not valid UTF-8", e);
        }
    }

    public static final class Decoded {
        public final int type;
        public final String text;
        public final StaticSticker staticSticker;
        public final Attachment attachment;

        private Decoded(
                int type, String text, StaticSticker staticSticker, Attachment attachment) {
            this.type = type;
            this.text = text;
            this.staticSticker = staticSticker;
            this.attachment = attachment;
        }

        private static Decoded text(String text) {
            return new Decoded(TYPE_TEXT, text, null, null);
        }

        private static Decoded sticker(StaticSticker sticker) {
            return new Decoded(
                    contentTypeForStickerFormat(sticker.format), null, sticker, null);
        }

        private static Decoded attachment(Attachment attachment) {
            return new Decoded(
                    attachment.photo ? TYPE_PHOTO : TYPE_FILE,
                    null,
                    null,
                    attachment);
        }
    }

    public static final class StaticSticker {
        public final byte[] mediaId;
        public final byte[] key;
        public final byte[] nonce;
        public final byte[] ciphertextSha256;
        public final int plaintextSize;
        public final int ciphertextSize;
        public final int width;
        public final int height;
        public final String emoji;
        public final int format;

        public StaticSticker(
                byte[] mediaId,
                byte[] key,
                byte[] nonce,
                byte[] ciphertextSha256,
                int plaintextSize,
                int ciphertextSize,
                int width,
                int height,
                String emoji) {
            this(
                    mediaId,
                    key,
                    nonce,
                    ciphertextSha256,
                    plaintextSize,
                    ciphertextSize,
                    width,
                    height,
                    emoji,
                    STICKER_FORMAT_WEBP);
        }

        public StaticSticker(
                byte[] mediaId,
                byte[] key,
                byte[] nonce,
                byte[] ciphertextSha256,
                int plaintextSize,
                int ciphertextSize,
                int width,
                int height,
                String emoji,
                int format) {
            this.mediaId = copy(mediaId);
            this.key = copy(key);
            this.nonce = copy(nonce);
            this.ciphertextSha256 = copy(ciphertextSha256);
            this.plaintextSize = plaintextSize;
            this.ciphertextSize = ciphertextSize;
            this.width = width;
            this.height = height;
            this.emoji = emoji == null ? "" : emoji;
            this.format = format;
            contentTypeForStickerFormat(format);
        }

        private static byte[] copy(byte[] value) {
            return value == null ? null : Arrays.copyOf(value, value.length);
        }
    }

    public static final class Attachment {
        public final byte[] mediaId;
        public final byte[] key;
        public final byte[] nonce;
        public final byte[] ciphertextSha256;
        public final int plaintextSize;
        public final int ciphertextSize;
        public final String fileName;
        public final String mimeType;
        public final String caption;
        public final int width;
        public final int height;
        public final boolean photo;

        public Attachment(
                byte[] mediaId,
                byte[] key,
                byte[] nonce,
                byte[] ciphertextSha256,
                int plaintextSize,
                int ciphertextSize,
                String fileName,
                String mimeType,
                String caption,
                int width,
                int height,
                boolean photo) {
            this.mediaId = StaticSticker.copy(mediaId);
            this.key = StaticSticker.copy(key);
            this.nonce = StaticSticker.copy(nonce);
            this.ciphertextSha256 = StaticSticker.copy(ciphertextSha256);
            this.plaintextSize = plaintextSize;
            this.ciphertextSize = ciphertextSize;
            this.fileName = fileName == null ? "" : fileName;
            this.mimeType = mimeType == null ? "" : mimeType;
            this.caption = caption == null ? "" : caption;
            this.width = width;
            this.height = height;
            this.photo = photo;
        }
    }
}
