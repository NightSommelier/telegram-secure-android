package org.telegram.secureoverlay;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import org.junit.Test;

public final class SecureEditRollbackJvmTest {
    @Test
    public void postDispatchEditRollbackMethodsAreDeprecatedAndSafeOnNull() throws Exception {
        Method textRollback = SecureChatEngine.class.getDeclaredMethod(
                "rollbackTextEdit", SecureChatEngine.TextEditTransport.class);
        Method attachmentRollback = SecureChatEngine.class.getDeclaredMethod(
                "rollbackAttachmentEdit", SecureChatEngine.AttachmentEditTransport.class);

        assertNotNull(textRollback.getAnnotation(Deprecated.class));
        assertNotNull(attachmentRollback.getAnnotation(Deprecated.class));

        SecureChatEngine.TextEditTransport textTransport =
                new SecureChatEngine.TextEditTransport(
                        "TGS1:carrier", new byte[] {1, 2}, new byte[] {3, 4});
        SecureChatEngine.AttachmentEditTransport attachmentTransport =
                new SecureChatEngine.AttachmentEditTransport(
                        "TGS1:attachment", new byte[] {5, 6}, new byte[] {7, 8});
        assertTrue(textTransport.textCarrier.startsWith("TGS1:"));
        assertTrue(attachmentTransport.attachmentCarrier.startsWith("TGS1:"));
    }
}
