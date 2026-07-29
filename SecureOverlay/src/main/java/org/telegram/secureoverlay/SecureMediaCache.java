package org.telegram.secureoverlay;

import java.io.File;
import java.util.Arrays;
import java.util.Comparator;

/** Small bounded cache policy for authenticated media and encrypted upload staging files. */
public final class SecureMediaCache {
    private SecureMediaCache() {}

    /**
     * Marks {@code activeFile} as recently used and deletes oldest siblings until both limits
     * hold. The active file is never deleted; Android may still clear the whole cache directory.
     */
    public static void touchAndPrune(
            File activeFile, int maximumFiles, long maximumBytes) {
        if (activeFile == null
                || !activeFile.isFile()
                || maximumFiles < 1
                || maximumBytes < 1) {
            return;
        }
        activeFile.setLastModified(System.currentTimeMillis());
        File directory = activeFile.getParentFile();
        File[] files = directory == null ? null : directory.listFiles(File::isFile);
        if (files == null || files.length == 0) {
            return;
        }
        Arrays.sort(files, Comparator
                .comparingLong(File::lastModified)
                .thenComparing(File::getName));
        long totalBytes = 0;
        int totalFiles = 0;
        for (File file : files) {
            totalBytes += Math.max(0, file.length());
            totalFiles++;
        }
        for (File file : files) {
            if (totalFiles <= maximumFiles && totalBytes <= maximumBytes) {
                break;
            }
            if (file.equals(activeFile)) {
                continue;
            }
            long bytes = Math.max(0, file.length());
            if (file.delete()) {
                totalBytes -= bytes;
                totalFiles--;
            }
        }
    }
}
