package org.telegram.messenger;

import android.app.Activity;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Process;
import android.os.SystemClock;
import android.view.FrameMetrics;
import android.view.Window;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import org.telegram.secureoverlay.SecureChatEngine;
import org.telegram.secureoverlay.SecureChatState;
import org.telegram.secureoverlay.SecureNameMask;
import org.telegram.secureoverlay.SecureSessionManager;

/**
 * Lightweight background {@link Window.OnFrameMetricsAvailableListener} telemetry for diagnosing UI
 * jank without main-thread overhead or normal-frame allocations.
 */
public final class ForkFrameMetricsLogger {
    private static final long JANK_THRESHOLD_NS = 32_000_000L; // 32 ms
    private static final long SEVERE_JANK_THRESHOLD_NS = 100_000_000L; // 100 ms
    private static final long LOG_RATE_LIMIT_MS = 500L;

    private static final Object LOCK = new Object();
    private static final ConcurrentHashMap<Integer, Boolean> PREWARMED_ACCOUNTS =
            new ConcurrentHashMap<>();

    private static HandlerThread metricsThread;
    private static Handler metricsHandler;
    private static Window attachedWindow;
    private static Window.OnFrameMetricsAvailableListener activeListener;

    private static long sessionFrames;
    private static long sessionJankyFrames;
    private static long sessionMaxDurationNs;
    private static long lastLoggedUptimeMs;

    private ForkFrameMetricsLogger() {
    }

    public static void attach(Activity activity, int account) {
        if (activity != null) {
            prewarmSecureOverlayAsync(activity.getApplicationContext(), account);
        }
        if (activity == null
                || Build.VERSION.SDK_INT < Build.VERSION_CODES.N
                || (!BuildVars.LOGS_ENABLED && !BuildVars.DEBUG_VERSION)) {
            return;
        }
        Window window = activity.getWindow();
        if (window == null) {
            return;
        }
        synchronized (LOCK) {
            if (attachedWindow == window && activeListener != null) {
                return;
            }
            detachLocked();
            ensureHandlerLocked();
            sessionFrames = 0L;
            sessionJankyFrames = 0L;
            sessionMaxDurationNs = 0L;
            lastLoggedUptimeMs = 0L;
            activeListener = (win, frameMetrics, dropCountSinceLastInvocation) -> {
                if (frameMetrics == null) {
                    return;
                }
                long totalNs = frameMetrics.getMetric(FrameMetrics.TOTAL_DURATION);
                sessionFrames++;
                if (totalNs > sessionMaxDurationNs) {
                    sessionMaxDurationNs = totalNs;
                }
                if (totalNs < JANK_THRESHOLD_NS) {
                    return;
                }
                sessionJankyFrames++;
                long nowMs = SystemClock.uptimeMillis();
                if (totalNs < SEVERE_JANK_THRESHOLD_NS
                        && nowMs - lastLoggedUptimeMs < LOG_RATE_LIMIT_MS) {
                    return;
                }
                lastLoggedUptimeMs = nowMs;
                double totalMs = totalNs / 1_000_000.0;
                double inputMs = frameMetrics.getMetric(FrameMetrics.INPUT_HANDLING_DURATION) / 1_000_000.0;
                double animMs = frameMetrics.getMetric(FrameMetrics.ANIMATION_DURATION) / 1_000_000.0;
                double layoutMs = frameMetrics.getMetric(FrameMetrics.LAYOUT_MEASURE_DURATION) / 1_000_000.0;
                double drawMs = frameMetrics.getMetric(FrameMetrics.DRAW_DURATION) / 1_000_000.0;
                double syncMs = frameMetrics.getMetric(FrameMetrics.SYNC_DURATION) / 1_000_000.0;
                double commandMs = frameMetrics.getMetric(FrameMetrics.COMMAND_ISSUE_DURATION) / 1_000_000.0;
                FileLog.d(String.format(
                        Locale.US,
                        "FrameMetricsListener: janky frame total=%.1fms (input=%.1fms anim=%.1fms layout=%.1fms draw=%.1fms sync=%.1fms gpu=%.1fms dropped=%d)",
                        totalMs, inputMs, animMs, layoutMs, drawMs, syncMs, commandMs,
                        dropCountSinceLastInvocation));
            };
            try {
                window.addOnFrameMetricsAvailableListener(activeListener, metricsHandler);
                attachedWindow = window;
                FileLog.d("FrameMetricsListener: attached");
            } catch (Throwable error) {
                activeListener = null;
                attachedWindow = null;
                FileLog.e(error);
            }
        }
    }

    public static void detach(Activity activity) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return;
        }
        synchronized (LOCK) {
            if (activity != null && attachedWindow != null && activity.getWindow() != attachedWindow) {
                return;
            }
            detachLocked();
        }
    }

    private static void detachLocked() {
        if (attachedWindow != null && activeListener != null) {
            try {
                attachedWindow.removeOnFrameMetricsAvailableListener(activeListener);
            } catch (Throwable ignore) {
            }
            final long frames = sessionFrames;
            final long janky = sessionJankyFrames;
            final double maxMs = sessionMaxDurationNs / 1_000_000.0;
            if (metricsHandler != null) {
                metricsHandler.post(() -> FileLog.d(String.format(
                        Locale.US,
                        "FrameMetricsListener: session summary frames=%d janky>=32ms=%d max=%.1fms",
                        frames, janky, maxMs)));
            }
        }
        attachedWindow = null;
        activeListener = null;
    }

    private static void ensureHandlerLocked() {
        if (metricsThread == null || !metricsThread.isAlive()) {
            metricsThread = new HandlerThread(
                    "ForkFrameMetrics", Process.THREAD_PRIORITY_BACKGROUND);
            metricsThread.start();
            metricsHandler = new Handler(metricsThread.getLooper());
        }
    }

    private static void prewarmSecureOverlayAsync(Context appContext, int account) {
        if (appContext == null || account < 0) {
            return;
        }
        if (PREWARMED_ACCOUNTS.putIfAbsent(account, Boolean.TRUE) != null) {
            return;
        }
        Utilities.globalQueue.postRunnable(() -> {
            try {
                if (SecureChatEngine.isStateTemporarilyUnavailable(appContext)) {
                    PREWARMED_ACCOUNTS.remove(account);
                    return;
                }
                SecureNameMask.getOrGenerateKey(appContext);
                new SecureChatState(appContext);
                SecureSessionManager.getInstance(appContext, account).ensureInitialized();
            } catch (Throwable error) {
                PREWARMED_ACCOUNTS.remove(account);
                FileLog.e(error);
            }
        });
    }
}
