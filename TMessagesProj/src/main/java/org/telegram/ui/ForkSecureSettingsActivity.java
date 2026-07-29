package org.telegram.ui;

import static org.telegram.messenger.LocaleController.formatString;
import static org.telegram.messenger.LocaleController.getString;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.text.InputType;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.R;
import org.telegram.messenger.Utilities;
import org.telegram.secureoverlay.SecureChatEngine;
import org.telegram.secureoverlay.SecureChatState;
import org.telegram.secureoverlay.SecureIdentityBackupManager;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextDetailSettingsCell;
import org.telegram.ui.Cells.TextInfoPrivacyCell;
import org.telegram.ui.Cells.TextSettingsCell;
import org.telegram.ui.Components.BulletinFactory;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.SectionsScrollView;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * Account-level Fork-Secure identity and backup controls.
 *
 * <p>The backup is intentionally identity-only. This screen must not imply that Telegram history,
 * media, peer trust, or ratchet sessions are included in the archive.</p>
 */
public final class ForkSecureSettingsActivity extends BaseFragment {
    private static final int BACKUP_EXPORT_REQUEST = 8941;
    private static final int BACKUP_IMPORT_REQUEST = 8942;
    private static final int BACKUP_MAX_BYTES = 8192;

    private byte[] pendingBackupArchive;
    private TextDetailSettingsCell fingerprintCell;
    private TextSettingsCell generationCell;
    private TextSettingsCell protectedCountCell;
    private TextSettingsCell waitingCountCell;
    private TextSettingsCell verificationCountCell;
    private TextSettingsCell pausedCountCell;
    private TextSettingsCell restoreCell;

    @Override
    public View createView(Context context) {
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setAllowOverlayTitle(true);
        actionBar.setTitle(getString(R.string.ForkSecureSettingsTitle));
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                }
            }
        });

        FrameLayout frameLayout = new FrameLayout(context);
        fragmentView = frameLayout;
        frameLayout.setBackgroundColor(
                Theme.getColor(Theme.key_windowBackgroundGray, getResourceProvider()));

        LinearLayout content = new SectionsScrollView.SectionsLinearLayout(context);
        content.setOrientation(LinearLayout.VERTICAL);
        SectionsScrollView scrollView =
                new SectionsScrollView(context, content, getResourceProvider());
        scrollView.addView(content);
        frameLayout.addView(scrollView, LayoutHelper.createFrame(
                LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));
        actionBar.setAdaptiveBackground(scrollView);

        HeaderCell identityHeader = new HeaderCell(context, getResourceProvider());
        identityHeader.setText(getString(R.string.ForkSecureIdentitySection));
        content.addView(identityHeader);

        fingerprintCell = new TextDetailSettingsCell(context);
        fingerprintCell.setMultilineDetail(true);
        fingerprintCell.setTextAndValue(
                getString(R.string.ForkSecureFingerprint), "", true);
        content.addView(fingerprintCell, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT));

        generationCell = settingsCell(
                context, getString(R.string.ForkSecureRecoveryGeneration), true);
        content.addView(generationCell);

        TextSettingsCell exportCell = actionCell(
                context, getString(R.string.ForkSecureExportBackup), true);
        exportCell.setOnClickListener(view -> showExportPasswordDialog());
        content.addView(exportCell);

        restoreCell = actionCell(
                context, getString(R.string.ForkSecureImportBackup), false);
        restoreCell.setOnClickListener(view -> showRestoreAction());
        content.addView(restoreCell);

        TextInfoPrivacyCell backupScope = new TextInfoPrivacyCell(
                context, getResourceProvider());
        backupScope.setText(getString(R.string.ForkSecureBackupScope));
        content.addView(backupScope, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT));

        HeaderCell chatHeader = new HeaderCell(context, getResourceProvider());
        chatHeader.setText(getString(R.string.ForkSecureChatsSection));
        content.addView(chatHeader);

        protectedCountCell = settingsCell(
                context, getString(R.string.ForkSecureProtectedCount), true);
        content.addView(protectedCountCell);
        waitingCountCell = settingsCell(
                context, getString(R.string.ForkSecureWaitingCount), true);
        content.addView(waitingCountCell);
        verificationCountCell = settingsCell(
                context, getString(R.string.ForkSecureVerificationCount), true);
        content.addView(verificationCountCell);
        pausedCountCell = settingsCell(
                context, getString(R.string.ForkSecurePausedCount), false);
        content.addView(pausedCountCell);

        TextInfoPrivacyCell chatScope = new TextInfoPrivacyCell(
                context, getResourceProvider());
        chatScope.setText(getString(R.string.ForkSecureChatsInfo));
        content.addView(chatScope, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT));

        HeaderCell resetHeader = new HeaderCell(context, getResourceProvider());
        resetHeader.setText(getString(R.string.ForkSecureDangerZone));
        content.addView(resetHeader);

        TextSettingsCell resetCell = actionCell(
                context, getString(R.string.ForkSecureResetIdentity), false);
        resetCell.setTextColor(
                Theme.getColor(Theme.key_text_RedRegular, getResourceProvider()));
        resetCell.setOnClickListener(view -> confirmIdentityReset());
        content.addView(resetCell);

        TextInfoPrivacyCell resetInfo = new TextInfoPrivacyCell(
                context, getResourceProvider());
        resetInfo.setText(getString(R.string.ForkSecureResetAllBody));
        content.addView(resetInfo, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT));

        refreshState();
        return fragmentView;
    }

    @Override
    public void onResume() {
        super.onResume();
        refreshState();
    }

    @Override
    public void onFragmentDestroy() {
        clearPendingBackupArchive();
        super.onFragmentDestroy();
    }

    @Override
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        if (requestCode == BACKUP_EXPORT_REQUEST) {
            if (resultCode == Activity.RESULT_OK && data != null && data.getData() != null) {
                writeBackup(data.getData());
            } else {
                clearPendingBackupArchive();
            }
            return;
        }
        if (requestCode == BACKUP_IMPORT_REQUEST
                && resultCode == Activity.RESULT_OK
                && data != null
                && data.getData() != null) {
            readBackup(data.getData());
        }
    }

    private TextSettingsCell actionCell(Context context, String text, boolean divider) {
        TextSettingsCell cell = settingsCell(context, text, divider);
        cell.setBackground(Theme.createSelectorWithBackgroundDrawable(
                Theme.getColor(Theme.key_windowBackgroundWhite, getResourceProvider()),
                Theme.getColor(Theme.key_listSelector, getResourceProvider())));
        return cell;
    }

    private TextSettingsCell settingsCell(
            Context context, String text, boolean divider) {
        TextSettingsCell cell = new TextSettingsCell(context, getResourceProvider());
        cell.setText(text, divider);
        return cell;
    }

    private void refreshState() {
        Context context = getContext();
        if (context == null || fingerprintCell == null || generationCell == null
                || protectedCountCell == null || waitingCountCell == null
                || verificationCountCell == null || pausedCountCell == null) {
            return;
        }
        try {
            SecureIdentityBackupManager.IdentityInfo identity =
                    SecureIdentityBackupManager.getIdentityInfo(context);
            fingerprintCell.setValue(identity.fingerprint);
            generationCell.setTextAndValue(
                    getString(R.string.ForkSecureRecoveryGeneration),
                    Long.toString(identity.generation),
                    true);

            SecureChatState.Summary summary =
                    new SecureChatState(context).getSummary(currentAccount);
            protectedCountCell.setTextAndValue(
                    getString(R.string.ForkSecureProtectedCount),
                    Integer.toString(summary.paired),
                    true);
            waitingCountCell.setTextAndValue(
                    getString(R.string.ForkSecureWaitingCount),
                    Integer.toString(summary.waiting),
                    true);
            verificationCountCell.setTextAndValue(
                    getString(R.string.ForkSecureVerificationCount),
                    Integer.toString(summary.identityPending),
                    true);
            pausedCountCell.setTextAndValue(
                    getString(R.string.ForkSecurePausedCount),
                    Integer.toString(summary.paused),
                    false);

            SecureIdentityBackupManager.PreparedImport prepared =
                    SecureIdentityBackupManager.getPreparedImport(context);
            restoreCell.setText(getString(prepared == null
                    ? R.string.ForkSecureImportBackup
                    : R.string.ForkSecureContinueRestore), false);
        } catch (RuntimeException error) {
            FileLog.e(error);
            fingerprintCell.setValue(
                    getString(R.string.ForkSecureBackupStateFailed));
            generationCell.setText(
                    getString(R.string.ForkSecureRecoveryGeneration), true);
            protectedCountCell.setText(
                    getString(R.string.ForkSecureProtectedCount), true);
            waitingCountCell.setText(
                    getString(R.string.ForkSecureWaitingCount), true);
            verificationCountCell.setText(
                    getString(R.string.ForkSecureVerificationCount), true);
            pausedCountCell.setText(
                    getString(R.string.ForkSecurePausedCount), false);
        }
    }

    private void showRestoreAction() {
        Context context = getContext();
        if (context == null) {
            return;
        }
        try {
            SecureIdentityBackupManager.PreparedImport prepared =
                    SecureIdentityBackupManager.getPreparedImport(context);
            if (prepared != null) {
                showPreparedImportDialog(prepared);
            } else {
                openImportPicker();
            }
        } catch (RuntimeException error) {
            FileLog.e(error);
            showBackupError(R.string.ForkSecureBackupStateFailed);
        }
    }

    private void showExportPasswordDialog() {
        showPasswordDialog(true, password -> {
            Context context = getContext();
            long ownerUserId = getUserConfig().getClientUserId();
            if (context == null || ownerUserId <= 0) {
                Arrays.fill(password, '\0');
                showBackupError(R.string.ForkSecureBackupStateFailed);
                return;
            }
            showInfo(R.string.ForkSecurePreparingBackup);
            Utilities.globalQueue.postRunnable(() -> {
                byte[] archive = null;
                RuntimeException failure = null;
                try {
                    archive = SecureIdentityBackupManager.exportArchive(
                            context, ownerUserId, password);
                } catch (RuntimeException error) {
                    failure = error;
                } finally {
                    Arrays.fill(password, '\0');
                }
                byte[] result = archive;
                RuntimeException error = failure;
                AndroidUtilities.runOnUIThread(() -> {
                    if (error != null) {
                        FileLog.e(error);
                        showBackupError(R.string.ForkSecureBackupExportFailed);
                        return;
                    }
                    clearPendingBackupArchive();
                    pendingBackupArchive = result;
                    Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                    intent.addCategory(Intent.CATEGORY_OPENABLE);
                    intent.setType("application/octet-stream");
                    intent.putExtra(Intent.EXTRA_TITLE, "fork-secure-identity.fsbk");
                    startActivityForResult(intent, BACKUP_EXPORT_REQUEST);
                });
            });
        }, null);
    }

    private void openImportPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        startActivityForResult(intent, BACKUP_IMPORT_REQUEST);
    }

    private void showPasswordDialog(
            boolean confirmPassword,
            PasswordCallback callback,
            Runnable onCancel) {
        Context context = getContext();
        if (context == null) {
            if (onCancel != null) {
                onCancel.run();
            }
            return;
        }
        LinearLayout content = new LinearLayout(context);
        content.setOrientation(LinearLayout.VERTICAL);
        int horizontal = AndroidUtilities.dp(24);
        content.setPadding(horizontal, 0, horizontal, 0);
        EditText first = createPasswordField(
                getString(R.string.ForkSecureBackupPassword));
        content.addView(first, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, 48));
        EditText second = null;
        if (confirmPassword) {
            second = createPasswordField(
                    getString(R.string.ForkSecureBackupPasswordAgain));
            content.addView(second, LayoutHelper.createLinear(
                    LayoutHelper.MATCH_PARENT, 48, 0, 8, 0, 0));
        }
        EditText confirmation = second;
        boolean[] cancelled = {false};
        Runnable cancelOnce = () -> {
            if (!cancelled[0]) {
                cancelled[0] = true;
                if (onCancel != null) {
                    onCancel.run();
                }
            }
        };
        AlertDialog dialog = new AlertDialog.Builder(context, getResourceProvider())
                .setTitle(getString(confirmPassword
                        ? R.string.ForkSecureExportBackup
                        : R.string.ForkSecureImportBackup))
                .setMessage(getString(R.string.ForkSecureBackupPasswordHint))
                .setView(content)
                .setPositiveButton(getString(R.string.Continue), null)
                .setNegativeButton(getString(R.string.Cancel),
                        (ignored, which) -> cancelOnce.run())
                .create();
        dialog.setOnCancelListener(ignored -> cancelOnce.run());
        dialog.setOnShowListener(ignored -> dialog.getButton(
                DialogInterface.BUTTON_POSITIVE).setOnClickListener(view -> {
            char[] password = first.getText().toString().toCharArray();
            char[] repeated = confirmation == null
                    ? null
                    : confirmation.getText().toString().toCharArray();
            boolean valid = password.length >= 12
                    && (repeated == null || Arrays.equals(password, repeated));
            if (repeated != null) {
                Arrays.fill(repeated, '\0');
            }
            first.getText().clear();
            if (confirmation != null) {
                confirmation.getText().clear();
            }
            if (!valid) {
                Arrays.fill(password, '\0');
                showBackupError(R.string.ForkSecureBackupPasswordInvalid);
                return;
            }
            cancelled[0] = true;
            dialog.dismiss();
            callback.onPassword(password);
        }));
        showDialog(dialog);
    }

    private EditText createPasswordField(String hint) {
        EditText field = new EditText(getContext());
        field.setHint(hint);
        field.setSingleLine(true);
        field.setSaveEnabled(false);
        field.setInputType(InputType.TYPE_CLASS_TEXT
                | InputType.TYPE_TEXT_VARIATION_PASSWORD
                | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            field.setImportantForAutofill(
                    View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        }
        return field;
    }

    private void readBackup(Uri uri) {
        Context context = getContext();
        if (context == null || uri == null) {
            showBackupError(R.string.ForkSecureBackupImportFailed);
            return;
        }
        Utilities.globalQueue.postRunnable(() -> {
            byte[] archive = null;
            RuntimeException failure = null;
            byte[] buffer = new byte[2048];
            try (InputStream input = context.getContentResolver().openInputStream(uri)) {
                if (input == null) {
                    throw new IllegalStateException("identity backup input is unavailable");
                }
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                int total = 0;
                int read;
                while ((read = input.read(buffer)) != -1) {
                    total += read;
                    if (total > BACKUP_MAX_BYTES) {
                        throw new IllegalArgumentException("identity backup is too large");
                    }
                    output.write(buffer, 0, read);
                }
                archive = output.toByteArray();
            } catch (Exception error) {
                failure = error instanceof RuntimeException
                        ? (RuntimeException) error
                        : new IllegalStateException("cannot read identity backup", error);
            } finally {
                Arrays.fill(buffer, (byte) 0);
            }
            byte[] result = archive;
            RuntimeException error = failure;
            AndroidUtilities.runOnUIThread(() -> {
                if (error != null) {
                    FileLog.e(error);
                    if (result != null) {
                        Arrays.fill(result, (byte) 0);
                    }
                    showBackupError(R.string.ForkSecureBackupImportFailed);
                    return;
                }
                showPasswordDialog(
                        false,
                        password -> prepareImport(result, password),
                        () -> Arrays.fill(result, (byte) 0));
            });
        });
    }

    private void prepareImport(byte[] archive, char[] password) {
        Context context = getContext();
        long ownerUserId = getUserConfig().getClientUserId();
        if (context == null || ownerUserId <= 0) {
            Arrays.fill(password, '\0');
            Arrays.fill(archive, (byte) 0);
            showBackupError(R.string.ForkSecureBackupImportFailed);
            return;
        }
        showInfo(R.string.ForkSecureCheckingBackup);
        Utilities.globalQueue.postRunnable(() -> {
            SecureIdentityBackupManager.PreparedImport prepared = null;
            RuntimeException failure = null;
            try {
                prepared = SecureIdentityBackupManager.prepareImport(
                        context, ownerUserId, archive, password);
            } catch (RuntimeException error) {
                failure = error;
            } finally {
                Arrays.fill(password, '\0');
                Arrays.fill(archive, (byte) 0);
            }
            SecureIdentityBackupManager.PreparedImport result = prepared;
            RuntimeException error = failure;
            AndroidUtilities.runOnUIThread(() -> {
                if (error != null) {
                    FileLog.e(error);
                    showBackupError(R.string.ForkSecureBackupImportFailed);
                } else {
                    refreshState();
                    showPreparedImportDialog(result);
                }
            });
        });
    }

    private void showPreparedImportDialog(
            SecureIdentityBackupManager.PreparedImport prepared) {
        if (getContext() == null || prepared == null) {
            return;
        }
        showDialog(new AlertDialog.Builder(getContext(), getResourceProvider())
                .setTitle(getString(R.string.ForkSecureConfirmRestoreTitle))
                .setMessage(formatString(
                        R.string.ForkSecureConfirmRestoreBody,
                        prepared.fingerprint,
                        prepared.archivedGeneration,
                        prepared.restoredGeneration))
                .setPositiveButton(getString(R.string.ForkSecureRestoreIdentity),
                        (ignored, which) -> commitImport())
                .setNegativeButton(getString(R.string.ForkSecureCancelRestore),
                        (ignored, which) -> cancelImport())
                .setNeutralButton(getString(R.string.ForkSecureRestoreLater), null)
                .create());
    }

    private void commitImport() {
        Context context = getContext();
        if (context == null) {
            return;
        }
        Utilities.globalQueue.postRunnable(() -> {
            SecureIdentityBackupManager.PreparedImport restored = null;
            RuntimeException failure = null;
            try {
                restored = SecureIdentityBackupManager.commitPreparedImport(context);
            } catch (RuntimeException error) {
                failure = error;
            }
            SecureIdentityBackupManager.PreparedImport result = restored;
            RuntimeException error = failure;
            AndroidUtilities.runOnUIThread(() -> {
                if (error != null) {
                    FileLog.e(error);
                    showBackupError(R.string.ForkSecureBackupRestoreFailed);
                    return;
                }
                refreshState();
                showDialog(new AlertDialog.Builder(getContext(), getResourceProvider())
                        .setTitle(getString(R.string.ForkSecureRestoreCompleteTitle))
                        .setMessage(formatString(
                                R.string.ForkSecureRestoreCompleteGlobal,
                                result.fingerprint))
                        .setPositiveButton(getString(R.string.OK), null)
                        .create());
            });
        });
    }

    private void cancelImport() {
        Context context = getContext();
        if (context == null) {
            return;
        }
        Utilities.globalQueue.postRunnable(() -> {
            RuntimeException failure = null;
            try {
                SecureIdentityBackupManager.cancelPreparedImport(context);
            } catch (RuntimeException error) {
                failure = error;
            }
            RuntimeException result = failure;
            AndroidUtilities.runOnUIThread(() -> {
                if (result != null) {
                    FileLog.e(result);
                    showBackupError(R.string.ForkSecureBackupStateFailed);
                }
                refreshState();
            });
        });
    }

    private void writeBackup(Uri uri) {
        Context context = getContext();
        byte[] archive = pendingBackupArchive;
        pendingBackupArchive = null;
        if (context == null || uri == null || archive == null) {
            if (archive != null) {
                Arrays.fill(archive, (byte) 0);
            }
            showBackupError(R.string.ForkSecureBackupExportFailed);
            return;
        }
        Utilities.globalQueue.postRunnable(() -> {
            RuntimeException failure = null;
            try (OutputStream output =
                         context.getContentResolver().openOutputStream(uri, "w")) {
                if (output == null) {
                    throw new IllegalStateException("identity backup output is unavailable");
                }
                output.write(archive);
                output.flush();
            } catch (Exception error) {
                failure = error instanceof RuntimeException
                        ? (RuntimeException) error
                        : new IllegalStateException("cannot write identity backup", error);
            } finally {
                Arrays.fill(archive, (byte) 0);
            }
            RuntimeException error = failure;
            AndroidUtilities.runOnUIThread(() -> {
                if (error != null) {
                    FileLog.e(error);
                    showBackupError(R.string.ForkSecureBackupExportFailed);
                } else {
                    showInfo(R.string.ForkSecureBackupSaved);
                }
            });
        });
    }

    private void confirmIdentityReset() {
        Context context = getContext();
        if (context == null) {
            return;
        }
        try {
            SecureIdentityBackupManager.PreparedImport prepared =
                    SecureIdentityBackupManager.getPreparedImport(context);
            if (prepared != null) {
                showPreparedImportDialog(prepared);
                return;
            }
        } catch (RuntimeException error) {
            FileLog.e(error);
            showBackupError(R.string.ForkSecureBackupStateFailed);
            return;
        }
        showDialog(new AlertDialog.Builder(context, getResourceProvider())
                .setTitle(getString(R.string.ForkSecureResetAllTitle))
                .setMessage(getString(R.string.ForkSecureResetAllBody))
                .setPositiveButton(getString(R.string.ForkSecureResetAndCreate),
                        (ignored, which) -> resetIdentity())
                .setNegativeButton(getString(R.string.Cancel), null)
                .create());
    }

    private void resetIdentity() {
        Context context = getContext();
        if (context == null) {
            return;
        }
        try {
            String fingerprint = SecureChatEngine.resetOwnIdentity(context);
            refreshState();
            showDialog(new AlertDialog.Builder(context, getResourceProvider())
                    .setTitle(getString(R.string.ForkSecureNewIdentityTitle))
                    .setMessage(formatString(
                            R.string.ForkSecureNewIdentityCreatedGlobal,
                            fingerprint))
                    .setPositiveButton(getString(R.string.OK), null)
                    .create());
        } catch (RuntimeException error) {
            FileLog.e(error);
            showBackupError(R.string.ForkSecureIdentityResetFailed);
            refreshState();
        }
    }

    private void clearPendingBackupArchive() {
        if (pendingBackupArchive != null) {
            Arrays.fill(pendingBackupArchive, (byte) 0);
            pendingBackupArchive = null;
        }
    }

    private void showInfo(int stringId) {
        BulletinFactory.of(this)
                .createSimpleBulletin(R.raw.chats_infotip, getString(stringId))
                .show();
    }

    private void showBackupError(int stringId) {
        BulletinFactory.of(this)
                .createErrorBulletin(getString(stringId))
                .show();
    }

    private interface PasswordCallback {
        void onPassword(char[] password);
    }
}
