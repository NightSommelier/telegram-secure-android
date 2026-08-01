package org.telegram.ui;

import static org.telegram.messenger.LocaleController.formatString;
import static org.telegram.messenger.LocaleController.getString;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.text.Editable;
import android.text.InputType;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.FileLog;
import org.telegram.messenger.R;
import org.telegram.messenger.Utilities;
import org.telegram.secureoverlay.SecureChatEngine;
import org.telegram.secureoverlay.SecureChatState;
import org.telegram.secureoverlay.SecureContentSettings;
import org.telegram.secureoverlay.SecureHistoryBackupCodec;
import org.telegram.secureoverlay.SecureHistoryBackupManager;
import org.telegram.secureoverlay.SecureIdentityBackupCodec;
import org.telegram.secureoverlay.SecureIdentityBackupManager;
import org.telegram.secureoverlay.SecureSavedMessagesSettings;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextCheckCell;
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
 * Account-level Fork-Secure identity and recovery controls.
 *
 * <p>The full archive includes identity and local history, while the advanced identity-only
 * archive remains a separate format. Neither contains Telegram credentials, live ratchet
 * sessions, contact trust, or decrypted media files.</p>
 */
public final class ForkSecureSettingsActivity extends BaseFragment {
    private static final int BACKUP_EXPORT_REQUEST = 8941;
    private static final int BACKUP_IMPORT_REQUEST = 8942;
    private static final int HISTORY_BACKUP_EXPORT_REQUEST = 8943;
    private static final int HISTORY_BACKUP_IMPORT_REQUEST = 8944;
    private static final int BACKUP_MAX_BYTES = 8192;
    private static final int HISTORY_BACKUP_MAX_BYTES = 32 * 1024 * 1024 + 128;

    private byte[] pendingBackupArchive;
    private TextDetailSettingsCell fingerprintCell;
    private TextSettingsCell generationCell;
    private TextSettingsCell protectedCountCell;
    private TextSettingsCell waitingCountCell;
    private TextSettingsCell verificationCountCell;
    private TextSettingsCell pausedCountCell;
    private TextSettingsCell restoreCell;
    private Dialog activePasswordDialog;
    private PasswordField[] activePasswordFields;

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

        HeaderCell historyHeader = new HeaderCell(context, getResourceProvider());
        historyHeader.setText(getString(R.string.ForkSecureHistoryBackupSection));
        content.addView(historyHeader);

        TextSettingsCell exportHistoryCell = actionCell(
                context, getString(R.string.ForkSecureExportHistoryBackup), true);
        exportHistoryCell.setOnClickListener(
                view -> showHistoryExportPasswordDialog());
        content.addView(exportHistoryCell);

        TextSettingsCell importHistoryCell = actionCell(
                context, getString(R.string.ForkSecureImportHistoryBackup), false);
        importHistoryCell.setOnClickListener(
                view -> openHistoryImportPicker());
        content.addView(importHistoryCell);

        TextInfoPrivacyCell historyScope = new TextInfoPrivacyCell(
                context, getResourceProvider());
        historyScope.setText(getString(R.string.ForkSecureHistoryBackupScope));
        content.addView(historyScope, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT));

        HeaderCell contentHeader = new HeaderCell(context, getResourceProvider());
        contentHeader.setText(getString(R.string.ForkSecureContentSection));
        content.addView(contentHeader);

        TextCheckCell screenProtectionCell =
                new TextCheckCell(context, getResourceProvider());
        screenProtectionCell.setTextAndCheck(
                getString(R.string.ForkSecureScreenProtection),
                SecureContentSettings.isScreenProtectionEnabled(context),
                false);
        screenProtectionCell.setOnClickListener(view -> {
            boolean enabled = !SecureContentSettings.isScreenProtectionEnabled(context);
            try {
                SecureContentSettings.setScreenProtectionEnabled(context, enabled);
                screenProtectionCell.setChecked(enabled);
            } catch (RuntimeException error) {
                FileLog.e(error);
                showBackupError(R.string.ForkSecureContentSettingFailed);
            }
        });
        content.addView(screenProtectionCell);

        TextInfoPrivacyCell screenProtectionInfo = new TextInfoPrivacyCell(
                context, getResourceProvider());
        screenProtectionInfo.setText(
                getString(R.string.ForkSecureScreenProtectionInfo));
        content.addView(screenProtectionInfo, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, LayoutHelper.WRAP_CONTENT));

        TextCheckCell savedMessagesCell =
                new TextCheckCell(context, getResourceProvider());
        savedMessagesCell.setTextAndCheck(
                getString(R.string.ForkSecureSavedMessagesProtection),
                SecureSavedMessagesSettings.isSecureByDefault(context, currentAccount),
                false);
        savedMessagesCell.setOnClickListener(view -> {
            boolean enabled = !SecureSavedMessagesSettings.isSecureByDefault(
                    context, currentAccount);
            try {
                SecureSavedMessagesSettings.setSecureByDefault(
                        context, currentAccount, enabled);
                savedMessagesCell.setChecked(enabled);
            } catch (RuntimeException error) {
                FileLog.e(error);
                showBackupError(R.string.ForkSecureContentSettingFailed);
            }
        });
        content.addView(savedMessagesCell);

        TextInfoPrivacyCell savedMessagesInfo = new TextInfoPrivacyCell(
                context, getResourceProvider());
        savedMessagesInfo.setText(
                getString(R.string.ForkSecureSavedMessagesProtectionInfo));
        content.addView(savedMessagesInfo, LayoutHelper.createLinear(
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
    public void onPause() {
        hideActivePasswords();
        super.onPause();
    }

    @Override
    public boolean dismissDialogOnPause(Dialog dialog) {
        return dialog != activePasswordDialog
                && super.dismissDialogOnPause(dialog);
    }

    @Override
    public void onFragmentDestroy() {
        clearActivePasswordDialogState(activePasswordDialog);
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
            return;
        }
        if (requestCode == HISTORY_BACKUP_EXPORT_REQUEST) {
            if (resultCode == Activity.RESULT_OK
                    && data != null
                    && data.getData() != null) {
                writeBackup(data.getData());
            } else {
                clearPendingBackupArchive();
            }
            return;
        }
        if (requestCode == HISTORY_BACKUP_IMPORT_REQUEST
                && resultCode == Activity.RESULT_OK
                && data != null
                && data.getData() != null) {
            readHistoryBackup(data.getData());
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
        cell.setBetterLayout(true);
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

    private void showHistoryExportPasswordDialog() {
        showPasswordDialog(
                true,
                R.string.ForkSecureExportHistoryBackup,
                password -> {
                    Context context = getContext();
                    long ownerUserId = getUserConfig().getClientUserId();
                    if (context == null || ownerUserId <= 0) {
                        Arrays.fill(password, '\0');
                        showBackupError(R.string.ForkSecureBackupStateFailed);
                        return;
                    }
                    showInfo(R.string.ForkSecurePreparingHistoryBackup);
                    Utilities.globalQueue.postRunnable(() -> {
                        byte[] archive = null;
                        RuntimeException failure = null;
                        try {
                            archive = SecureHistoryBackupManager.exportArchive(
                                    context,
                                    currentAccount,
                                    ownerUserId,
                                    password);
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
                                showBackupError(
                                        R.string.ForkSecureHistoryBackupExportFailed);
                                return;
                            }
                            clearPendingBackupArchive();
                            pendingBackupArchive = result;
                            Intent intent =
                                    new Intent(Intent.ACTION_CREATE_DOCUMENT);
                            intent.addCategory(Intent.CATEGORY_OPENABLE);
                            intent.setType("application/octet-stream");
                            intent.putExtra(
                                    Intent.EXTRA_TITLE,
                                    "fork-secure-history.fsrk");
                            startActivityForResult(
                                    intent, HISTORY_BACKUP_EXPORT_REQUEST);
                        });
                    });
                },
                null);
    }

    private void openImportPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        startActivityForResult(intent, BACKUP_IMPORT_REQUEST);
    }

    private void openHistoryImportPicker() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        startActivityForResult(intent, HISTORY_BACKUP_IMPORT_REQUEST);
    }

    private void showPasswordDialog(
            boolean confirmPassword,
            PasswordCallback callback,
            Runnable onCancel) {
        showPasswordDialog(
                confirmPassword,
                confirmPassword
                        ? R.string.ForkSecureExportBackup
                        : R.string.ForkSecureImportBackup,
                callback,
                onCancel);
    }

    private void showPasswordDialog(
            boolean confirmPassword,
            int titleStringId,
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
        PasswordField firstField = createPasswordField(
                getString(R.string.ForkSecureBackupPassword));
        EditText first = firstField.input;
        content.addView(firstField.row, LayoutHelper.createLinear(
                LayoutHelper.MATCH_PARENT, 48));
        EditText second = null;
        PasswordField secondField = null;
        if (confirmPassword) {
            secondField = createPasswordField(
                    getString(R.string.ForkSecureBackupPasswordAgain));
            second = secondField.input;
            content.addView(secondField.row, LayoutHelper.createLinear(
                    LayoutHelper.MATCH_PARENT, 48, 0, 8, 0, 0));

            TextView matchStatus = new TextView(context);
            matchStatus.setTextSize(14);
            matchStatus.setGravity(Gravity.START);
            matchStatus.setVisibility(View.GONE);
            content.addView(matchStatus, LayoutHelper.createLinear(
                    LayoutHelper.MATCH_PARENT,
                    LayoutHelper.WRAP_CONTENT,
                    0,
                    4,
                    0,
                    0));
            addPasswordMatchWatcher(first, second, matchStatus);
        }
        activePasswordFields = secondField == null
                ? new PasswordField[] {firstField}
                : new PasswordField[] {firstField, secondField};
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
                .setTitle(getString(titleStringId))
                .setMessage(getString(R.string.ForkSecureBackupPasswordHint))
                .setView(content)
                .setPositiveButton(getString(R.string.Continue), null)
                .setNegativeButton(getString(R.string.Cancel),
                        (ignored, which) -> cancelOnce.run())
                .create();
        activePasswordDialog = dialog;
        dialog.setOnCancelListener(ignored -> cancelOnce.run());
        dialog.setOnShowListener(ignored -> dialog.getButton(
                DialogInterface.BUTTON_POSITIVE).setOnClickListener(view -> {
            char[] password = first.getText().toString().toCharArray();
            char[] repeated = confirmation == null
                    ? null
                    : confirmation.getText().toString().toCharArray();
            boolean noPassword = confirmPassword
                    && password.length == 0
                    && repeated != null
                    && repeated.length == 0;
            boolean valid = noPassword
                    || (password.length >= 5
                    && (repeated == null || Arrays.equals(password, repeated)));
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
            if (noPassword) {
                confirmUnprotectedExport(password, callback);
            } else {
                callback.onPassword(password);
            }
        }));
        showDialog(dialog, ignored -> clearActivePasswordDialogState(dialog));
    }

    private void confirmUnprotectedExport(
            char[] password, PasswordCallback callback) {
        Context context = getContext();
        if (context == null) {
            Arrays.fill(password, '\0');
            return;
        }
        AlertDialog warning = new AlertDialog.Builder(context, getResourceProvider())
                .setTitle(getString(R.string.ForkSecureBackupWithoutPassword))
                .setMessage(getString(
                        R.string.ForkSecureBackupWithoutPasswordWarning))
                .setPositiveButton(getString(R.string.Continue),
                        (ignored, which) -> callback.onPassword(password))
                .setNegativeButton(getString(R.string.Cancel),
                        (ignored, which) -> Arrays.fill(password, '\0'))
                .create();
        warning.setOnCancelListener(
                ignored -> Arrays.fill(password, '\0'));
        showDialog(warning);
    }

    private PasswordField createPasswordField(String hint) {
        LinearLayout row = new LinearLayout(getContext());
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);

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
        row.addView(field, LayoutHelper.createLinear(
                0, LayoutHelper.MATCH_PARENT, 1f));

        ImageView visibility = new ImageView(getContext());
        visibility.setImageResource(R.drawable.msg_message);
        visibility.setScaleType(ImageView.ScaleType.CENTER);
        visibility.setBackground(Theme.createSelectorDrawable(
                Theme.getColor(
                        Theme.key_listSelector, getResourceProvider())));
        PasswordField passwordField =
                new PasswordField(row, field, visibility);
        visibility.setOnClickListener(
                view -> setPasswordVisible(
                        passwordField, !passwordField.visible));
        setPasswordVisible(passwordField, false);
        row.addView(visibility, LayoutHelper.createLinear(
                48, LayoutHelper.MATCH_PARENT));
        return passwordField;
    }

    private void addPasswordMatchWatcher(
            EditText first, EditText second, TextView matchStatus) {
        TextWatcher watcher = new TextWatcher() {
            @Override
            public void beforeTextChanged(
                    CharSequence value, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(
                    CharSequence value, int start, int before, int count) {
                updatePasswordMatchStatus(first, second, matchStatus);
            }

            @Override
            public void afterTextChanged(Editable value) {
            }
        };
        first.addTextChangedListener(watcher);
        second.addTextChangedListener(watcher);
    }

    private void updatePasswordMatchStatus(
            EditText first, EditText second, TextView matchStatus) {
        if (second.length() == 0) {
            matchStatus.setVisibility(View.GONE);
            return;
        }
        boolean matches = TextUtils.equals(first.getText(), second.getText());
        matchStatus.setText(getString(matches
                ? R.string.ForkSecureBackupPasswordsMatch
                : R.string.ForkSecureBackupPasswordsDoNotMatch));
        matchStatus.setTextColor(Theme.getColor(
                matches
                        ? Theme.key_windowBackgroundWhiteGreenText
                        : Theme.key_text_RedRegular,
                getResourceProvider()));
        matchStatus.setVisibility(View.VISIBLE);
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
                final boolean requiresPassword;
                try {
                    requiresPassword =
                            SecureIdentityBackupCodec.requiresPassword(result);
                } catch (RuntimeException parseError) {
                    FileLog.e(parseError);
                    Arrays.fill(result, (byte) 0);
                    showBackupError(R.string.ForkSecureBackupImportFailed);
                    return;
                }
                if (requiresPassword) {
                    showPasswordDialog(
                            false,
                            password -> prepareImport(result, password),
                            () -> Arrays.fill(result, (byte) 0));
                } else {
                    confirmUnprotectedImport(result);
                }
            });
        });
    }

    private void readHistoryBackup(Uri uri) {
        Context context = getContext();
        if (context == null || uri == null) {
            showBackupError(R.string.ForkSecureHistoryBackupImportFailed);
            return;
        }
        Utilities.globalQueue.postRunnable(() -> {
            byte[] archive = null;
            RuntimeException failure = null;
            byte[] buffer = new byte[8192];
            try (InputStream input =
                         context.getContentResolver().openInputStream(uri)) {
                if (input == null) {
                    throw new IllegalStateException(
                            "history backup input is unavailable");
                }
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                int total = 0;
                int read;
                while ((read = input.read(buffer)) != -1) {
                    total += read;
                    if (total > HISTORY_BACKUP_MAX_BYTES) {
                        throw new IllegalArgumentException(
                                "history backup is too large");
                    }
                    output.write(buffer, 0, read);
                }
                archive = output.toByteArray();
            } catch (Exception error) {
                failure = error instanceof RuntimeException
                        ? (RuntimeException) error
                        : new IllegalStateException(
                                "cannot read history backup", error);
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
                    showBackupError(
                            R.string.ForkSecureHistoryBackupImportFailed);
                    return;
                }
                final boolean requiresPassword;
                try {
                    requiresPassword =
                            SecureHistoryBackupCodec.requiresPassword(result);
                } catch (RuntimeException parseError) {
                    FileLog.e(parseError);
                    Arrays.fill(result, (byte) 0);
                    showBackupError(
                            R.string.ForkSecureHistoryBackupImportFailed);
                    return;
                }
                if (requiresPassword) {
                    showPasswordDialog(
                            false,
                            R.string.ForkSecureImportHistoryBackup,
                            password ->
                                    confirmHistoryRestore(result, password),
                            () -> Arrays.fill(result, (byte) 0));
                } else {
                    confirmUnprotectedHistoryImport(result);
                }
            });
        });
    }

    private void confirmUnprotectedHistoryImport(byte[] archive) {
        Context context = getContext();
        if (context == null) {
            Arrays.fill(archive, (byte) 0);
            return;
        }
        AlertDialog warning =
                new AlertDialog.Builder(context, getResourceProvider())
                        .setTitle(getString(
                                R.string.ForkSecureBackupWithoutPassword))
                        .setMessage(getString(
                                R.string
                                        .ForkSecureHistoryBackupWithoutPasswordImportWarning))
                        .setPositiveButton(
                                getString(R.string.Continue),
                                (ignored, which) ->
                                        confirmHistoryRestore(
                                                archive, new char[0]))
                        .setNegativeButton(
                                getString(R.string.Cancel),
                                (ignored, which) ->
                                        Arrays.fill(archive, (byte) 0))
                        .create();
        warning.setOnCancelListener(
                ignored -> Arrays.fill(archive, (byte) 0));
        showDialog(warning);
    }

    private void confirmHistoryRestore(byte[] archive, char[] password) {
        Context context = getContext();
        if (context == null) {
            Arrays.fill(password, '\0');
            Arrays.fill(archive, (byte) 0);
            return;
        }
        AlertDialog confirmation =
                new AlertDialog.Builder(context, getResourceProvider())
                        .setTitle(getString(
                                R.string.ForkSecureConfirmHistoryRestoreTitle))
                        .setMessage(getString(
                                R.string.ForkSecureConfirmHistoryRestoreBody))
                        .setPositiveButton(
                                getString(R.string.ForkSecureRestoreHistory),
                                (ignored, which) ->
                                        restoreHistoryBackup(
                                                archive, password))
                        .setNegativeButton(
                                getString(R.string.Cancel),
                                (ignored, which) -> {
                                    Arrays.fill(password, '\0');
                                    Arrays.fill(archive, (byte) 0);
                                })
                        .create();
        confirmation.setOnCancelListener(ignored -> {
            Arrays.fill(password, '\0');
            Arrays.fill(archive, (byte) 0);
        });
        showDialog(confirmation);
    }

    private void restoreHistoryBackup(byte[] archive, char[] password) {
        Context context = getContext();
        long ownerUserId = getUserConfig().getClientUserId();
        if (context == null || ownerUserId <= 0) {
            Arrays.fill(password, '\0');
            Arrays.fill(archive, (byte) 0);
            showBackupError(R.string.ForkSecureHistoryBackupImportFailed);
            return;
        }
        showInfo(R.string.ForkSecureCheckingHistoryBackup);
        Utilities.globalQueue.postRunnable(() -> {
            SecureHistoryBackupManager.RestoreResult restored = null;
            RuntimeException failure = null;
            try {
                restored = SecureHistoryBackupManager.restoreArchive(
                        context,
                        currentAccount,
                        ownerUserId,
                        archive,
                        password);
            } catch (RuntimeException error) {
                failure = error;
            } finally {
                Arrays.fill(password, '\0');
                Arrays.fill(archive, (byte) 0);
            }
            SecureHistoryBackupManager.RestoreResult result = restored;
            RuntimeException error = failure;
            AndroidUtilities.runOnUIThread(() -> {
                if (error != null) {
                    FileLog.e(error);
                    showBackupError(
                            R.string.ForkSecureHistoryBackupImportFailed);
                    return;
                }
                refreshState();
                if (getContext() == null) {
                    return;
                }
                showDialog(new AlertDialog.Builder(
                        getContext(), getResourceProvider())
                        .setTitle(getString(
                                R.string.ForkSecureHistoryRestoreCompleteTitle))
                        .setMessage(formatString(
                                R.string.ForkSecureHistoryRestoreComplete,
                                result.fingerprint,
                                result.restoredMessages,
                                result.pausedChats))
                        .setPositiveButton(getString(R.string.OK), null)
                        .create());
            });
        });
    }

    private void confirmUnprotectedImport(byte[] archive) {
        Context context = getContext();
        if (context == null) {
            Arrays.fill(archive, (byte) 0);
            return;
        }
        AlertDialog warning = new AlertDialog.Builder(context, getResourceProvider())
                .setTitle(getString(R.string.ForkSecureBackupWithoutPassword))
                .setMessage(getString(
                        R.string.ForkSecureBackupWithoutPasswordImportWarning))
                .setPositiveButton(getString(R.string.Continue),
                        (ignored, which) ->
                                prepareImport(archive, new char[0]))
                .setNegativeButton(getString(R.string.Cancel),
                        (ignored, which) -> Arrays.fill(archive, (byte) 0))
                .create();
        warning.setOnCancelListener(
                ignored -> Arrays.fill(archive, (byte) 0));
        showDialog(warning);
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
        int messageId = prepared.replacesExistingState
                ? R.string.ForkSecureConfirmRestoreReplaceBody
                : R.string.ForkSecureConfirmRestoreBody;
        showDialog(new AlertDialog.Builder(getContext(), getResourceProvider())
                .setTitle(getString(R.string.ForkSecureConfirmRestoreTitle))
                .setMessage(formatString(
                        messageId,
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

    private void setPasswordVisible(
            PasswordField passwordField, boolean visible) {
        if (passwordField == null) {
            return;
        }
        int selectionStart = passwordField.input.getSelectionStart();
        int selectionEnd = passwordField.input.getSelectionEnd();
        passwordField.visible = visible;
        passwordField.input.setInputType(
                InputType.TYPE_CLASS_TEXT
                        | (visible
                        ? InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
                        : InputType.TYPE_TEXT_VARIATION_PASSWORD)
                        | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        if (selectionStart >= 0 && selectionEnd >= 0) {
            passwordField.input.setSelection(
                    Math.min(selectionStart, passwordField.input.length()),
                    Math.min(selectionEnd, passwordField.input.length()));
        }
        passwordField.visibility.setColorFilter(Theme.getColor(
                visible
                        ? Theme.key_windowBackgroundWhiteInputFieldActivated
                        : Theme.key_windowBackgroundWhiteHintText,
                getResourceProvider()));
        passwordField.visibility.setContentDescription(getString(
                visible
                        ? R.string.ForkSecureHideBackupPassword
                        : R.string.ForkSecureShowBackupPassword));
    }

    private void hideActivePasswords() {
        if (activePasswordFields == null) {
            return;
        }
        for (PasswordField field : activePasswordFields) {
            setPasswordVisible(field, false);
        }
    }

    private void clearActivePasswordDialogState(Dialog dialog) {
        if (dialog == null || dialog != activePasswordDialog) {
            return;
        }
        if (activePasswordFields != null) {
            for (PasswordField field : activePasswordFields) {
                field.input.getText().clear();
                field.visible = false;
            }
        }
        activePasswordFields = null;
        activePasswordDialog = null;
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

    private static final class PasswordField {
        final LinearLayout row;
        final EditText input;
        final ImageView visibility;
        boolean visible;

        PasswordField(
                LinearLayout row, EditText input, ImageView visibility) {
            this.row = row;
            this.input = input;
            this.visibility = visibility;
        }
    }
}
