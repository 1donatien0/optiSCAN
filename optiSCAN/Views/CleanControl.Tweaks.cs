using optiSCAN.Localization;
using optiSCAN.Services;
using optiSCAN.Strings;
using System.Collections.Generic;
using System.Linq;
using System.Windows;

namespace optiSCAN.Views
{
    /// <summary>
    /// Panneau Optimiser — sous-onglet « Tweaks » (performance, confidentialité,
    /// interface, maintenance). Port C# des onglets Performance / Confidentialité /
    /// Interface d'OptiWin. Les actions HKCU sont appliquées directement ; les
    /// actions admin (télémétrie, DISM, historique Defender) partagent une seule invite UAC.
    /// </summary>
    public partial class CleanControl
    {
        private bool _tweaksRunning;

        private readonly struct TweakSelection
        {
            public bool PowerPlan { get; init; }
            public bool VisualFx { get; init; }
            public bool Telemetry { get; init; }
            public bool Ads { get; init; }
            public bool Suggestions { get; init; }
            public bool Tailored { get; init; }
            public bool ShowExt { get; init; }
            public bool ShowHidden { get; init; }
            public bool TaskbarLeft { get; init; }
            public bool HideWidgets { get; init; }
            public bool SearchIcon { get; init; }
            public bool ThisPc { get; init; }
            public bool Dism { get; init; }

            public bool AnyUi => ShowExt || ShowHidden || TaskbarLeft || HideWidgets || SearchIcon || ThisPc;
            public bool AnyElevated => Telemetry || Dism;
            public bool Any => PowerPlan || VisualFx || Telemetry || Ads || Suggestions
                               || Tailored || AnyUi || Dism;
        }

        private TweakSelection ReadTweakSelection() => new()
        {
            PowerPlan = chkTwkPowerPlan?.IsChecked == true,
            VisualFx = chkTwkVisualFx?.IsChecked == true,
            Telemetry = chkTwkTelemetry?.IsChecked == true,
            Ads = chkTwkAds?.IsChecked == true,
            Suggestions = chkTwkSuggestions?.IsChecked == true,
            Tailored = chkTwkTailored?.IsChecked == true,
            ShowExt = chkTwkExt?.IsChecked == true,
            ShowHidden = chkTwkHidden?.IsChecked == true,
            TaskbarLeft = chkTwkTaskbarLeft?.IsChecked == true,
            HideWidgets = chkTwkWidgets?.IsChecked == true,
            SearchIcon = chkTwkSearchIcon?.IsChecked == true,
            ThisPc = chkTwkThisPC?.IsChecked == true,
            Dism = chkTwkDism?.IsChecked == true,
        };

        // ── Appliquer ────────────────────────────────────────────────────────
        private async void btnTwkApply_Click(object sender, RoutedEventArgs e)
        {
            if (_tweaksRunning) return;

            var sel = ReadTweakSelection();
            if (!sel.Any)
            {
                AppendTweaksLog(LocalizationService.GetString("Twk_LogNone"));
                return;
            }

            // Récapitulatif + confirmation (même pattern qu'OptiWin).
            var labels = BuildTweakLabels(sel);
            var summary = string.Join("\n", labels.Select(l => $" •  {l}"));
            var confirmBody = LocalizationService.Format("Twk_ConfirmBody", summary);
            var confirm = System.Windows.MessageBox.Show(
                confirmBody,
                OptiscanStrings.Confirmations.Title,
                MessageBoxButton.OKCancel,
                MessageBoxImage.Question);
            if (confirm != MessageBoxResult.OK)
            {
                AppendTweaksLog(LocalizationService.GetString("Twk_Cancelled"));
                return;
            }

            _tweaksRunning = true;
            btnTwkApply.IsEnabled = false;
            SetTweaksLog(LocalizationService.GetString("Twk_LogStart"));

            try
            {
                bool elevatedOk = true;
                await Task.Run(() =>
                {
                    // ── Actions sans élévation (HKCU / powercfg) ─────────────
                    if (sel.PowerPlan)
                        LogTweakResult("Twk_PowerPlan", SystemTweaksService.EnableHighPerformancePowerPlan());
                    if (sel.VisualFx)
                        LogTweakResult("Twk_VisualFx", SystemTweaksService.SetVisualEffectsBestPerformance());
                    if (sel.Ads)
                        LogTweakResult("Twk_Ads", SystemTweaksService.DisableAdvertisingId());
                    if (sel.Suggestions)
                        LogTweakResult("Twk_Suggestions", SystemTweaksService.DisableSuggestions());
                    if (sel.Tailored)
                        LogTweakResult("Twk_Tailored", SystemTweaksService.DisableTailoredExperiences());
                    if (sel.ShowExt)
                        LogTweakResult("Twk_ShowExt", SystemTweaksService.ShowFileExtensions());
                    if (sel.ShowHidden)
                        LogTweakResult("Twk_ShowHidden", SystemTweaksService.ShowHiddenFiles());
                    if (sel.TaskbarLeft)
                        LogTweakResult("Twk_TaskbarLeft", SystemTweaksService.AlignTaskbarLeft());
                    if (sel.HideWidgets)
                        LogTweakResult("Twk_HideWidgets", SystemTweaksService.HideTaskbarWidgets());
                    if (sel.SearchIcon)
                        LogTweakResult("Twk_SearchIcon", SystemTweaksService.SearchBoxAsIcon());
                    if (sel.ThisPc)
                        LogTweakResult("Twk_ThisPC", SystemTweaksService.ExplorerOpensThisPc());

                    // ── Actions admin regroupées : une seule invite UAC ──────
                    if (sel.AnyElevated)
                    {
                        AppendTweaksLog(LocalizationService.GetString("Twk_LogElevStart"));
                        elevatedOk = SystemTweaksService.RunElevatedTweaks(
                            sel.Telemetry, sel.Dism, waitForExit: true);
                        if (elevatedOk)
                        {
                            if (sel.Telemetry)
                            {
                                TweakUndoStore.RecordTelemetryApplied();
                                LogTweakResult("Twk_Telemetry", true);
                            }
                            if (sel.Dism) LogTweakResult("Twk_Dism", true);
                        }
                        else
                        {
                            AppendTweaksLog(LocalizationService.GetString("Twk_LogElevDenied"));
                        }
                    }

                    // ── Redémarrage de l'Explorateur si tweaks d'interface ───
                    if (sel.AnyUi)
                    {
                        SystemTweaksService.RestartExplorer();
                        AppendTweaksLog(LocalizationService.GetString("Twk_LogExplorerRestart"));
                    }
                });

                AppendTweaksLog(LocalizationService.GetString("Twk_LogEnd"));
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Application des tweaks", ex);
                AppendTweaksLog(LocalizationService.Format("Twk_LogError", ex.Message));
            }
            finally
            {
                _tweaksRunning = false;
                btnTwkApply.IsEnabled = true;
                RefreshTweakUndoButton();
            }
        }

        // ── Rétablir les réglages d'origine (audit A11) ──────────────────────
        private void btnTwkUndo_Loaded(object sender, RoutedEventArgs e) => RefreshTweakUndoButton();

        private void RefreshTweakUndoButton()
        {
            if (btnTwkUndo != null)
                btnTwkUndo.IsEnabled = !_tweaksRunning && TweakUndoStore.HasPendingUndo;
        }

        private async void btnTwkUndo_Click(object sender, RoutedEventArgs e)
        {
            if (_tweaksRunning) return;
            if (!TweakUndoStore.HasPendingUndo)
            {
                AppendTweaksLog(LocalizationService.GetString("Twk_UndoNothing"));
                RefreshTweakUndoButton();
                return;
            }

            var confirm = System.Windows.MessageBox.Show(
                LocalizationService.GetString("Twk_UndoConfirm"),
                OptiscanStrings.Confirmations.Title,
                MessageBoxButton.OKCancel,
                MessageBoxImage.Question);
            if (confirm != MessageBoxResult.OK)
                return;

            _tweaksRunning = true;
            btnTwkApply.IsEnabled = false;
            btnTwkUndo.IsEnabled = false;
            SetTweaksLog(LocalizationService.GetString("Twk_UndoStart"));
            try
            {
                await Task.Run(() =>
                {
                    var ok = SystemTweaksService.UndoAll(out var telemetryUndo, out var explorerRestart);
                    if (telemetryUndo)
                    {
                        AppendTweaksLog(LocalizationService.GetString("Twk_LogElevStart"));
                        if (SystemTweaksService.RunElevatedKnown("telemetry-undo", waitForExit: true))
                            SystemTweaksService.MarkTelemetryRestored();
                        else
                        {
                            ok = false;
                            AppendTweaksLog(LocalizationService.GetString("Twk_LogElevDenied"));
                        }
                    }

                    if (explorerRestart)
                    {
                        SystemTweaksService.RestartExplorer();
                        AppendTweaksLog(LocalizationService.GetString("Twk_LogExplorerRestart"));
                    }

                    AppendTweaksLog(LocalizationService.GetString(ok ? "Twk_UndoDone" : "Twk_UndoPartial"));
                });
            }
            catch (Exception ex)
            {
                AppLogger.Warn("CleanControl", "Rétablissement des tweaks", ex);
                AppendTweaksLog(LocalizationService.Format("Twk_LogError", ex.Message));
            }
            finally
            {
                _tweaksRunning = false;
                btnTwkApply.IsEnabled = true;
                RefreshTweakUndoButton();
            }
        }

        // ── Applications au démarrage ────────────────────────────────────────
        private void btnTwkStartup_Click(object sender, RoutedEventArgs e)
        {
            if (SystemTweaksService.OpenStartupAppsManager())
                AppendTweaksLog(LocalizationService.GetString("Twk_LogStartupOpened"));
        }

        // ── Helpers ──────────────────────────────────────────────────────────
        private static List<string> BuildTweakLabels(TweakSelection sel)
        {
            var labels = new List<string>(13);
            if (sel.PowerPlan) labels.Add(LocalizationService.GetString("Twk_PowerPlan"));
            if (sel.VisualFx) labels.Add(LocalizationService.GetString("Twk_VisualFx"));
            if (sel.Telemetry) labels.Add(LocalizationService.GetString("Twk_Telemetry"));
            if (sel.Ads) labels.Add(LocalizationService.GetString("Twk_Ads"));
            if (sel.Suggestions) labels.Add(LocalizationService.GetString("Twk_Suggestions"));
            if (sel.Tailored) labels.Add(LocalizationService.GetString("Twk_Tailored"));
            if (sel.ShowExt) labels.Add(LocalizationService.GetString("Twk_ShowExt"));
            if (sel.ShowHidden) labels.Add(LocalizationService.GetString("Twk_ShowHidden"));
            if (sel.TaskbarLeft) labels.Add(LocalizationService.GetString("Twk_TaskbarLeft"));
            if (sel.HideWidgets) labels.Add(LocalizationService.GetString("Twk_HideWidgets"));
            if (sel.SearchIcon) labels.Add(LocalizationService.GetString("Twk_SearchIcon"));
            if (sel.ThisPc) labels.Add(LocalizationService.GetString("Twk_ThisPC"));
            if (sel.Dism) labels.Add(LocalizationService.GetString("Twk_Dism"));
            return labels;
        }

        private void LogTweakResult(string labelKey, bool success)
        {
            var label = LocalizationService.GetString(labelKey);
            AppendTweaksLog(success
                ? LocalizationService.Format("Twk_LogOk", label)
                : LocalizationService.Format("Twk_LogFail", label));
        }

        private void SetTweaksLog(string text)
        {
            if (txtTweaksLog != null)
                txtTweaksLog.Text = $"[{DateTime.Now:HH:mm:ss}] {text}\n";
        }

        private void AppendTweaksLog(string line)
        {
            Dispatcher.InvokeAsync(() =>
            {
                if (txtTweaksLog == null) return;
                if (txtTweaksLog.Text.StartsWith("Cochez", StringComparison.OrdinalIgnoreCase)
                    || txtTweaksLog.Text.StartsWith("Check", StringComparison.OrdinalIgnoreCase))
                    txtTweaksLog.Text = string.Empty;
                txtTweaksLog.Text += $"[{DateTime.Now:HH:mm:ss}] {line}\n";
                txtTweaksLog.ScrollToEnd();
            });
        }
    }
}
