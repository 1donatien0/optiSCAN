using optiSCAN.Localization;
using optiSCAN.Services;

namespace optiSCAN.WinUI.Services;

/// <summary>Premier lancement — parcours court en 3 étapes (WinUI).</summary>
public static class WinUiOnboardingService
{
    public static void ShowIfNeeded(
        IUserConfirmService confirm,
        ServiceContainer container)
    {
        var prefs = container.UserPreferencesAccessor.Current;
        if (prefs.OnboardingCompleted)
            return;

        if (prefs.TotalScansCount > 0)
        {
            prefs.OnboardingCompleted = true;
            prefs.Save();
            return;
        }

        var title = LocalizationService.GetString("Onboarding_Title");

        if (!confirm.ConfirmYesNo(
                LocalizationService.GetString("Onboarding_Step1"),
                title,
                warning: false))
            return;

        // Windows Defender actif : proposer la cohabitation (Defender garde le temps réel).
        if (DefenderCoexistenceService.IsDefenderActive())
        {
            var complement = confirm.ConfirmYesNo(
                LocalizationService.GetString("Onboarding_DefenderStep"),
                LocalizationService.GetString("Onboarding_DefenderTitle"),
                warning: false);

            if (complement)
            {
                DefenderCoexistenceService.ApplyComplementMode(
                    container.UserPreferencesAccessor,
                    container.ExclusionSettingsAccessor,
                    container.ApplyRealtimeProtection,
                    container.ApplyPlatformProtectionService,
                    container.ApplyProcessMonitor);
            }
            else
            {
                DefenderCoexistenceService.ApplyFullOptiscanMode(
                    container.UserPreferencesAccessor,
                    container.ExclusionSettingsAccessor,
                    container.ApplyRealtimeProtection,
                    container.ApplyPlatformProtectionService,
                    container.ApplyProcessMonitor);
            }

            DefenderCoexistenceService.MarkConfigured(container.UserPreferencesAccessor);
            // Exclusions Defender : opt-in via Options (pas d'Add-MpPreference silencieux ici).
        }

        // Les signatures se téléchargent automatiquement en arrière-plan : information seulement.
        confirm.Inform(LocalizationService.GetString("Onboarding_Step2"), title);
        confirm.Inform(LocalizationService.GetString("Onboarding_Step3"), title);

        prefs.OnboardingCompleted = true;
        prefs.Save();
    }
}
