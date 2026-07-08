using optiSCAN.Localization;
using optiSCAN.Services;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace optiSCAN.Services
{
    /// <summary>Premier lancement : parcours court en 3 étapes (v7).</summary>
    public static class OnboardingService
    {
        public static void ShowIfNeeded(Window owner, IViewServices ui) =>
            ShowIfNeeded(owner, ui, null);

        public static void ShowIfNeeded(Window owner, IViewServices ui, IUserPreferencesAccessor? preferences) =>
            ShowIfNeeded(owner, ui as ServiceContainer, preferences);

        public static void ShowIfNeeded(Window owner, ServiceContainer? container, IUserPreferencesAccessor? preferences = null)
        {
            var prefsAccessor = preferences ?? container?.UserPreferencesAccessor ?? new DefaultUserPreferencesAccessor();
            var prefs = prefsAccessor.Current;
            if (prefs.OnboardingCompleted)
                return;

            if (prefs.TotalScansCount > 0)
            {
                prefs.OnboardingCompleted = true;
                prefs.Save();
                return;
            }

            var title = LocalizationService.GetString("Onboarding_Title");

            var step1 = MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Step1"),
                title,
                MessageBoxButton.OKCancel,
                MessageBoxImage.Information);
            if (step1 != MessageBoxResult.OK)
                return;

            if (container != null && DefenderCoexistenceService.IsDefenderActive())
            {
                var defenderChoice = MessageBox.Show(
                    owner,
                    LocalizationService.GetString("Onboarding_DefenderStep"),
                    LocalizationService.GetString("Onboarding_DefenderTitle"),
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (defenderChoice == MessageBoxResult.Yes)
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
                WindowsDefenderExclusionService.EnsureOptiscanExclusionsAsync();
            }

            var step2 = MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Step2"),
                title,
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (step2 == MessageBoxResult.Yes)
            {
                container?.Navigation?.NavigateTo(Strings.OptiscanStrings.PanelIds.Antivirus);
                container?.RequestFocusAntivirusSignaturesTab();
                container?.TriggerSignatureUpdate();
            }

            MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Step3"),
                title,
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            prefs.OnboardingCompleted = true;
            prefs.Save();
        }
    }
}
