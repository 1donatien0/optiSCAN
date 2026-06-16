using optiSCAN.Localization;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace optiSCAN.Services
{
    /// <summary>Premier lancement : parcours court en 3 étapes (v7).</summary>
    public static class OnboardingService
    {
        public static void ShowIfNeeded(Window owner, IViewServices ui)
        {
            var prefs = UserPreferences.Current;
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

            var step2 = MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Step2"),
                title,
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (step2 == MessageBoxResult.Yes)
            {
                ui.Navigation?.NavigateTo(Strings.OptiscanStrings.PanelIds.Antivirus);
                ui.RequestFocusAntivirusSignaturesTab();
                ui.TriggerSignatureUpdate();
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
