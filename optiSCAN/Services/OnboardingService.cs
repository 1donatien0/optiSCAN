using optiSCAN.Localization;
using System.Windows;
using MessageBox = System.Windows.MessageBox;

namespace optiSCAN.Services
{
    /// <summary>Premier lancement : rappel des actions essentielles (une fois).</summary>
    public static class OnboardingService
    {
        public static void ShowIfNeeded(Window owner)
        {
            var prefs = UserPreferences.Current;
            if (prefs.OnboardingCompleted)
                return;

            // Utilisateur existant (déjà des scans) : ne pas afficher.
            if (prefs.TotalScansCount > 0)
            {
                prefs.OnboardingCompleted = true;
                prefs.Save();
                return;
            }

            var result = MessageBox.Show(
                owner,
                LocalizationService.GetString("Onboarding_Body"),
                LocalizationService.GetString("Onboarding_Title"),
                System.Windows.MessageBoxButton.OK,
                System.Windows.MessageBoxImage.Information);

            if (result == MessageBoxResult.OK)
            {
                prefs.OnboardingCompleted = true;
                prefs.Save();
            }
        }
    }
}
