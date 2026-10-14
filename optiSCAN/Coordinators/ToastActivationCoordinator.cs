using optiSCAN.Models;
using optiSCAN.Services;
using optiSCAN.Strings;

namespace optiSCAN.Coordinators;

/// <summary>Route les actions toast Windows vers navigation et services antivirus.</summary>
public static class ToastActivationCoordinator
{
    public sealed class Host
    {
        public required IViewServices Services { get; init; }
        public required INavigationService Navigation { get; init; }
        public required Action ShowWindow { get; init; }
        public required Action<string, bool, bool> SetStatus { get; init; }
        public required Action RefreshQuarantineList { get; init; }
        public required Action RefreshAntivirusView { get; init; }
        public required Action SelectAntivirusScanTab { get; init; }
        public required Action SelectAntivirusQuarantineTab { get; init; }
        public required Action SelectAntivirusSignaturesTab { get; init; }
        public required Action TriggerManualSignatureUpdate { get; init; }

        /// <summary>
        /// Confirmation avant d'exclure un fichier depuis une notification (chemin, nom de la
        /// menace). Absente ou refusée : aucune exclusion.
        /// </summary>
        public Func<string, string?, bool>? ConfirmIgnore { get; init; }
    }

    public static void Handle(ToastActivationEventArgs e, Host host)
    {
        var c = host.Services;
        switch (e.Action.ToLowerInvariant())
        {
            case "quarantine":
                if (!string.IsNullOrEmpty(e.FilePath))
                {
                    var result = c.Actions.QuarantineThreat(e.FilePath);
                    host.SetStatus(result.Message, result.IsError, result.IsWarning);
                    if (result.Success)
                    {
                        host.RefreshQuarantineList();
                        host.RefreshAntivirusView();
                    }
                }
                host.ShowWindow();
                host.Navigation.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                break;

            case "ignore":
                // Le bouton d'une notification excluait le fichier de toutes les analyses, pour
                // toujours, en un clic souvent pris pour « fermer ». La fenêtre s'ouvre et
                // l'exclusion n'a lieu qu'après confirmation explicite.
                host.ShowWindow();
                if (!string.IsNullOrEmpty(e.FilePath)
                    && host.ConfirmIgnore?.Invoke(e.FilePath, e.VirusName) == true)
                {
                    var result = c.Actions.IgnoreThreat(e.FilePath);
                    host.SetStatus(result.Message, result.IsError, result.IsWarning);
                    host.RefreshAntivirusView();
                }
                break;

            case "openav":
                host.ShowWindow();
                host.Navigation.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                host.SelectAntivirusScanTab();
                break;

            case "open":
            case "threat":
                host.ShowWindow();
                host.Navigation.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                host.SelectAntivirusScanTab();
                break;

            case "showquarantine":
                host.ShowWindow();
                host.Navigation.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                host.SelectAntivirusQuarantineTab();
                host.RefreshQuarantineList();
                break;

            case "history":
            case "scanthreats":
                host.ShowWindow();
                host.Navigation.NavigateTo(OptiscanStrings.PanelIds.History);
                break;

            case "update":
                host.ShowWindow();
                host.Navigation.NavigateTo(OptiscanStrings.PanelIds.Antivirus);
                host.SelectAntivirusSignaturesTab();
                host.TriggerManualSignatureUpdate();
                break;
        }
    }
}
