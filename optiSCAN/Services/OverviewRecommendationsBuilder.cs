using optiSCAN.Localization;
using optiSCAN.Models;

namespace optiSCAN.Services
{
    /// <summary>
    /// Calcule les deux lignes de recommandations affichées sur l'accueil (hygiène + activité),
    /// sans aucune dépendance UI.
    /// Extrait de MainWindow pour permettre les tests unitaires et alléger la fenêtre.
    /// </summary>
    public sealed class OverviewRecommendationsBuilder
    {
        /// <summary>Résultat d'un appel à <see cref="Build"/>.</summary>
        public sealed class Result
        {
            /// <summary>Texte de la ligne hygiène.</summary>
            public string HygieneLine { get; init; } = string.Empty;

            /// <summary>Sévérité de la ligne hygiène (0=vert, 1=orange, 2=vert, 3=bleu info).</summary>
            public int HygieneSeverity { get; init; }

            /// <summary>Afficher le lien "Mettre à jour maintenant" sur la ligne hygiène.</summary>
            public bool ShowSigUpdateLink { get; init; }

            /// <summary>Texte de la ligne activité.</summary>
            public string ActivityLine { get; init; } = string.Empty;

            /// <summary>Sévérité de la ligne activité.</summary>
            public int ActivitySeverity { get; init; }
        }

        /// <summary>Contexte fourni par MainWindow pour calculer les recommandations.</summary>
        public sealed class Context
        {
            public bool ClamInstalled { get; init; }
            /// <summary>
            /// Dernière MAJ signatures ClamAV (freshclam réussi ou date des .cvd/.cld locaux).
            /// Fournir via <see cref="FreshclamUpdater.GetLastSignatureUpdateTime"/>.
            /// </summary>
            public DateTime? LastFreshclamUpdate { get; init; }
            public DateTime? LastCleanAt { get; init; }
            public IReadOnlyList<ScanSession> ScanSessions { get; init; } = Array.Empty<ScanSession>();
        }

        /// <summary>
        /// Calcule les recommandations à partir du contexte fourni et des préférences utilisateur.
        /// </summary>
        public static Result Build(Context ctx)
        {
            var prefs = UserPreferences.Current;

            // ── Ligne activité ───────────────────────────────────────────────────
            var cutoff = DateTime.Now.AddDays(-30);
            int threats30 = ctx.ScanSessions
                .Where(s => s.StartedAt >= cutoff)
                .Sum(s => s.ThreatsFound);

            string actLine;
            int actSev;
            if (ctx.ScanSessions.Count == 0)
            {
                actLine = LocalizationService.GetString("Rec_ActNone");
                actSev = 3; // conseil préventif
            }
            else if (threats30 > 0)
            {
                actLine = LocalizationService.Format("Rec_ActThreats", threats30);
                actSev = 1; // alerte réelle
            }
            else
            {
                actLine = LocalizationService.GetString("Rec_ActOk");
                actSev = 2; // tout va bien
            }

            // ── Ligne hygiène (priorité : ClamAV > signatures > nettoyage) ───────
            bool suggestClean = !ctx.LastCleanAt.HasValue
                || (DateTime.Now - ctx.LastCleanAt.Value).TotalDays > prefs.CleanSuggestThresholdDays;

            string hypLine = suggestClean
                ? LocalizationService.GetString("Rec_CleanSuggest")
                : LocalizationService.Format("Rec_CleanRecent",
                    ctx.LastCleanAt!.Value.ToString("d", LocalizationService.CurrentCulture));
            int hypSev = suggestClean ? 1 : 0;
            bool showLink = false;

            if (!ctx.ClamInstalled)
            {
                hypLine = LocalizationService.GetString("Rec_ClamMissing");
                hypSev = 1;
            }
            else if (ctx.LastFreshclamUpdate is null)
            {
                hypLine = LocalizationService.GetString("Rec_SigNeverUpdated");
                hypSev = 1;
                showLink = true;
            }
            else if ((DateTime.Now - ctx.LastFreshclamUpdate.Value).TotalDays > prefs.SignatureStaleThresholdDays)
            {
                hypLine = LocalizationService.Format("Rec_SigStale", prefs.SignatureStaleThresholdDays);
                hypSev = 1;
                showLink = true;
            }
            else if (!prefs.SignatureAutoUpdateEnabled)
            {
                hypLine = LocalizationService.GetString("Rec_SigAutoOff");
                hypSev = 3;
            }

            return new Result
            {
                HygieneLine = hypLine,
                HygieneSeverity = hypSev,
                ShowSigUpdateLink = showLink,
                ActivityLine = actLine,
                ActivitySeverity = actSev,
            };
        }
    }
}
