using optiSCAN.Models;
using System.IO;
using System.Text;

namespace optiSCAN.Services
{
    /// <summary>
    /// Génère un rapport HTML moderne à partir de l'historique des scans
    /// et des menaces détectées.
    /// </summary>
    public sealed class HtmlExportService
    {
        // ── API publique ──────────────────────────────────────────────────────────

        /// <summary>
        /// Génère un rapport HTML complet et le sauvegarde dans <paramref name="outputPath"/>.
        /// </summary>
        public void ExportFullReport(
            IEnumerable<ScanSession> scanHistory,
            IEnumerable<ThreatInfo> activeThreats,
            IEnumerable<QuarantineEntry> quarantine,
            UserPreferences prefs,
            string outputPath)
        {
            var html = BuildHtml(scanHistory, activeThreats, quarantine, prefs);
            File.WriteAllText(outputPath, html, Encoding.UTF8);
        }

        // ── Génération HTML ───────────────────────────────────────────────────────

        private static string BuildHtml(
            IEnumerable<ScanSession> scans,
            IEnumerable<ThreatInfo> threats,
            IEnumerable<QuarantineEntry> quarantine,
            UserPreferences prefs)
        {
            var now = DateTime.Now;
            var scanList = scans.Take(20).ToList();
            var threatList = threats.ToList();
            var quarList = quarantine.Take(50).ToList();
            var totalScans = scanList.Count;
            var totalThreats = scanList.Sum(s => s.ThreatsFound);

            var sb = new StringBuilder();
            sb.AppendLine($@"<!DOCTYPE html>
<html lang=""fr"">
<head>
  <meta charset=""UTF-8"">
  <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">
  <title>optiSCAN — Rapport du {now:dd/MM/yyyy}</title>
  <style>
    :root {{
      --bg:       #0b1628;
      --surface:  #111f3c;
      --card:     #162040;
      --border:   #1e3a6e;
      --blue:     #3b82f6;
      --gold:     #f59e0b;
      --green:    #22c55e;
      --red:      #ef4444;
      --text:     #e2e8f0;
      --muted:    #64748b;
      --radius:   12px;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 32px;
      line-height: 1.6;
    }}
    header {{
      display: flex;
      align-items: center;
      gap: 16px;
      margin-bottom: 32px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }}
    .logo {{
      width: 48px; height: 48px;
      background: linear-gradient(135deg, var(--blue), #6366f1);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 24px;
    }}
    h1 {{ font-size: 22px; font-weight: 700; }}
    .meta {{ color: var(--muted); font-size: 13px; margin-top: 2px; }}
    .grid-4 {{
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 16px;
      margin-bottom: 28px;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px 20px;
    }}
    .card-label {{ color: var(--muted); font-size: 11px; font-weight: 600;
                   text-transform: uppercase; letter-spacing: .6px; margin-bottom: 6px; }}
    .card-value {{ font-size: 28px; font-weight: 700; }}
    .blue {{ color: var(--blue); }}
    .gold {{ color: var(--gold); }}
    .green {{ color: var(--green); }}
    .red {{ color: var(--red); }}
    h2 {{
      font-size: 14px; font-weight: 600; color: var(--gold);
      text-transform: uppercase; letter-spacing: .5px;
      margin-bottom: 12px;
    }}
    table {{
      width: 100%; border-collapse: collapse; font-size: 13px;
      margin-bottom: 28px;
    }}
    thead th {{
      background: var(--surface);
      color: var(--muted);
      font-size: 11px; font-weight: 600; text-align: left;
      padding: 10px 14px;
      border-bottom: 1px solid var(--border);
    }}
    tbody tr {{ border-bottom: 1px solid var(--border); }}
    tbody tr:hover {{ background: var(--surface); }}
    td {{ padding: 10px 14px; }}
    .badge {{
      display: inline-block; padding: 2px 8px; border-radius: 20px;
      font-size: 11px; font-weight: 600;
    }}
    .badge-ok  {{ background: #16532320; color: var(--green); }}
    .badge-warn {{ background: #92400e20; color: var(--gold); }}
    .badge-err  {{ background: #7f1d1d20; color: var(--red); }}
    .section {{ margin-bottom: 32px; }}
    footer {{
      color: var(--muted); font-size: 11px; text-align: center;
      margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
    }}
    @media (max-width: 700px) {{ .grid-4 {{ grid-template-columns: repeat(2,1fr); }} }}
  </style>
</head>
<body>
<header>
  <div class=""logo"">🛡</div>
  <div>
    <h1>Rapport optiSCAN</h1>
    <div class=""meta"">Généré le {now:dddd dd MMMM yyyy à HH:mm} · optiSCAN v2.0</div>
  </div>
</header>

<!-- KPIs -->
<div class=""grid-4"">
  <div class=""card"">
    <div class=""card-label"">Scans effectués</div>
    <div class=""card-value blue"">{prefs.TotalScansCount}</div>
  </div>
  <div class=""card"">
    <div class=""card-label"">Scans (ce rapport)</div>
    <div class=""card-value gold"">{totalScans}</div>
  </div>
  <div class=""card"">
    <div class=""card-label"">Menaces détectées</div>
    <div class=""card-value red"">{totalThreats}</div>
  </div>
  <div class=""card"">
    <div class=""card-label"">En quarantaine</div>
    <div class=""card-value green"">{quarList.Count}</div>
  </div>
</div>

<!-- Historique des scans -->
<div class=""section"">
  <h2>Historique des scans</h2>
  <table>
    <thead>
      <tr>
        <th>Date</th>
        <th>Type</th>
        <th>Fichiers analysés</th>
        <th>Menaces</th>
        <th>Durée</th>
        <th>Statut</th>
      </tr>
    </thead>
    <tbody>");

            foreach (var s in scanList)
            {
                string badge = s.ThreatsFound == 0
                    ? "<span class=\"badge badge-ok\">✓ Propre</span>"
                    : $"<span class=\"badge badge-err\">⚠ {s.ThreatsFound} menace(s)</span>";

                sb.AppendLine($@"      <tr>
        <td>{s.StartedAt:dd/MM/yyyy HH:mm}</td>
        <td>{s.TypeDisplay}</td>
        <td>{s.FilesScanned:N0}</td>
        <td class=""{(s.ThreatsFound > 0 ? "red" : "green")}"">{s.ThreatsFound}</td>
        <td>{s.DurationDisplay}</td>
        <td>{badge}</td>
      </tr>");
            }

            if (!scanList.Any())
                sb.AppendLine("      <tr><td colspan=\"6\" style=\"text-align:center;color:var(--muted)\">Aucun scan enregistré</td></tr>");

            sb.AppendLine("    </tbody></table></div>");

            // Menaces actives
            if (threatList.Any())
            {
                sb.AppendLine(@"<div class=""section"">
  <h2>Menaces actives (non traitées)</h2>
  <table>
    <thead><tr><th>Fichier</th><th>Virus détecté</th><th>Chemin</th><th>Statut</th></tr></thead>
    <tbody>");
                foreach (var t in threatList)
                {
                    sb.AppendLine($@"      <tr>
        <td>{System.Net.WebUtility.HtmlEncode(t.FileName)}</td>
        <td class=""red"">{System.Net.WebUtility.HtmlEncode(t.VirusName)}</td>
        <td style=""font-size:11px;color:var(--muted)"">{System.Net.WebUtility.HtmlEncode(t.FilePath)}</td>
        <td><span class=""badge badge-err"">Non traité</span></td>
      </tr>");
                }
                sb.AppendLine("    </tbody></table></div>");
            }

            // Quarantaine
            if (quarList.Any())
            {
                sb.AppendLine(@"<div class=""section"">
  <h2>Quarantaine</h2>
  <table>
    <thead><tr><th>Fichier</th><th>Virus</th><th>Date quarantaine</th><th>Taille</th></tr></thead>
    <tbody>");
                foreach (var q in quarList)
                {
                    sb.AppendLine($@"      <tr>
        <td>{System.Net.WebUtility.HtmlEncode(q.FileName)}</td>
        <td class=""gold"">{System.Net.WebUtility.HtmlEncode(q.VirusName)}</td>
        <td>{q.QuarantinedAt:dd/MM/yyyy HH:mm}</td>
        <td>{q.SizeDisplay}</td>
      </tr>");
                }
                sb.AppendLine("    </tbody></table></div>");
            }

            // Cibles récentes
            if (prefs.RecentTargets.Any())
            {
                sb.AppendLine(@"<div class=""section"">
  <h2>Cibles récentes</h2>
  <table>
    <thead><tr><th>Chemin</th><th>Type</th><th>Dernier scan</th></tr></thead>
    <tbody>");
                foreach (var r in prefs.RecentTargets)
                {
                    sb.AppendLine($@"      <tr>
        <td>{System.Net.WebUtility.HtmlEncode(r.Path)}</td>
        <td>{r.ScanType}</td>
        <td>{r.LastUsed:dd/MM/yyyy HH:mm}</td>
      </tr>");
                }
                sb.AppendLine("    </tbody></table></div>");
            }

            sb.AppendLine($@"<footer>
  Rapport généré automatiquement par optiSCAN v2.0 — {now:yyyy} ·
  Les informations de ce rapport sont confidentielles.
</footer>
</body>
</html>");

            return sb.ToString();
        }
    }
}
