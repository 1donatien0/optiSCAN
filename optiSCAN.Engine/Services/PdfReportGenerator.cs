using optiSCAN.Localization;
using optiSCAN.Models;
using System.Globalization;
using System.Linq;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using PdfSharp.Fonts;
using Color = MigraDoc.DocumentObjectModel.Color;
using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Génère des rapports PDF complets à partir d'un ScanResult.
    /// Utilise PDFsharp et MigraDoc (licence MIT).
    /// </summary>
    public class PdfReportGenerator
    {
        static PdfReportGenerator()
        {
            // Polices lues dans le dossier des polices de Windows (Segoe UI, repli Arial).
            if (OperatingSystem.IsWindows() && GlobalFontSettings.FontResolver == null)
                GlobalFontSettings.FontResolver = new PdfFontResolver();
        }

        private static string RedactPath(string? path) => PathRedaction.RedactPath(path);

        // Palette fixe du rapport (indépendante du thème de l'interface).
        private static readonly Color Accent = Color.FromRgb(0x19, 0x76, 0xD2);
        private static readonly Color Muted = Color.FromRgb(0x9E, 0x9E, 0x9E);
        private static readonly Color MutedDark = Color.FromRgb(0x75, 0x75, 0x75);
        private static readonly Color Rule = Color.FromRgb(0xE0, 0xE0, 0xE0);
        private static readonly Color Frame = Color.FromRgb(0xBD, 0xBD, 0xBD);
        private static readonly Color Danger = Color.FromRgb(0xF4, 0x43, 0x36);
        private static readonly Color Safe = Color.FromRgb(0x4C, 0xAF, 0x50);
        private static readonly Color SafeBackground = Color.FromRgb(0xA5, 0xD6, 0xA7);
        private static readonly Color SafeText = Color.FromRgb(0x38, 0x8E, 0x3C);

        /// <summary>
        /// Génère un rapport PDF et le sauvegarde au chemin indiqué.
        /// Retourne les octets du PDF généré.
        /// </summary>
        public byte[] GenerateReport(ScanResult result, string outputPath = "")
        {
            // AssessAll évalue TOUTES les menaces et retourne la plus sévère
            var riskAssessment = RiskScoringService.AssessAll(result.Threats);
            var cult = CultureInfo.CurrentCulture;
            static string L(string key) => LocalizationService.GetString(key);
            var headerWhen = DateTime.Now.ToString("g", cult);

            var document = new Document();
            document.Info.Title = "optiSCAN";
            var normal = document.Styles[StyleNames.Normal]!;
            normal.Font.Name = "Segoe UI";
            normal.Font.Size = 11;

            var section = document.AddSection();
            section.PageSetup = document.DefaultPageSetup.Clone();
            section.PageSetup.PageFormat = PageFormat.A4;
            section.PageSetup.TopMargin = Unit.FromCentimeter(2.5);
            section.PageSetup.BottomMargin = Unit.FromCentimeter(2);
            section.PageSetup.LeftMargin = Unit.FromCentimeter(2);
            section.PageSetup.RightMargin = Unit.FromCentimeter(2);
            section.PageSetup.HeaderDistance = Unit.FromCentimeter(1);
            var contentWidth = Unit.FromCentimeter(21 - 4);

            // ── En-tête ──────────────────────────────────────────────
            var header = section.Headers.Primary.AddTable();
            header.AddColumn(Unit.FromCentimeter(5));
            header.AddColumn(contentWidth - Unit.FromCentimeter(5));
            var headerRow = header.AddRow();
            headerRow.VerticalAlignment = VerticalAlignment.Bottom;
            var brand = headerRow.Cells[0].AddParagraph("optiSCAN");
            brand.Format.Font.Size = 24;
            brand.Format.Font.Bold = true;
            brand.Format.Font.Color = Accent;
            var subtitle = headerRow.Cells[1].AddParagraph(LocalizationService.Format("Export_Pdf_HeaderSubtitle", headerWhen));
            subtitle.Format.Alignment = ParagraphAlignment.Right;
            subtitle.Format.Font.Size = 10;
            subtitle.Format.Font.Color = Muted;

            // ── Résumé ───────────────────────────────────────────────
            AddSectionTitle(section, L("Export_Pdf_Summary"), spaceBefore: 0);

            var summary = section.AddTable();
            summary.AddColumn(Unit.FromPoint(130));
            summary.AddColumn(contentWidth - Unit.FromPoint(130));
            summary.TopPadding = 2;
            summary.BottomPadding = 2;
            AddRow(summary, L("Export_Pdf_RowType"), result.TypeDisplay);
            AddRow(summary, L("Export_Pdf_RowTarget"), RedactPath(result.TargetPath));
            AddRow(summary, L("Export_Pdf_RowStart"), result.StartedAt.ToString("G", cult));
            if (result.FinishedAt.HasValue)
                AddRow(summary, L("Export_Pdf_RowEnd"), result.FinishedAt.Value.ToString("G", cult));
            AddRow(summary, L("Export_Pdf_RowDuration"),
                LocalizationService.Format("Export_Pdf_DurationSeconds", $"{result.Duration.TotalSeconds:F0}"));
            AddRow(summary, L("Export_Pdf_RowFiles"), result.FilesScanned.ToString("N0", cult));
            var threatsRow = AddRow(summary, L("Export_Pdf_RowThreats"), $"{result.ThreatsFound}");
            threatsRow.Cells[1].Format.Font.Color = result.ThreatsFound > 0 ? Danger : Safe;

            if (result.Threats.Count > 0)
            {
                // ── Évaluation de risque ─────────────────────────────
                AddSectionTitle(section, L("Export_Pdf_RiskTitle"), spaceBefore: 15);

                var risk = section.AddTable();
                risk.AddColumn(contentWidth);
                risk.Borders.Width = 1;
                risk.Borders.Color = Frame;
                risk.LeftPadding = risk.RightPadding = risk.TopPadding = risk.BottomPadding = Unit.FromPoint(8);
                var riskCell = risk.AddRow().Cells[0];

                var severity = riskCell.AddParagraph();
                var severityText = severity.AddFormattedText(riskAssessment.Severity ?? string.Empty);
                severityText.Font.Size = 16;
                severityText.Font.Bold = true;
                severity.AddText("    ");
                var score = severity.AddFormattedText(LocalizationService.Format("Export_Pdf_Score", riskAssessment.Score));
                score.Font.Size = 12;
                score.Font.Color = MutedDark;

                var recommendation = riskCell.AddParagraph(riskAssessment.Recommendation ?? string.Empty);
                recommendation.Format.SpaceBefore = 5;
                recommendation.Format.Font.Color = MutedDark;

                if (riskAssessment.Reasons.Count > 0)
                {
                    foreach (var reason in riskAssessment.Reasons)
                    {
                        var line = riskCell.AddParagraph("• " + reason);
                        line.Format.Font.Size = 10;
                        line.Format.Font.Color = Muted;
                    }
                }

                // ── Liste des menaces ────────────────────────────────
                AddSectionTitle(section, L("Export_Pdf_ThreatsTitle"), spaceBefore: 15);

                var threats = section.AddTable();
                var unit = contentWidth / 8;
                threats.AddColumn(unit * 4);
                threats.AddColumn(unit * 3);
                threats.AddColumn(unit);
                threats.TopPadding = 2;
                threats.BottomPadding = 2;

                var head = threats.AddRow();
                head.HeadingFormat = true;
                head.Format.Font.Bold = true;
                head.Format.Font.Size = 10;
                head.Cells[0].AddParagraph(L("Export_Pdf_ColLocation"));
                head.Cells[1].AddParagraph(L("Export_Pdf_ColThreat"));
                head.Cells[2].AddParagraph(L("Export_Pdf_ColTime"));

                foreach (var threat in result.Threats)
                {
                    var row = threats.AddRow();
                    var location = row.Cells[0].AddParagraph(RedactPath(threat.FilePath));
                    location.Format.Font.Size = 8;
                    var name = row.Cells[1].AddParagraph(threat.VirusName ?? string.Empty);
                    name.Format.Font.Size = 9;
                    name.Format.Font.Color = Danger;
                    var time = row.Cells[2].AddParagraph(threat.DetectedAt.ToString("T", cult));
                    time.Format.Font.Size = 9;
                }
            }
            else
            {
                var clean = section.AddTable();
                clean.AddColumn(contentWidth);
                clean.Shading.Color = SafeBackground;
                clean.LeftPadding = clean.RightPadding = clean.TopPadding = clean.BottomPadding = Unit.FromPoint(10);
                var cleanRow = clean.AddRow();
                cleanRow.TopPadding = 10;
                var message = cleanRow.Cells[0].AddParagraph(L("Export_Pdf_NoThreats"));
                message.Format.Alignment = ParagraphAlignment.Center;
                message.Format.Font.Size = 12;
                message.Format.Font.Color = SafeText;
            }

            // ── Pied de page ─────────────────────────────────────────
            var footer = section.Footers.Primary.AddParagraph();
            footer.Format.Alignment = ParagraphAlignment.Center;
            footer.Format.Font.Size = 8;
            footer.Format.Font.Color = Muted;
            footer.AddText(LocalizationService.Format(
                "Export_Pdf_Footer",
                ProductVersionInfo.ReleaseLabel,
                ProductVersionInfo.SemVer,
                DateTime.Now.ToString("G", cult)));
            footer.AddPageField();
            footer.AddText(" / ");
            footer.AddNumPagesField();

            var renderer = new PdfDocumentRenderer { Document = document };
            renderer.RenderDocument();
            byte[] pdfBytes;
            using (var stream = new MemoryStream())
            {
                renderer.PdfDocument.Save(stream, closeStream: false);
                pdfBytes = stream.ToArray();
            }

            if (!string.IsNullOrEmpty(outputPath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                File.WriteAllBytes(outputPath, pdfBytes);
            }

            return pdfBytes;
        }

        private static void AddSectionTitle(Section section, string text, double spaceBefore)
        {
            var title = section.AddParagraph(text);
            title.Format.SpaceBefore = Unit.FromPoint(spaceBefore);
            title.Format.SpaceAfter = Unit.FromPoint(8);
            title.Format.Font.Size = 14;
            title.Format.Font.Bold = true;
            title.Format.Font.Color = Accent;
            title.Format.Borders.Bottom.Width = 1;
            title.Format.Borders.Bottom.Color = Rule;
            title.Format.Borders.DistanceFromBottom = Unit.FromPoint(4);
        }

        /// <summary>
        /// Rapport PDF à partir d’une entrée d’historique (sans liste détaillée des fichiers si elle n’a pas été conservée).
        /// </summary>
        public byte[] GenerateReportFromSession(ScanSession session, string outputPath = "")
        {
            var result = new ScanResult
            {
                SessionId = session.SessionId,
                StartedAt = session.StartedAt,
                FinishedAt = session.FinishedAt,
                TargetPath = session.TargetPath,
                FilesScanned = session.FilesScanned,
                Status = Enum.TryParse<ScanStatus>(session.StatusDisplay, ignoreCase: true, out var st)
                    ? st
                    : ScanStatus.Completed,
                Type = MapScanType(session.TypeDisplay),
            };

            if (session.Threats.Count > 0)
                result.Threats = session.Threats.Select(t => t.Clone()).ToList();
            else if (session.ThreatsFound > 0)
            {
                var path = string.IsNullOrWhiteSpace(session.TargetPath) ? "—" : session.TargetPath;
                var at = session.FinishedAt ?? session.StartedAt;
                for (int i = 0; i < session.ThreatsFound; i++)
                {
                    result.Threats.Add(new ThreatInfo
                    {
                        FilePath = path,
                        VirusName = session.ThreatsFound == 1
                            ? LocalizationService.GetString("Export_Pdf_ThreatLegacySingle")
                            : LocalizationService.Format("Export_Pdf_ThreatLegacyMulti", i + 1, session.ThreatsFound),
                        DetectedAt = at,
                        DetectedBy = "historique"
                    });
                }
            }

            return GenerateReport(result, outputPath);
        }

        private static ScanType MapScanType(string typeDisplay)
        {
            foreach (ScanType t in Enum.GetValues<ScanType>())
            {
                if (string.Equals(typeDisplay, LocalizationService.ScanTypeDisplay(t), StringComparison.OrdinalIgnoreCase))
                    return t;
            }
            return ScanType.Folder;
        }

        /// <summary>
        /// Génère et sauvegarde automatiquement dans %LocalAppData%\optiSCAN\Reports\
        /// Retourne le chemin du fichier créé.
        /// </summary>
        public string GenerateAndSave(ScanResult result)
        {
            var fileName = $"SCAN_{result.TypeDisplay}_{result.StartedAt:yyyyMMdd_HHmmss}.pdf";
            // Supprimer les caractères invalides
            foreach (var c in Path.GetInvalidFileNameChars())
                fileName = fileName.Replace(c, '_');

            var outputPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiSCAN", "Reports", fileName);

            GenerateReport(result, outputPath);
            return outputPath;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static Row AddRow(Table table, string label, string value)
        {
            var row = table.AddRow();
            var name = row.Cells[0].AddParagraph(label);
            name.Format.Font.Bold = true;
            row.Cells[1].AddParagraph(value ?? string.Empty);
            return row;
        }
    }
}
