using optiSCAN.Models;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System.IO;

namespace optiSCAN.Services
{
    /// <summary>
    /// Génère des rapports PDF complets à partir d'un ScanResult.
    /// Utilise QuestPDF (licence Community).
    /// </summary>
    public class PdfReportGenerator
    {
        static PdfReportGenerator()
        {
            QuestPDF.Settings.License = LicenseType.Community;
        }

        /// <summary>
        /// Génère un rapport PDF et le sauvegarde au chemin indiqué.
        /// Retourne les octets du PDF généré.
        /// </summary>
        public byte[] GenerateReport(ScanResult result, string outputPath = "")
        {
            // AssessAll évalue TOUTES les menaces et retourne la plus sévère
            var riskAssessment = RiskScoringService.AssessAll(result.Threats);

            var document = Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4);
                    page.Margin(2, Unit.Centimetre);
                    page.DefaultTextStyle(x => x.FontFamily("Segoe UI"));

                    // ── En-tête ──────────────────────────────────────────────
                    page.Header()
                        .Row(row =>
                        {
                            row.AutoItem()
                                .Text("optiSCAN")
                                .FontSize(24)
                                .FontColor(Colors.Blue.Darken2)
                                .Bold();

                            row.Spacing(10);

                            row.RelativeItem()
                                .AlignRight()
                                .Text($"Rapport d'analyse antivirus\n{DateTime.Now:dd/MM/yyyy HH:mm}")
                                .FontSize(10)
                                .FontColor(Colors.Grey.Medium);
                        });

                    // ── Contenu ──────────────────────────────────────────────
                    page.Content()
                        .PaddingVertical(10)
                        .Column(col =>
                        {
                            // Résumé
                            col.Item()
                                .BorderBottom(1).BorderColor(Colors.Grey.Lighten2)
                                .PaddingBottom(5)
                                .Text("RÉSUMÉ DE L'ANALYSE")
                                .FontSize(14).Bold()
                                .FontColor(Colors.Blue.Darken2);

                            col.Item().PaddingTop(10)
                                .Table(table =>
                                {
                                    table.ColumnsDefinition(cols =>
                                    {
                                        cols.ConstantColumn(130);
                                        cols.RelativeColumn();
                                    });

                                    AddRow(table, "Type d'analyse", result.TypeDisplay);
                                    AddRow(table, "Cible", result.TargetPath);
                                    AddRow(table, "Date de début", result.StartedAt.ToString("dd/MM/yyyy HH:mm:ss"));
                                    if (result.FinishedAt.HasValue)
                                        AddRow(table, "Date de fin", result.FinishedAt.Value.ToString("dd/MM/yyyy HH:mm:ss"));
                                    AddRow(table, "Durée", $"{result.Duration.TotalSeconds:F0} secondes");
                                    AddRow(table, "Fichiers analysés", $"{result.FilesScanned:N0}");

                                    // Menaces avec couleur conditionnelle
                                    table.Cell().Text("Menaces détectées").FontSize(11).SemiBold();
                                    table.Cell().Text($"{result.ThreatsFound}")
                                        .FontSize(11)
                                        .FontColor(result.ThreatsFound > 0 ? Colors.Red.Medium : Colors.Green.Medium);
                                });

                            // Évaluation de risque
                            if (result.Threats.Count > 0)
                            {
                                col.Item().PaddingTop(15)
                                    .BorderBottom(1).BorderColor(Colors.Grey.Lighten2)
                                    .PaddingBottom(5)
                                    .Text("ÉVALUATION DU RISQUE")
                                    .FontSize(14).Bold()
                                    .FontColor(Colors.Blue.Darken2);

                                col.Item().PaddingTop(8)
                                    .Border(1).BorderColor(Colors.Grey.Lighten1)
                                    .Padding(10)
                                    .Column(riskCol =>
                                    {
                                        riskCol.Item().Row(row =>
                                        {
                                            row.AutoItem()
                                                .Text($"{riskAssessment.Icon}  {riskAssessment.Severity}")
                                                .FontSize(16).Bold();
                                            row.Spacing(20);
                                            row.AutoItem()
                                                .Text($"Score : {riskAssessment.Score}/100")
                                                .FontSize(12)
                                                .FontColor(Colors.Grey.Darken1);
                                        });

                                        riskCol.Item().PaddingTop(5)
                                            .Text(riskAssessment.Recommendation)
                                            .FontSize(11)
                                            .FontColor(Colors.Grey.Darken1);

                                        if (riskAssessment.Reasons.Count > 0)
                                        {
                                            riskCol.Item().PaddingTop(5)
                                                .Text("• " + string.Join("\n• ", riskAssessment.Reasons))
                                                .FontSize(10)
                                                .FontColor(Colors.Grey.Medium);
                                        }
                                    });

                                // Liste des menaces
                                col.Item().PaddingTop(15)
                                    .BorderBottom(1).BorderColor(Colors.Grey.Lighten2)
                                    .PaddingBottom(5)
                                    .Text("MENACES DÉTECTÉES")
                                    .FontSize(14).Bold()
                                    .FontColor(Colors.Blue.Darken2);

                                col.Item().PaddingTop(10)
                                    .Table(table =>
                                    {
                                        table.ColumnsDefinition(cols =>
                                        {
                                            cols.RelativeColumn(3);
                                            cols.RelativeColumn(3);
                                            cols.RelativeColumn(2);
                                            cols.RelativeColumn(2);
                                        });

                                        table.Header(header =>
                                        {
                                            header.Cell().Text("Fichier").FontSize(10).Bold();
                                            header.Cell().Text("Menace").FontSize(10).Bold();
                                            header.Cell().Text("Moteur").FontSize(10).Bold();
                                            header.Cell().Text("Heure").FontSize(10).Bold();
                                        });

                                        foreach (var threat in result.Threats)
                                        {
                                            table.Cell().Text(Path.GetFileName(threat.FilePath)).FontSize(9);
                                            table.Cell().Text(threat.VirusName).FontSize(9).FontColor(Colors.Red.Medium);
                                            table.Cell().Text(threat.DetectedBy ?? "ClamAV").FontSize(9);
                                            table.Cell().Text(threat.DetectedAt.ToString("HH:mm:ss")).FontSize(9);
                                        }
                                    });
                            }
                            else
                            {
                                col.Item().PaddingTop(15)
                                    .Background(Colors.Green.Lighten3)
                                    .Padding(10)
                                    .AlignCenter()
                                    .Text("✅ Aucune menace détectée")
                                    .FontSize(12)
                                    .FontColor(Colors.Green.Darken2);
                            }
                        });

                    // ── Pied de page ─────────────────────────────────────────
                    page.Footer()
                        .AlignCenter()
                        .DefaultTextStyle(s => s.FontSize(8).FontColor(Colors.Grey.Medium))
                        .Text(x =>
                        {
                            x.Span($"optiSCAN v2.0 — Rapport généré le {DateTime.Now:dd/MM/yyyy HH:mm:ss} — Page ");
                            x.CurrentPageNumber();
                            x.Span(" / ");
                            x.TotalPages();
                        });
                });
            });

            var pdfBytes = document.GeneratePdf();

            if (!string.IsNullOrEmpty(outputPath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                File.WriteAllBytes(outputPath, pdfBytes);
            }

            return pdfBytes;
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

        private static void AddRow(TableDescriptor table, string label, string value)
        {
            table.Cell().Text(label).FontSize(11).SemiBold();
            table.Cell().Text(value).FontSize(11);
        }
    }
}
