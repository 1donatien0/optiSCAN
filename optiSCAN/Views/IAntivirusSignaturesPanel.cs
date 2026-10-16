// SPDX-License-Identifier: GPL-3.0-or-later
namespace optiSCAN.Views;

/// <summary>Onglet Signatures de <see cref="AntivirusView"/>.</summary>
public interface IAntivirusSignaturesPanel
{
    void UpdateSignaturesPanel(
        string yaraVersion,
        string yaraLastMaj,
        string clamVersion,
        string clamLastMaj);
}
