// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ClamdHostTests
{
    [Fact]
    public void Config_path_with_spaces_stays_a_single_argument()
    {
        const string conf = @"C:\Users\Jean Dupont\AppData\Local\optiSCAN\clamd\clamd.conf";

        var psi = ClamdHost.BuildStartInfo(@"C:\Program Files\optiSCAN\clamav\x64\clamd.exe", conf);

        // Un seul argument, chemin intact : .NET l'entourera de guillemets au lancement.
        var arg = Assert.Single(psi.ArgumentList);
        Assert.Equal("--config-file=" + conf, arg);
        Assert.Empty(psi.Arguments);
        Assert.False(psi.UseShellExecute);
        Assert.Equal(@"C:\Program Files\optiSCAN\clamav\x64", psi.WorkingDirectory);
    }
}
