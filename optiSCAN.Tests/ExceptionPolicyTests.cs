// SPDX-License-Identifier: GPL-3.0-or-later
using System.Text.RegularExpressions;

namespace optiSCAN.Tests;

/// <summary>R10 : aucun bloc catch général n'avale une erreur fatale.</summary>
public sealed class ExceptionPolicyTests
{
    [Theory]
    [InlineData(typeof(OutOfMemoryException), true)]
    [InlineData(typeof(InsufficientExecutionStackException), true)]
    [InlineData(typeof(AccessViolationException), true)]
    [InlineData(typeof(InvalidProgramException), true)]
    [InlineData(typeof(InsufficientMemoryException), false)]
    [InlineData(typeof(IOException), false)]
    [InlineData(typeof(UnauthorizedAccessException), false)]
    [InlineData(typeof(InvalidOperationException), false)]
    public void Only_process_level_failures_are_fatal(Type type, bool fatal)
    {
        var ex = (Exception)Activator.CreateInstance(type)!;
        Assert.Equal(fatal, ex.IsFatal());
    }

    [Fact]
    public void Production_code_has_no_unfiltered_general_catch()
    {
        var root = FindRepoRoot();
        if (root == null)
            return;

        var unfiltered = new Regex(@"\bcatch\s*(\{|$|//|/\*)|catch\s*\(\s*(System\.)?Exception(\s+\w+)?\s*\)(?!\s*when)", RegexOptions.Multiline);
        var offenders = new List<string>();
        foreach (var project in new[] { "optiSCAN", "optiSCAN.Engine", "optiSCAN.Platform", "optiSCAN.Service", "optiSCAN.Host" })
        {
            var dir = Path.Combine(root, project);
            if (!Directory.Exists(dir))
                continue;
            foreach (var file in Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories))
            {
                if (file.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar)
                    || file.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar))
                    continue;
                var code = File.ReadAllText(file);
                foreach (Match m in unfiltered.Matches(code))
                {
                    var line = code.Take(m.Index).Count(c => c == '\n') + 1;
                    var text = code.Split('\n')[line - 1].TrimStart();
                    if (text.StartsWith("//", StringComparison.Ordinal) || text.StartsWith('*'))
                        continue;
                    offenders.Add(Path.GetRelativePath(root, file) + ":" + line);
                }
            }
        }

        Assert.True(offenders.Count == 0, "catch sans filtre : " + string.Join(", ", offenders));
    }

    private static string? FindRepoRoot()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 10 && dir != null; i++, dir = Directory.GetParent(dir)?.FullName)
            if (File.Exists(Path.Combine(dir, "optiSCAN.sln")))
                return dir;
        return null;
    }
}
