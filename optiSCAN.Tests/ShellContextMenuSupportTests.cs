// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Localization;

namespace optiSCAN.Tests;

public sealed class ShellContextMenuSupportTests
{
    [Fact]
    public void StableMenuKey_is_ascii_and_unique()
    {
        Assert.Equal("optiSCAN.Scan", ShellContextMenuSupport.StableMenuKey);
        Assert.DoesNotContain(' ', ShellContextMenuSupport.StableMenuKey);
    }

    [Fact]
    public void LegacyMenuKeys_include_known_orphan_names()
    {
        var keys = ShellContextMenuSupport.LegacyMenuKeys;
        Assert.Contains("Scanner avec optiSCAN", keys);
        Assert.Contains("Scan with optiSCAN", keys);
        Assert.Contains("ScanWithOptiSCAN", keys);
        Assert.Contains(ShellContextMenuSupport.StableMenuKey, keys);
    }

    [Fact]
    public void RemoveAllMenus_does_not_throw_when_menus_absent()
    {
        var ex = Record.Exception(ShellContextMenuSupport.RemoveAllMenus);
        Assert.Null(ex);
    }
}
