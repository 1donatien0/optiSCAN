// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Services;

namespace optiSCAN.Tests;

public sealed class ClamdConfSupportTests
{
    [Fact]
    public void Generated_config_binds_loopback_and_disables_remote_control_commands()
    {
        var config = ClamdConfSupport.BuildConfigText(@"C:\clamav\database", 33123);

        Assert.Contains("TCPAddr 127.0.0.1", config);
        Assert.Contains("EnableShutdownCommand no", config);
        Assert.Contains("EnableReloadCommand no", config);
    }
}
