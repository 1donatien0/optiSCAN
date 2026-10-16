// SPDX-License-Identifier: GPL-3.0-or-later
using optiSCAN.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using optiSCAN.Platform;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = ProtectionIdentifiers.ServiceName);
builder.Services.AddHostedService<ProtectionWindowsService>();
var host = builder.Build();
await host.RunAsync();
