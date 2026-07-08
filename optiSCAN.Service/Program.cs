using optiSCAN.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "optiSCAN Protection v9");
builder.Services.AddHostedService<ProtectionWindowsService>();
var host = builder.Build();
await host.RunAsync();
