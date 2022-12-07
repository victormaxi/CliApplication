// We will be using CliWrap third party libray in this project
using CliWrap;
using CliWrap.Buffered;
using System.Management.Automation;

// To check if Docker exist on my machine

//var dockerResults = await Cli.Wrap("docker")
//    .WithArguments(new[] { "--version" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(dockerResults.StandardOutput);


//// Check git version on machine

//var gitResults = await Cli.Wrap("git")
//    .WithArguments(new[] { "--version" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(gitResults.StandardOutput);


// running Powershell
var powershellResults = await Cli.Wrap("powershell")
    .WithWorkingDirectory(@"C:\Users")
    .WithArguments(new[] { @"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts\ProjConfig.ps1 CONTOSO dev" })
    .ExecuteBufferedAsync();

Console.WriteLine(powershellResults.StandardOutput);

//var powershellResults = await Cli.Wrap("powershell")
//    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
//    .WithArguments(new[] { @"& ""${env:USERPROFILE}\.nuget\plugins\netfx\CredentialProvider.Microsoft\CredentialProvider.Microsoft.exe"" -I -C -V Verbose -U ""https://pkgs.dev.azure.com/griffinv4/_packaging/griffinv4-packages/nuget/v3/index.json""" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(powershellResults.StandardOutput);

//var powershellResults = await Cli.Wrap("powershell")
//    .WithWorkingDirectory(@"C:\Users")
//    .WithArguments(new[] { @"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts\ProjRuntimeCli.ps1 GrifClientCode CONTOSO" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(powershellResults.StandardOutput);


//var powershellResults = await Cli.Wrap("powershell")
//    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
//    .WithArguments(new[] { "choco" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(powershellResults.StandardOutput);


//var powershellResults = await Cli.Wrap("powershell")
//    .WithArguments(new[] { "choco" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(powershellResults.StandardOutput);

//var powershellResults = await Cli.Wrap("powershell").
//    WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts\ProjRuntimeCli.ps1")
//    .WithArguments(new[] { " GrifClientCode CONTOSO" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(powershellResults.StandardOutput);


//using var ps = PowerShell.Create();

//var param = " CONTOSO";

//try
//{
//    ps.AddCommand("ps1 GrifClientCode").AddParameter(param).Invoke();
//}
//catch(Exception ex)
//{
//    Console.WriteLine(ex.Message);
//}
Console.ReadLine();

Console.WriteLine("Hello, World!");
