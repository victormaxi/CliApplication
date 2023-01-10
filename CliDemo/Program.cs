// We will be using CliWrap third party libray in this project
using CliWrap;
using CliWrap.Buffered;
using System.Diagnostics;
using System.Management.Automation;

// To check if Docker exist on my machine

//var dockerResults = await Cli.Wrap("docker")
//    .WithArguments(new[] { "--version" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(dockerResults.StandardOutput);


// Check git version on machine

//var gitResults = await Cli.Wrap("git")
//    .WithArguments(new[] { "--version" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(gitResults.StandardOutput);


// running Powershell
//var powershellResults = await Cli.Wrap("powershell")
//    .WithWorkingDirectory(@"C:\Users")
//    .WithArguments(new[] { @"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts\ProjConfig.ps1 CONTOSO dev" })
//    .ExecuteBufferedAsync();

//Console.WriteLine(powershellResults.StandardOutput);


//var projRunTime = await Cli.Wrap(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts\ProjRuntimeCli.ps1")
//    .WithArguments(@"  - GrifClientCode CONTOSO - GrifEnvironment Development - UseExistingContext")
//    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
//    //.WithArguments(new[] { @" " })
//    //.WithArguments(new[] { @"az login --scope https://graph.microsoft.com//.default" })
//    .ExecuteBufferedAsync();


ProcessStartInfo processInfo = new ProcessStartInfo();
processInfo.FileName = @"powershell.exe";
processInfo.Arguments = @"& {C:\Users\Lenovo\source\griffinv4\ErpCore\scripts\ProjRuntimeCli.ps1}";
processInfo.Arguments = @"& {- GrifClientCode CONTOSO - GrifEnvironment Development - UseExistingContext}";
processInfo.RedirectStandardError = true;
processInfo.RedirectStandardOutput = true;
processInfo.UseShellExecute= false;
processInfo.CreateNoWindow = true;

Process process = new Process();
process.StartInfo = processInfo;
process.Start();

Console.WriteLine("Output - {0}", process.StandardOutput.ReadToEnd());
Console.WriteLine("Errors - {0}", process.StandardError.ReadToEnd());
Console.Read();


var projRunTime = await Cli.Wrap(@"\Users\Lenovo\source\griffinv4\ErpCore\scripts\ProjRuntimeCli.ps1")
    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
    .WithArguments(new[] { @"\ProjRuntimeCli.ps1 - GrifClientCode CONTOSO - GrifEnvironment Development - UseExistingContext" })
    //.WithArguments(new[] { @"az login --scope https://graph.microsoft.com//.default" })
    .ExecuteBufferedAsync();

Console.WriteLine(projRunTime.StandardOutput);


var devEnvSetup = await Cli.Wrap("powershell")
    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
    .WithArguments(new[] { @".\__DevEnvSetup.ps1" })
    .ExecuteBufferedAsync();

Console.WriteLine(devEnvSetup.StandardOutput);

Console.WriteLine("Dev done");





//var projRunTime = await Cli.Wrap("powershell")
//    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
//    //.WithArguments(new[] { @".\ProjRuntimeCli.ps1 - GrifClientCode CONTOSO - GrifEnvironment Development - UseExistingContext" })
//    .WithArguments(new[] { @"az login --scope https://graph.microsoft.com//.default" })
//    .ExecuteBufferedAsync();

Console.WriteLine(projRunTime.StandardOutput);

Console.WriteLine("projRunTime done");



var credentialProvider = await Cli.Wrap("powershell")
    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
    .WithArguments(new[] { @"& ""${env:USERPROFILE}\.nuget\plugins\netfx\CredentialProvider.Microsoft\CredentialProvider.Microsoft.exe"" -I -C -V Verbose -U ""https://pkgs.dev.azure.com/griffinv4/_packaging/griffinv4-packages/nuget/v3/index.json""" })
    .ExecuteBufferedAsync();

Console.WriteLine(credentialProvider.StandardOutput);


Console.WriteLine("cred done");

var devMigration = await Cli.Wrap("powershell")
    .WithWorkingDirectory(@"C:\Users\Lenovo\source\griffinv4\ErpCore\scripts")
    .WithArguments(new[] { @".\DevMigrationApply.ps1 - GrifClientCode CONTOSO - GrifProjGroup Griffin - GrifEnvironment Development" })
    .ExecuteBufferedAsync();

Console.WriteLine(devMigration.StandardOutput);

Console.WriteLine("DevMigration done");



Console.WriteLine("Hello done.");



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
