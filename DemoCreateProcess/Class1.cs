using System.Diagnostics;

public class TestClass
{
    public static void RunProcess(string path, string path2)
    {
        System.Console.WriteLine("[STDOUT] Running {0} and {1}...", path, path2);
        System.Console.Error.WriteLine("[STDERR] Running {0} and {1}...", path, path2);
        Process.Start(path);
        Process.Start(path2);
    }
}