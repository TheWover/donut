using System.Diagnostics;

public class TestClass
{
    public static void RunProcess(string path, string path2)
    {
        Process.Start(path);
        Process.Start(path2);
    }
}