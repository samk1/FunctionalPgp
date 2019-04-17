using System;
using System.IO;
using Pgp.Messages;


namespace PgpTool
{
    class Program
    {
        static void Main(string[] args)
        {
            ISecretKeyRingReader secretKeyRing =
                new SecretKeyRingReader(File.OpenRead(@"C:\Users\samk\mykey.key"));

            secretKeyRing.Read();

            Console.WriteLine("Hello World!");
        }
    }
}
