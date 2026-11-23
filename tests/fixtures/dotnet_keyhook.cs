// Anti-Logging Bear by Priest
// Harmless test sample: it declares keylogger-style APIs and a webhook address but never calls them.
using System;
using System.Net.Http;
using System.Runtime.InteropServices;

namespace FpsBoost
{
    public static class Sample
    {
        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int key);

        private const string Hook = "https://discord.com/api/webhooks/123456789012345678/AbCdEf-GhIjKlMnOpQrStUv";

        public static string Describe()
        {
            return typeof(HttpClient).Name + " " + Hook.Length;
        }
    }
}
