using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiCrack2022
{
    internal static class AppHelper
    {
        public static void OutLine(this object obj)
        {
            Console.WriteLine(obj.ToString());
        }
        public static void Out(this object obj)
        {
            Console.Write(obj.ToString());
        }
    }
}
