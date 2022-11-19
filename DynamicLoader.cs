using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static System.Environment;
namespace AntiCrack2022
{
    internal class DynamicLoader
    {
        private readonly Protected Protectedf = new();
        private readonly Dictionary<string, object> Functions = new();
        private readonly Dictionary<string, IntPtr> LibraryAddress = new();

        internal Protected ProtectedData => Protectedf;

        public DynamicLoader()
        {

        }
        public TDelegate Run<TDelegate>(string libname, SpecialFolder folder = SpecialFolder.System)
        {
            if (!Functions.ContainsKey(typeof(TDelegate).Name))
            {
                var func = GetFunction<TDelegate>(libname, folder);
                if(func is not null)
                {
                    _ = Functions.TryAdd(typeof(TDelegate).Name, func);
                    return func;
                }
                else
                {
                    throw new Exception();
                }
            }
            else
            {
                return (TDelegate)Functions[typeof(TDelegate).Name];
            }
        }
        private TDelegate GetFunction<TDelegate>(string libname, SpecialFolder folder)
        {
            var libraryName = libname.ToLower();
            if (!LibraryAddress.ContainsKey(libraryName))
            {
                //libname.OutLine();
                Protectedf.AddLibrary(libname, folder);
                _ = LibraryAddress.TryAdd(libraryName, LoadLibrary(Protectedf.ModulesNames[libraryName]));
            }
            return Marshal.GetDelegateForFunctionPointer<TDelegate>(GetExport(LibraryAddress[libraryName], typeof(TDelegate).Name));
        }
        public static IntPtr GetExport(IntPtr dllAddress, string funcName)
        {
            return NativeLibrary.GetExport(dllAddress, funcName);
        }
        public static IntPtr LoadLibrary(string libname)
        {
            return NativeLibrary.Load(libname);
        }
    }
}
