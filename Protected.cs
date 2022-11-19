using static System.Environment;

namespace AntiCrack2022
{
    internal class Protected
    {
        private readonly Dictionary<string, string> modulesNames = new();
        private readonly Dictionary<SpecialFolder, DirectoryInfo> basePaths = new();

        public Protected()
        {
        }

        public Dictionary<string, string> ModulesNames => modulesNames;

        public Dictionary<SpecialFolder, DirectoryInfo> BasePaths => basePaths;

        public void AddLibrary(string libname, SpecialFolder folder)
        {
            var lowername = libname.ToLower();
            if ((!ModulesNames.ContainsKey(lowername)))
            {
                if (!BasePaths.ContainsKey(folder))
                {
                    AddPath(folder);
                }
                foreach (var dll in BasePaths[folder].GetFiles())
                {
                    if (dll.Name.ToLower() == libname.ToLower())
                    {
                        //dll.FullName.OutLine();
                        if (!ModulesNames.ContainsValue(lowername))
                        {
                            _ = ModulesNames.TryAdd(lowername, dll.FullName);
                        } 
                    }
                }
            }
        }

        public void AddPath(SpecialFolder folder)
        {
            if (!BasePaths.ContainsKey(folder))
            {
                _ = BasePaths.TryAdd(folder, new(GetFolderPath(folder)));
            }
        }
    }
}