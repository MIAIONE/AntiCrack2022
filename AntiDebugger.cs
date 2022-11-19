using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AntiCrack2022
{
    internal class AntiDebugger
    {
        private readonly DynamicLoader Loader;
        private readonly System.Timers.Timer WatchDogHandle;
        public AntiDebugger(DynamicLoader loader)
        {
            Loader = loader;
            loader.ProtectedData.AddPath(Environment.SpecialFolder.System);
            WatchDogHandle = new (1);
            WatchDogHandle.Elapsed += new(WatchDog);
            
        }
        public void Watch()
        {
            WatchDogHandle.Start();
        }
        
        public bool IsDebug()
        {
            // 获取当前进程process实例
            var currentProcess = Process.GetCurrentProcess();
            //获取当前进程句柄
            var appHandle = currentProcess.Handle;

            //检查是否有调试文件
            var debugEnvironment = CheckDeveloperToolsAndFiles(currentProcess);

            //附加调试器
            var isDebuggerPresent = Loader.Run<IsDebuggerPresent>("kernel32.dll")();
            
            //远程调试器
            var runRemoteCheckState = Loader.Run<CheckRemoteDebuggerPresent>("kernel32.dll")(
                appHandle,
                out bool checkRemoteDebuggerPresent
                );
            

            /*
             * 这里需要弹出我们自己加的调试器
             * 我们不需要弹出WIN32调试器,反而要利用他触发breakpoint
             * 触发之后timer会无限循环加载C:\Windows\System32\*.dll,导致异常
             * 如果不行,继续运行到exit,再不行就触发breakpoint
             */
            
            try { Loader.Run<DebugActiveProcessStop>("kernel32.dll")(currentProcess.Id); } catch { }
            
            return
                Debugger.IsAttached||
                debugEnvironment||
                isDebuggerPresent ||
                checkRemoteDebuggerPresent ||
                (runRemoteCheckState == false)
                ;
        }
        private bool CheckDeveloperToolsAndFiles(Process app)
        {
            var appPath = Path.GetDirectoryName(app.MainModule?.FileName);
            if ((appPath != null) && (appPath != ""))
            {
                //如果进行静态分析,如ida64,会产生debuginfo文件
                //此时肯定会用x64dbg/od动态调试,然后直接exit程序
                var banExtf = new List<string>()
                {
                    "*.idb",
                    "*.dump",
                    "*.dmp",
                    "*.i64",
                    "*.i32",
                    "*.dd64",
                    "*.dd32",
                    "*.obj",
                    "*.map",
                    "*dump*",
                    "*fix*",
                    "*crack*",
                    "*unpack*",
                    "*.rsp",
                    "*.exp",
                    "*.dll",
                    "*.db",
#if DEBUG == false
                    "*.pdb" //否则程序无法调试
#endif
                };
                foreach (var ext in banExtf)
                {
                    try
                    {
                        var files = Directory.EnumerateFiles(appPath, ext, SearchOption.AllDirectories);
                        if (files is not null)
                        {
                            return files.Any();
                        }
                    }
                    catch { }
                }
                var computers = new List<string>()
                {
                    "15pb",
                    "7man2",
                    "stella",
                    "f4kh9od",
                    "willcarter",
                    "biluta",
                    "ehwalker",
                    "hong lee",
                    "joe cage",
                    "jonathan",
                    "kindsight",
                    "malware",
                    "peter miller",
                    "petermiller",
                    "phil",
                    "rapit",
                    "r0b0t",
                    "cuckoo",
                    "vm-pc",
                    "analyze",
                    "vbccsb",
                    "roslyn",
                    "vince",
                    "test",
                    "sample",
                    "mcafee",
                    "vmscan",
                    "mallab",
                    "abby",
                    "elvis",
                    "wilbert",
                    "joe smith",
                    "hanspeter",
                    "johnson",
                    "placehole",
                    "tequila",
                    "paggy sue",
                    "klone",
                    "oliver",
                    "stevens",
                    "ieuser",
                    "virlab",
                    "beginer",
                    "beginner",
                    "markos",
                    "semims",
                    "gregory",
                    "tom-pc",
                    "will carter",
                    "angelica",
                    "eric johns",
                    "john ca",
                    "lebron james",
                    "rats-pc",
                    "robot",
                    "serena",
                    "sofynia",
                    "straz",
                    "bea-ch"
                };
                foreach (var computer in computers)
                {
                    if(Environment.MachineName.Contains(computer, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
                var debuggers = new List<string>() 
                { 
                    "python",
                    "vmacthlp",
                    "VGAuthService",
                    "vmtoolsd",
                    "TPAutoConnSvc",
                    "ftnlsv",
                    "ftscanmgrhv",
                    "vmwsprrdpwks",
                    "usbarbitrator",
                    "horizon_client_service",
                    "ProcessHacker",
                    "procexp",
                    "Autoruns",
                    "pestudio",
                    "Wireshark",
                    "dumpcap",
                    "TSVNCache",
                    "dnSpy",
                    "ConEmu",
                    "010Editor",
                    "ida64",
                    "ida",
                    "Procmon",
                    "ollydbg",
                    "x64dbg",
                    "x32dbg",
                    "x96dbg",
                    "windbg",
                    "windbgx",
                    "dbgsrv",
                    "dbgrpc",
                    "kdbgctrl",
                    "DbgX.Shell",
                    "Dbgview",
                    "LordPE",
                    "Fiddler",
                    "CFF Explorer",
                    "sample",
                    "vboxservice",
                    "vboxtray",
                    "vsjitdebugger",
                    "HRSword"
                };
                foreach(var debugger in debuggers)
                {
                    try
                    {
                        var procDetectDbg = false;
                        Process.GetProcesses().ToList().ForEach(x =>
                        {
                            if(x.ProcessName.Contains(debugger, StringComparison.OrdinalIgnoreCase))
                            {
                                procDetectDbg = true;
                            }

                            if (x.MainWindowTitle.Contains(debugger, StringComparison.OrdinalIgnoreCase))
                            {
                                procDetectDbg = true;
                            }


                        });
                        return procDetectDbg;
                    }
                    catch
                    {
                        continue;
                    }
                }
                foreach (ProcessModule processmd in Process.GetCurrentProcess().Modules)
                {
                    var dll = processmd.FileName;
                    if(dll is not null)
                    {
                        var dllDir = Path.GetDirectoryName(dll);
                        if ((dll != Environment.ProcessPath)&&(dllDir is not null))
                        {
                            if (new DirectoryInfo(dllDir) != Loader.ProtectedData.BasePaths[Environment.SpecialFolder.System])
                            {
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            else
            {
                return true;
            }
        }
        private void LoadSystemAllDllFiles()
        {
            try
            {
                var files = Directory.EnumerateFiles(
                    Loader.ProtectedData.BasePaths[Environment.SpecialFolder.System].FullName,
                    "*.dll",
                    SearchOption.AllDirectories
                    );
                if (files is not null)
                {
                    if (files.Any())
                    {
                        foreach(var file in files)
                        {
                            try
                            {
                                DynamicLoader.LoadLibrary(file);
                                Debugger.Break();
                            }
                            catch
                            {
                            }
                        }
                    }
                }
            }
            catch { }
        }
        private void WatchDog(object? obj, System.Timers.ElapsedEventArgs args)
        {
            while (IsDebug())
            {
                LoadSystemAllDllFiles();
                Environment.Exit(0);
                Loader.Run<DebugBreak>("kernel32.dll")();
            }
            //Loader.Run<DebugBreak>("kernel32.dll")();
        }

        /// <summary>
        /// 尝试附加调试器到指定进程
        /// </summary>
        /// <param name="pid"> PID </param>
        /// <returns> 是否成功 </returns>
        private delegate bool DebugActiveProcess(int pid);

        /// <summary>
        /// 尝试停止指定进程的调试器
        /// </summary>
        /// <param name="pid"> PID </param>
        /// <returns> 是否成功 </returns>
        private delegate bool DebugActiveProcessStop(int pid);

        /// <summary>
        /// 主动断点
        /// </summary>
        private delegate void DebugBreak();

        /// <summary>
        /// 在指定的进程中断点
        /// </summary>
        /// <param name="appHandle"> 进程句柄 </param>
        /// <returns> 是否成功 </returns>
        private delegate bool DebugBreakProcess(IntPtr appHandle);

        /// <summary>
        /// 检查附加调试器 (易被屏蔽)
        /// </summary>
        /// <returns> 是否被调试 </returns>
        private delegate bool IsDebuggerPresent();

        /// <summary>
        /// 检查远程调试器
        /// </summary>
        /// <param name="appHandle"> 进程句柄 </param>
        /// <param name="isDebuggerPresent"> 是否被调试 </param>
        /// <returns> 函数是否成功 </returns>
        private delegate bool CheckRemoteDebuggerPresent(IntPtr appHandle, out bool isDebuggerPresent);


        private enum PROCESS_INFO_CLASS : int
        {
            ProcessBasicInformation = 0x00,
            ProcessDebugPort = 0x07,
            ProcessExceptionPort = 0x08,
            ProcessAccessToken = 0x09,
            ProcessWow64Information = 0x1A,
            ProcessImageFileName = 0x1B,
            ProcessDebugObjectHandle = 0x1E,
            ProcessDebugFlags = 0x1F,
            ProcessExecuteFlags = 0x22,
            ProcessInstrumentationCallback = 0x28,
            MaxProcessInfoClass = 0x64
        }
        enum THREAD_INFO_CLASS : int
        {
            ThreadBasicInformation,
            ThreadTimes,
            ThreadPriority,
            ThreadBasePriority,
            ThreadAffinityMask,
            ThreadImpersonationToken,
            ThreadDescriptorTableEntry,
            ThreadEnableAlignmentFaultFixup,
            ThreadEventPair_Reusable,
            ThreadQuerySetWin32StartAddress,
            ThreadZeroTlsCell,
            ThreadPerformanceCount,
            ThreadAmILastThread,
            ThreadIdealProcessor,
            ThreadPriorityBoost,
            ThreadSetTlsArrayAddress,
            ThreadIsIoPending,
            ThreadHideFromDebugger,
            ThreadBreakOnTermination,
            MaxThreadInfoClass
        }
    }
}