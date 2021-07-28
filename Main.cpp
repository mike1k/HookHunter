#include "HookHunter.hpp"


int main(int argc, char* argv[])
{
    if (argc > 1)
    {
        //
        // Build spdlog
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::debug);
        console_sink->set_pattern("[%^%L%$] %v");

        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/console.txt", true);
        file_sink->set_level(spdlog::level::trace);


        g_log = std::make_shared<spdlog::logger>("multi_sink", spdlog::sinks_init_list{ console_sink, file_sink });
        g_log->set_level(spdlog::level::debug);

        g_log->info("HookHunter started..");

        for (int i = 1; i < argc; i++)
        {
            //
            // Extract process ID or look for process by name..
            if (_stricmp(argv[i], "-proc") == 0) 
            {
                const char* szArg = argv[++i];

                if (szArg[0] != '\'')
                {
                    cfg.ProcessId = std::atoi(szArg);
                    if (cfg.ProcessId == 0)
                    {
                        g_log->critical("Invalid process id '{}'", szArg);
                        return EXIT_FAILURE;
                    }
                }
                else
                {
                    std::string argProc = std::string(szArg).substr(1, strlen(szArg) - 2);
                    spdlog::stopwatch sw;

                    // Search for process with the name
                    while ((cfg.ProcessId = HhSearchForProcess(argProc)) == static_cast<DWORD>(-1))
                    {
                        if (std::chrono::duration_cast<std::chrono::milliseconds>(sw.elapsed()).count() > 10000)
                        {
                            g_log->critical("Timed out searching for process {}.", argProc);
                            return EXIT_FAILURE;
                        }

                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                continue;
            }

            //
            // Accept a custom module list, if empty then
            if (_stricmp(argv[i], "-mod") == 0)
            {
                while (i + 1 < argc && argv[i+1][0] != '-')
                {
                    std::string smod = argv[++i];
                    std::transform(smod.begin(), smod.end(), smod.begin(), ::tolower);

                    cfg.ModuleList.push_back(std::move(smod));
                }

                continue;
            }

            //
            // 
            if (_stricmp(argv[i], "-dump") == 0)
            {
                cfg.DumpModules = true;
            }

            //
            // May not work in your favor on X86.
            // Reason being is X86 will have to take into consideration relocations/etc
            // which are currently not (todo)
            if (_stricmp(argv[i], "-heal") == 0)
            {
                cfg.Heal = true;
            }

            //
            // -pecheck allows for an input file that's imports are traversed
            // HookHunter will spit warnings if the PE file is using imports that are hooked by the target
            if (_stricmp(argv[i], "-pecheck") == 0)
            {
                cfg.IntegrityCheckPE = argv[++i];
            }

            if (_stricmp(argv[i], "-verbose") == 0)
            {
                cfg.Verbose = true;
            }
        }

        //
        // Instantiate a HookHunter class
        hookhunter = std::make_unique<HookHunter>();
        spdlog::stopwatch processStopwatch;
        hookhunter->BeginScanning();


        g_log->debug("Finished scanning, it took {} milliseconds.",
            std::chrono::duration_cast<std::chrono::milliseconds>(processStopwatch.elapsed()).count());

        hookhunter->Publish();
    }
    else
    {
        std::cout << "HookHunter: Analyze patches in a process (developed by github.com/mike1k)" << std::endl;
        std::cout <<
            "Usage: \thookhunter\n  -proc \t(required) process name/process id" <<
            std::endl;
        std::cout << "  -mod: \t(optional) names of modules to check (or all if none specified)." << std::endl;
        std::cout << "  -dump: \t(optional) dumps patched and unpatched modules for further investigation." << std::endl;
        std::cout << "  -pecheck: \t(optional) path to a file to alert if any imports the executable uses are being modified." << std::endl;
        std::cout << "  -heal: \t(optional) repair all modifications to the target binary to the original byte code." << std::endl;
        std::cout << "  -verbose: \t(optional) log redundant messages associated with HookHunter's scanning" << std::endl;

        std::cout <<
            "Example usages:\n"
            "*\thookhunter -proc 'explorer.exe' -mod ntdll kernel32 -pecheck c:\\my_dll.dll -heal -verbose -dump\n" <<
            "*\thookhunter -proc 123456 -mod ntdll.dll\n" <<
            std::endl;

        std::cout << std::endl;
    }
    

    return EXIT_SUCCESS;
}