#include "HookHunter.hpp"

DWORD HhSearchForProcess(std::string_view process_name) noexcept
{
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof pe32;

    hh::nt::ScopedHandle hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (static_cast<HANDLE>(hSnapshot) == INVALID_HANDLE_VALUE)
        return -1;

    if (Process32First(hSnapshot, &pe32))
    {
        do
        {
            std::string_view this_proc = pe32.szExeFile;
            if (this_proc.find(process_name) != this_proc.npos && pe32.th32ProcessID != GetCurrentProcessId())
                return pe32.th32ProcessID;
        } while (Process32Next(hSnapshot, &pe32));
    }

    return static_cast<DWORD>(-1);
}

bool HhFindModulesInProcess(HANDLE proc, std::vector<ModuleInformation_t>& modules)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    if (EnumProcessModules(proc, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.
            if (GetModuleFileNameEx(proc, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                MODULEINFO info{};
                GetModuleInformation(proc, hMods[i], &info, sizeof info);

                modules.emplace_back(szModName, (std::uint64_t)hMods[i], info.SizeOfImage);
            }
        }
    }

    return modules.size() > 0;
}

bool HhFindNamedModulesInProcess(HANDLE proc, const std::vector<std::string>& names, std::vector<ModuleInformation_t>& modules)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    unsigned int i;

    if (EnumProcessModules(proc, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.
            if (GetModuleFileNameEx(proc, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                std::string sMod = szModName;
                std::transform(sMod.begin(), sMod.end(), sMod.begin(), ::tolower);

                for (auto const& wanted_name : names)
                {
                    if (sMod.find(wanted_name) != sMod.npos)
                    {
                        MODULEINFO info{};
                        GetModuleInformation(proc, hMods[i], &info, sizeof info);

                        modules.emplace_back(szModName, (std::uint64_t)hMods[i], info.SizeOfImage);
                        break;
                    }
                }
                
            }
        }
    }

    return modules.size() > 0;
}

