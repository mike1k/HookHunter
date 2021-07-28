#pragma once

#include <Windows.h>
#include <psapi.h>
#include <string>
#include <string_view>
#include <map>
#include <vector>
#include <TlHelp32.h>
#include <algorithm>
#include <memory>
#include <inttypes.h>
#include <filesystem>
#pragma comment(lib, "psapi.lib")

//! PE parsing and manipulation
#include "msc/Address.hpp"
#include "msc/Process.hpp"
#include "msc/ScopedHandle.hpp"
#include <pepp/PELibrary.hpp>

//! Include Zydis disassembler
#include <zydis/include/Zydis/Zydis.h>
#include <zycore/include/Zycore/Format.h>
#include <zycore/include/Zycore/LibC.h>

//! Include spdlog
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/stopwatch.h>
#include <spdlog/fmt/bin_to_hex.h>

//! Include HookHunter files
#include "HhUtil.hpp"

#ifdef _WIN64
using Image_t = pepp::Image64;
#else
using Image_t = pepp::Image86;
#endif

//
// HookHunter configuration
struct HookHunterConfig
{
	std::uint32_t				ProcessId;
	std::vector<std::string>	ModuleList;
	std::string					IntegrityCheckPE;
	bool						DumpModules;
	bool						Heal;
	bool						Verbose;
};

class HookHunter
{
	struct JmpInfo_t
	{
		std::uintptr_t dst_ptr;
		std::uintptr_t dst_rva;
		std::string	   dst_module;
	};

public:
	struct Mismatch_t
	{
		std::uintptr_t			runtime_address;
		std::uintptr_t			file_address;
		std::string				export_name;
		std::vector<uint8_t>	orig_bytes;
		std::vector<uint8_t>	patch_bytes;
		std::vector<JmpInfo_t>	jmps;
	};


	HookHunter() noexcept;
	HookHunter(const HookHunter& hh) = delete;
	~HookHunter() = default;

	//! Begin scan
	void BeginScanning();
	//! Parse results, and print
	void Publish();

private:
	void DissassembleBuffer(std::uintptr_t runtime_address, ZyanU8* data, ZyanUSize length, std::string& buffer, std::vector<JmpInfo_t>* jmps = nullptr);
	bool GetModuleFromAddress(std::uintptr_t ptr, ModuleInformation_t* mod);
private:
	ZydisDecoder							m_decoder;
	hh::nt::Process		m_process;
	std::map<std::string, std::vector<Mismatch_t>>	m_mismatches;
	std::vector<ModuleInformation_t> m_moduleList;
};

inline std::shared_ptr<spdlog::logger> g_log;
inline HookHunterConfig				   cfg{};
inline std::unique_ptr<HookHunter>	   hookhunter;