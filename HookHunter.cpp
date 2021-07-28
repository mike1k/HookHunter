#include "HookHunter.hpp"
 

#ifdef _WIN64
static constexpr auto REGISTER_IP = ZYDIS_REGISTER_RIP;
#else
static constexpr auto REGISTER_IP = ZYDIS_REGISTER_EIP;
#endif

HookHunter::HookHunter() noexcept
{
#if defined (_WIN64)
	ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#else
	ZydisDecoderInit(&m_decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_ADDRESS_WIDTH_32);
#endif
}

void HookHunter::BeginScanning()
{
	if (!m_process.CreateHandle(cfg.ProcessId, PROCESS_ALL_ACCESS))
	{
		g_log->critical("Unable to open a handle to process {}", cfg.ProcessId);
		return;
	}

	g_log->info("Attached to process {}", cfg.ProcessId);


	//
	// Process all DLLs if none were explicitly defined
	if (cfg.ModuleList.empty())
	{
		if (!HhFindModulesInProcess(m_process.handle(), m_moduleList))
		{
			g_log->critical("Unable to enumerate process' modules");
			return;
		}
	}
	else
	{
		g_log->info("Using custom module list.");

		if (!HhFindNamedModulesInProcess(m_process.handle(), cfg.ModuleList, m_moduleList))
		{
			g_log->critical("Unable to enumerate process' modules");
			return;
		}
	}

	if (m_moduleList.empty())
	{
		g_log->critical("Module list was empty..");
		return;
	}


	for (auto const& mod : m_moduleList)
	{
		hh::Address _moduleAddress = mod.base_address;
		std::size_t _lastSize = 0;
		std::unique_ptr<std::uint8_t> _moduleBuffer(new std::uint8_t[mod.module_size]{});
		std::string _moduleName = (std::filesystem::path(mod.module_path).filename().string());
		MEMORY_BASIC_INFORMATION mbi{};
		int _numMismatches = 0;

		//
		// Loop through the module's memory and insert into the buffer.
		while (VirtualQueryEx(m_process.handle(), (_moduleAddress + _lastSize).as_ptr<void>(), &mbi, sizeof mbi))
		{
			if (m_process.ReadMemory(mbi.BaseAddress, &_moduleBuffer.get()[_lastSize], mbi.RegionSize))
				; // logger->info("Read memory at {} with size {}", mbi.BaseAddress, mbi.RegionSize);
			else
				// Log the faliure, but that is all. We will still try to parse.
				g_log->critical("Unable to read memory at {:X}", (std::uintptr_t)mbi.BaseAddress);

			_lastSize += mbi.RegionSize;

			if (_lastSize >= mod.module_size)
				break;
		}

		Image_t _imgMap { Image_t::FromRuntimeMemory(_moduleBuffer.get(), mod.module_size) };

		if (_imgMap.magic() == IMAGE_DOS_SIGNATURE && _imgMap.GetExportDirectory().IsPresent())
		{
			if (cfg.Verbose)
				g_log->info("Beginning scan of module {} @ 0x{:X}", _moduleName, mod.base_address);

			Image_t _imgFile(mod.module_path);
			if (_imgFile.magic() != IMAGE_DOS_SIGNATURE)
			{
				if (cfg.Verbose)
					g_log->critical("Unable to parse file image {}, skipping.", mod.module_path);
				continue;
			}

			int _numEntries = 0;

			_imgMap.GetExportDirectory().TraverseExports(
				[&](pepp::ExportData_t* exp)
				{
					std::uint32_t _fileOffset = _imgFile.GetPEHeader().RvaToOffset(exp->rva);
					std::uint32_t _mappedOffset = exp->rva;
					pepp::mem::ByteVector _origBytes, _patchBytes;


					//
					// For now, skip non-executable regions
					if (!(_imgMap.GetSectionHeaderFromOffset(_mappedOffset).GetCharacteristics() & pepp::SCN_MEM_EXECUTE))
						return;

					ZydisDecodedInstruction _fInsn{};
					ZydisDecodedInstruction _mInsn{};
					int						_curFileOffset{}, 
											_curMemOffset{};
					std::vector<JmpInfo_t>	jmp{};
					JmpInfo_t				_jmpInfo{};


					//
					// Fetch both file and memory instructions
					while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, &_imgFile.buffer()[_fileOffset + _curFileOffset], 0x40, &_fInsn)) &&
						   ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, &_imgMap.buffer()[_mappedOffset + _curMemOffset], 0x40, &_mInsn)))
					{
						//
						// Instruction by instruction, compare if they're the same.
						if (memcmp(&_imgFile.buffer()[_fileOffset + _curMemOffset],
							&_imgMap.buffer()[_mappedOffset + _curMemOffset],
							_fInsn.length) == 0)
						{
							//
							// Equal instructions, jump out.
							break;
						}

#ifndef _WIN64
						if (_fInsn.opcode == _mInsn.opcode && _mInsn.mnemonic != ZYDIS_MNEMONIC_JMP)
							break;
#endif
						//
						// Chain JMPs
						if (_mInsn.mnemonic == ZYDIS_MNEMONIC_JMP)
						{
							ZydisDecodedInstruction tmp_instr{};
							ZyanU64 ptr = (mod.base_address + _mappedOffset + _curMemOffset);
							ModuleInformation_t _tmp{};

							//
							// Follow.
							if (_mInsn.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
							{
								if (_mInsn.operands[0].imm.is_relative)
									ZydisCalcAbsoluteAddress(&_mInsn, &_mInsn.operands[0], (mod.base_address + _mappedOffset + _curMemOffset), &ptr);
								else
									ptr = _mInsn.operands[0].imm.value.u;
							}
							else if (_mInsn.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
							{
								if (_mInsn.operands[0].mem.disp.has_displacement)
									ptr = _mInsn.operands[0].mem.disp.value;
							}

							//
							// Possible that a hook won't lead to a legitimate module, and maybe just some allocated executable
							// memory.
							if (GetModuleFromAddress(ptr, &_tmp)) 
							{
								_jmpInfo.dst_ptr = ptr;
								_jmpInfo.dst_rva = (ptr - _tmp.base_address);
								_jmpInfo.dst_module = std::filesystem::path(_tmp.module_path).filename().string();
							}
							else
							{
								MEMORY_BASIC_INFORMATION _tmpMbi{};
								if (VirtualQueryEx(m_process.handle(), (void*)ptr, &_tmpMbi, sizeof(_tmpMbi)))
								{
									_jmpInfo.dst_rva = ptr - (std::uintptr_t)_tmpMbi.AllocationBase;
									_jmpInfo.dst_module = fmt::format("memory@{:X}", 
										(std::uintptr_t)_tmpMbi.AllocationBase);
									_jmpInfo.dst_ptr = ptr;
								}
							}


#ifndef _WIN64
							//
							// On X86, we'll need to ignore JMPs that had relocations processed on them.
							// This check isn't exactly the best way but it is convenient and good enough for this purpose.
							if (_fInsn.opcode == 0xff && ptr > 0)
							{
								ZyanU64 _fptr = _imgFile.buffer().deref<uint32_t>(_fileOffset + _curFileOffset + 2);
								
								//
								// Translate to an RVA
								_fptr -= _imgFile.GetPEHeader().GetOptionalHeader().GetImageBase();

								//
								// Leads to the same place, false positive!
								if (_fptr == _jmpInfo.dst_rva)
								{					
									break;
								}
							}
#endif


							//
							// Append a JMP
							jmp.emplace_back(std::move(_jmpInfo));

							//
							// This is really ugly and bad, but it was added last minute as a method to follow JMPs
							// I will come back and fix it when I have time.
							bool tmp_val = true;
							uint8_t tmp_buf[0x20];

							while (tmp_val)
							{
								if (m_process.ReadMemory(ptr, tmp_buf, sizeof tmp_buf))
								{
									while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, tmp_buf, 0x20, &tmp_instr)))
									{
										if (tmp_instr.mnemonic == ZYDIS_MNEMONIC_JMP)
										{
											switch (tmp_instr.operands[0].type)
											{
											case ZYDIS_OPERAND_TYPE_IMMEDIATE:
											{
												if (tmp_instr.operands[0].imm.is_relative)
													ZydisCalcAbsoluteAddress(&tmp_instr,
														&tmp_instr.operands[0], ptr, &ptr);
												else
													ptr = tmp_instr.operands[0].imm.value.u;

												if (GetModuleFromAddress(ptr, &_tmp))
												{
													_jmpInfo.dst_ptr = ptr;
													_jmpInfo.dst_rva = (ptr - _tmp.base_address);
													_jmpInfo.dst_module = std::filesystem::path(_tmp.module_path).filename().string();
												}
												else
												{
													MEMORY_BASIC_INFORMATION _tmpMbi{};
													if (VirtualQueryEx(m_process.handle(), (void*)ptr, &_tmpMbi, sizeof(_tmpMbi)))
													{
														_jmpInfo.dst_rva = ptr - (std::uintptr_t)_tmpMbi.AllocationBase;
														_jmpInfo.dst_module = fmt::format("memory@{:X}",
															(std::uintptr_t)_tmpMbi.AllocationBase);
														_jmpInfo.dst_ptr = ptr;
													}
												}

												jmp.emplace_back(std::move(_jmpInfo));
												_patchBytes.push_raw(tmp_buf, tmp_instr.length);
												break;
											}
											case ZYDIS_OPERAND_TYPE_MEMORY:
											{
												//
												// This will only be used on X64 usually.
												if (tmp_instr.operands[0].mem.base == REGISTER_IP)
												{
													ptr += tmp_instr.length;

													//
													// Read the JMP destination.
													m_process.ReadMemory(ptr, &ptr, sizeof(ptr));

													if (GetModuleFromAddress(ptr, &_tmp))
													{
														_jmpInfo.dst_ptr = ptr;
														_jmpInfo.dst_rva = (ptr - _tmp.base_address);
														_jmpInfo.dst_module = std::filesystem::path(_tmp.module_path).filename().string();
													}
													else
													{
														MEMORY_BASIC_INFORMATION _tmpMbi{};
														if (VirtualQueryEx(m_process.handle(), (void*)ptr, &_tmpMbi, sizeof(_tmpMbi)))
														{
															_jmpInfo.dst_rva = ptr - (std::uintptr_t)_tmpMbi.AllocationBase;
															_jmpInfo.dst_module = fmt::format("memory@{:X}",
																(std::uintptr_t)_tmpMbi.AllocationBase);
															_jmpInfo.dst_ptr = ptr;
														}
													}

													jmp.emplace_back(std::move(_jmpInfo));
													_patchBytes.push_raw(tmp_buf, tmp_instr.length);
												}
												break;
											}
											default:
												tmp_val = false;
												break;
											}
										}
										else
										{
											tmp_val = false;
										}

										break;
									}
								}
								else
								{
									tmp_val = false;
								}
							}
						}


						//
						// Mismatch, add them into the stream.
						_origBytes.push_raw(&_imgFile.buffer()[_fileOffset + _curFileOffset], _fInsn.length);
						_patchBytes.push_raw(&_imgMap.buffer()[_mappedOffset + _curMemOffset], _mInsn.length);

						//
						// See notes regarding "Heal" @ Main.cpp
//#ifdef _WIN64
						if (cfg.Heal)
						{
							//
							// Write back the file's bytes into the process (this currently won't take into account many things, so this option
							// should be used with care.
							m_process.WriteMemory(mod.base_address + _mappedOffset + _curMemOffset, &_imgFile.buffer()[_fileOffset + _curFileOffset], _fInsn.length);
						
							if (cfg.Verbose)
							{
								g_log->debug("* Healing memory @ <{}+0x{:X}> (0x{:X})", _moduleName, _mappedOffset + _curMemOffset, mod.base_address + _mappedOffset + _curMemOffset);
							}
						}
//#endif

						_curFileOffset += _fInsn.length;
						_curMemOffset  += _mInsn.length;
					}

					//while (mappedImg.buffer()[mapped_offset] != fileImg.buffer()[file_offset])
					//{
					//	origBytes.push_back(fileImg.buffer()[file_offset++]);
					//	patchBytes.push_back(mappedImg.buffer()[mapped_offset++]);
					//}

					if (!_origBytes.empty())
					{
						m_mismatches[_moduleName].emplace_back(
							mod.base_address + exp->rva, 
							_imgFile.GetPEHeader().GetOptionalHeader().GetImageBase() + exp->rva,
							std::move(exp->name), 
							std::move(_origBytes),
							std::move(_patchBytes),
							std::move(jmp));
						++_numMismatches;

						if (cfg.DumpModules)
						{
							g_log->debug("Dumping entry {}", _moduleName);

							_imgFile.WriteToFile(fmt::format("{}-unpatched.bin", _moduleName));
							_imgMap.WriteToFile(fmt::format("{}-patched.bin", _moduleName));
						}
					}

					++_numEntries;
				}
			);

			if (cfg.Verbose)
				g_log->info("Finished scan of module {}, found {} mismatches from {} entries.", _moduleName, _numMismatches, _numEntries);
		}
	}
}

void HookHunter::Publish()
{
	static auto spdlog_SetPublishFormat = []() [[msvc::forceinline]]
	{
		auto fmter = std::make_unique<spdlog::pattern_formatter>("%^*** %v%$", spdlog::pattern_time_type::local, std::string(""));
		g_log->set_formatter(std::move(fmter));
	};

	static auto spdlog_SetDefaultFormat = []() [[msvc::forceinline]]
	{
		auto fmter = std::make_unique<spdlog::pattern_formatter>("[%^%L%$] %v", spdlog::pattern_time_type::local, std::string("\r\n"));
		g_log->set_formatter(std::move(fmter));
	};

	if (m_mismatches.empty())
		return;

	g_log->info("Publishing {} entries", m_mismatches.size());

	spdlog_SetPublishFormat();
	

	for (auto it = m_mismatches.begin(); it != m_mismatches.end(); ++it)
	{
		for (auto& mm : it->second)
		{
			std::string unpatched_disasm;
			DissassembleBuffer(mm.file_address, mm.orig_bytes.data(), mm.orig_bytes.size(), unpatched_disasm);
			std::string patched_disasm;
			DissassembleBuffer(mm.runtime_address, mm.patch_bytes.data(), mm.patch_bytes.size(), patched_disasm, &mm.jmps);

			g_log->warn("[M{:X}/F{:X}] Mismatch detected @ {}!{}\r\n",
				mm.runtime_address, mm.file_address, it->first, mm.export_name);
			g_log->info("[[FILE]]\r\n");
			g_log->debug(unpatched_disasm);
			g_log->info("[[MEMORY]]\r\n");
			g_log->error(patched_disasm);
		}
	}

	if (!cfg.IntegrityCheckPE.empty())
	{
		g_log->debug("Parsing imports of PE file: {}\n", cfg.IntegrityCheckPE);

		//
		// Will improve later..
		Image_t integrityFile{ cfg.IntegrityCheckPE };
		if (integrityFile.magic() == IMAGE_DOS_SIGNATURE)
		{
			int nAlerts = 0;

			integrityFile.GetImportDirectory().TraverseImports([&](pepp::ModuleImportData_t* imp)
			{
				//
				// Will fix later.. 
				if (imp->ordinal)
					return;

				std::string& sMod = imp->module_name;
				std::transform(sMod.begin(), sMod.end(), sMod.begin(), ::tolower);

				auto mit = m_mismatches.find(sMod);
				if (mit != m_mismatches.end())
				{
					for (auto& mismatch : mit->second)
					{
						if (mismatch.export_name == std::get<std::string>(imp->import_variant))
						{
							g_log->critical("File uses modified procedure: {}!{}\n", sMod, std::get<std::string>(imp->import_variant));
							++nAlerts;
						}
					}
				}
			});

			nAlerts == 0 ? 
				g_log->debug("No imports found to be hooked (be wary that this scan does not included forwarded imports e.g LoadLibrary->LdrLoadDll).") :
				g_log->error("Found {} imports that are hooked in the target process.", nAlerts);
		}
		else
		{
			g_log->error("Unable to open file.. skipped integrity check.\n");
		}
	}
	

	spdlog_SetDefaultFormat();
}

void HookHunter::DissassembleBuffer(std::uintptr_t runtime_address, ZyanU8* data, ZyanUSize length, std::string& buffer, std::vector<JmpInfo_t>* jmps)
{
	static auto MakeByteString = [](uint8_t* p, ZyanUSize len) -> std::string
	{
		std::stringstream ss;
		ss << std::hex;

		 for (int i(0); i < len; ++i)
			 ss << std::setw(2) << std::setfill('0') << (int)p[i] << ' ';

		 return ss.str();
	};

	ZydisFormatter formatter;
	ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
	ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);

	ZydisDecodedInstruction instruction;
	char tmp[256];

	int nJumpsProcessed{};
	bool bHasJumps = jmps && !jmps->empty();

	//
	// Not a fan of this either, but didn't really care to make it better.
	while (ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&m_decoder, data, length, &instruction)))
	{
		ZydisFormatterFormatInstruction(&formatter, &instruction, &tmp[0], sizeof(tmp), runtime_address);

		if (bHasJumps)
		{
			if (nJumpsProcessed == 0)
			{
#ifdef _WIN64
				buffer.append(fmt::format("{:016X} ", (std::uintptr_t)runtime_address));
#else
				buffer.append(fmt::format("{:08X} ", (std::uintptr_t)runtime_address));
#endif
			}
			else
			{
#ifdef _WIN64
				buffer.append(fmt::format("{:<16} ", "FOLLOWED"));
#else
				buffer.append(fmt::format("{:<8} ", "FOLLOWED"));
#endif
			}
		}
		else
		{
#ifdef _WIN64
			buffer.append(fmt::format("{:016X} ", (std::uintptr_t)runtime_address));
#else
			buffer.append(fmt::format("{:08X} ", (std::uintptr_t)runtime_address));
#endif
		}

		buffer.append(fmt::format("{:<32}", MakeByteString(data, instruction.length)));
		buffer.append(tmp);

		if (jmps && !jmps->empty() && jmps->front().dst_ptr != 0)
		{
			buffer.append(fmt::format(" ; jmp <{}+{:X}>", jmps->front().dst_module, jmps->front().dst_rva));
			jmps->erase(jmps->begin());
			++nJumpsProcessed;
		}

		if (length - instruction.length > 0)
			buffer.append("\n*** ");
		else
			buffer.push_back('\n');

		data += instruction.length;
		length -= instruction.length;
		runtime_address += instruction.length;
	}
}

bool HookHunter::GetModuleFromAddress(std::uintptr_t ptr, ModuleInformation_t* pmod)
{
	if (m_moduleList.empty())
		return false;

	for (auto& mod : m_moduleList)
	{
		if (ptr >= mod.base_address && ptr <= mod.base_address + mod.module_size)
		{
			*pmod = mod;
			return true;
		}
	}

	return false;
}