#pragma once

#include "Address.hpp"
#include "ScopedHandle.hpp"
#include <pepp/misc/NonCopyable.hpp>

namespace hh::nt
{
	//! Currently limited to same architecture processes
	class Process : pepp::msc::NonCopyable
	{
	public:
		Process() = default;
		Process(std::uint32_t processId) noexcept;


		//! Create a handle to the process
		//! - returns true or false depending OpenProcess status
		bool CreateHandle(std::uint32_t flags) noexcept; 
		bool CreateHandle(std::uint32_t processId, std::uint32_t flags) noexcept;


		//! Read memory
		bool ReadMemory(Address<> address, void* buffer, std::size_t size) noexcept;

		//! Write memory
		bool WriteMemory(Address<> address, void* buffer, std::size_t size) noexcept;

		//! Get handle pointer
		HANDLE handle() noexcept { return m_handle.handle(); }

	private:
		std::uint16_t			m_processId = 0;
		hh::nt::ScopedHandle	m_handle;
	};
}