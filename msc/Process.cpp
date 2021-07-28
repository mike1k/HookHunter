#include <Windows.h>
#include "Process.hpp"

using namespace hh::nt;

Process::Process(std::uint32_t processId) noexcept
	: m_processId(processId)
{
}

bool Process::CreateHandle(std::uint32_t flags) noexcept
{
	m_handle = OpenProcess(flags, FALSE, m_processId);
	return m_handle != INVALID_HANDLE_VALUE;
}

bool Process::CreateHandle(std::uint32_t processId, std::uint32_t flags) noexcept
{
	m_processId = processId;
	m_handle = OpenProcess(flags, FALSE, m_processId);
	return m_handle != INVALID_HANDLE_VALUE;
}

bool Process::ReadMemory(Address<> address, void* buffer, std::size_t size) noexcept
{
	if (m_handle == INVALID_HANDLE_VALUE)
		return false;

	return static_cast<bool>(ReadProcessMemory(m_handle, address.as_ptr<void>(), buffer, size, nullptr));
}

bool Process::WriteMemory(Address<> address, void* buffer, std::size_t size) noexcept
{
	if (m_handle == INVALID_HANDLE_VALUE)
		return false;

	return static_cast<bool>(WriteProcessMemory(m_handle, address.as_ptr<void>(), buffer, size, nullptr));
}