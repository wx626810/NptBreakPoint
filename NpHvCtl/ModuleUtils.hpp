#include "stdafx.h"
#include "str_enc.h"



#include <winternl.h>
#include "sf/nt.h"
namespace ModuleUtil {
	bool GetKernelModuleAddress(const char* moduleName, std::uint64_t& moduleBase, ULONG& moduleSize)
	{
		moduleBase = 0;
		moduleSize = 0;

		HMODULE ntdll = GetModuleHandleW(WSX(L"ntdll.dll").c_str());
		if (!ntdll)
		{
			ntdll = LoadLibraryW(WSX(L"ntdll.dll").c_str());
			if (!ntdll)
				return false;
		}

		const auto querySystemInformation = reinterpret_cast<NtQuerySystemInformationProc>(
			GetProcAddress(ntdll, SX("NtQuerySystemInformation").c_str()));
		if (!querySystemInformation)
			return false;

		ULONG bufferSize = 0;
		querySystemInformation(kSystemModuleInformation, nullptr, 0, &bufferSize);
		if (bufferSize == 0)
			return false;

		std::vector<std::uint8_t> buffer(bufferSize);
		if (querySystemInformation(kSystemModuleInformation, buffer.data(), bufferSize, &bufferSize) != 0)
			return false;

		const auto modules = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer.data());
		for (ULONG i = 0; i < modules->NumberOfModules; ++i)
		{
			const auto& module = modules->Modules[i];
			const char* name = reinterpret_cast<const char*>(&module.FullPathName[module.OffsetToFileName]);
			if (_stricmp(name, moduleName) == 0)
			{
				moduleBase = reinterpret_cast<std::uint64_t>(module.ImageBase);
				moduleSize = module.ImageSize;
				return true;
			}
		}

		return false;
	}






}