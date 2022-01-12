#include "pe.hpp"
#undef max

class PE32::ApplyRelocCallback : public RelocEntryCallback
{
public:
	ApplyRelocCallback(bool is_pe32plus, ULONGLONG old_base, ULONGLONG new_base)
		: RelocEntryCallback(is_pe32plus), old_base(old_base), new_base(new_base)
	{
	}

	void processRelocField(BASE_RELOCATION_ENTRY* entry, ULONG_PTR reloc_field) override
	{
		if (is_pe32plus)
		{
			auto relocate_addr = reinterpret_cast<ULONGLONG*>(reloc_field);
			const ULONGLONG rva = *relocate_addr - old_base;
			*relocate_addr = rva + new_base;
		}
		else
		{
			auto relocate_addr = reinterpret_cast<DWORD*>(reloc_field);
			const ULONGLONG rva = static_cast<ULONGLONG>(*relocate_addr) - old_base;
			*relocate_addr = static_cast<DWORD>(rva + new_base);
		}
	}

protected:
	ULONGLONG old_base;
	ULONGLONG new_base;
};

class PE32::RelocateImportRelatedCallback : public RelocEntryCallback
{
public:
	RelocateImportRelatedCallback(std::shared_ptr<PE32> pe32, DWORD old_rva, DWORD old_size_in_bytes, DWORD new_rva) :
		RelocEntryCallback(static_cast<bool>(std::dynamic_pointer_cast<PE32Plus>(pe32))), pe32(pe32),
		old_rva(old_rva), old_size_in_bytes(old_size_in_bytes), new_rva(new_rva) {}

	void processRelocField(BASE_RELOCATION_ENTRY* entry, ULONG_PTR reloc_field) override = 0;
protected:
	std::shared_ptr<PE32> pe32;
	DWORD old_rva;
	DWORD old_size_in_bytes;
	DWORD new_rva;
};

class PE32::RelocateImportRelatedCallback32 : public RelocateImportRelatedCallback
{
public:
	RelocateImportRelatedCallback32(std::shared_ptr<PE32> pe32, DWORD old_rva, DWORD old_size_in_bytes, DWORD new_rva) :
		RelocateImportRelatedCallback(pe32, old_rva, old_size_in_bytes, new_rva) {}
	void processRelocField(BASE_RELOCATION_ENTRY* entry, ULONG_PTR reloc_field) override
	{
		if (const auto old_reloc = *reinterpret_cast<DWORD*>(reloc_field) - pe32->ImageBase();
			old_reloc >= this->old_rva && old_reloc < this->old_rva + this->old_size_in_bytes)
		{
			const auto new_reloc = this->new_rva + old_reloc - this->old_rva;
			*reinterpret_cast<DWORD*>(reloc_field) = pe32->ImageBase() + new_reloc;
		}
	}

};

class PE32Plus::RelocateImportRelatedCallback64 : public RelocateImportRelatedCallback
{
public:
	RelocateImportRelatedCallback64(std::shared_ptr<PE32Plus> pe32plus, DWORD old_rva, DWORD old_size_in_bytes, DWORD new_rva) :
		RelocateImportRelatedCallback(pe32plus, old_rva, old_size_in_bytes, new_rva), pe32plus(pe32plus) {}
	void processRelocField(BASE_RELOCATION_ENTRY* entry, ULONG_PTR reloc_field) override
	{
		if (const auto old_reloc = *reinterpret_cast<ULONGLONG*>(reloc_field) - pe32->ImageBase();
			old_reloc >= this->old_rva && old_reloc < static_cast<ULONGLONG>(this->old_rva) + this->old_size_in_bytes)
		{
			const auto new_reloc = this->new_rva + old_reloc - this->old_rva;
			*reinterpret_cast<ULONGLONG*>(reloc_field) = pe32plus->ImageBase() + new_reloc;
		}
	}
private:
	std::shared_ptr<PE32Plus> pe32plus;
};

std::shared_ptr<PE32> LoadPE(const std::filesystem::path& filename) noexcept(false)
{
	HANDLE              fd = nullptr;
	HANDLE              mapd = nullptr;
	PBYTE               mem = nullptr;

	try
	{
		fd = CreateFileW(
			filename.native().c_str(),
			GENERIC_READ | GENERIC_WRITE,
			NULL,
			nullptr,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			nullptr);
		if (fd == INVALID_HANDLE_VALUE)
		{
			throw std::exception("Could not open file!");
		}

		const auto filesize = GetFileSize(fd, nullptr);

		mapd = CreateFileMapping(
			fd,
			nullptr,
			PAGE_READWRITE,
			0,
			filesize,
			nullptr);
		if (!mapd)
		{
			throw std::exception("Could not create mapping!");
		}

		// отображаем проекцию в пам€ть
		mem = static_cast<PBYTE>(MapViewOfFile(
			mapd,
			FILE_MAP_ALL_ACCESS,
			NULL,
			NULL,
			NULL));
		if (!mem) {
			throw std::exception("Could not map view of file");
		}

		const auto doshead = reinterpret_cast<IMAGE_DOS_HEADER*>(mem);

		if (doshead->e_magic != IMAGE_DOS_SIGNATURE)
		{
			throw std::exception("Wrong DOS signature!");
		}

		const auto nthead32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<ULONG_PTR>(mem) + doshead->e_lfanew);
		if (nthead32->Signature != IMAGE_NT_SIGNATURE)
		{
			throw std::exception("Wrong NT signature!");
		}
		std::shared_ptr<PE32> pe;
		IMAGE_DATA_DIRECTORY* data_dir;
		if (nthead32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			const auto sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(&nthead32->OptionalHeader) +
				nthead32->FileHeader.SizeOfOptionalHeader);
			data_dir = nthead32->OptionalHeader.DataDirectory;
			pe = std::make_shared<PE32>(PE32(fd, mapd, mem, filesize, doshead, nthead32, sections, data_dir));
		}
		else if (nthead32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			const auto nthead64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(nthead32);
			const auto sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PBYTE>(&nthead64->OptionalHeader) +
				nthead64->FileHeader.SizeOfOptionalHeader);
			data_dir = nthead64->OptionalHeader.DataDirectory;
			pe = std::make_shared<PE32Plus>(PE32Plus(fd, mapd, mem, filesize, doshead, nthead64, sections, data_dir));
		}
		else
		{
			throw std::exception("Unsupportable NT signature!");
		}
		return pe;
	}
	catch (...)
	{
		if (mem)
		{
			UnmapViewOfFile(mem);
		}
		if (mapd)
		{
			CloseHandle(mapd);
		}
		if (fd)
		{
			CloseHandle(fd);
		}
		throw;
	}
}

void UnloadPE(std::shared_ptr<PE32> pe)
{
	if (pe->mem)
	{
		UnmapViewOfFile(pe->mem);
		pe->mem = nullptr;
	}
	if (pe->mapd)
	{
		CloseHandle(pe->mapd);
		pe->mapd = nullptr;
	}
	if (pe->fd)
	{
		CloseHandle(pe->fd);
		pe->fd = nullptr;
	}
}

PE32::PE32(HANDLE fd, HANDLE mapd, PBYTE mem, DWORD filesize, IMAGE_DOS_HEADER* doshead, IMAGE_NT_HEADERS32* nthead,
	IMAGE_SECTION_HEADER* sections, IMAGE_DATA_DIRECTORY* data_dir) :
	nthead(nthead), fd(fd), mapd(mapd), mem(mem), filesize(filesize),
	doshead(doshead), sections(sections), data_dir(data_dir) {}

ULONG_PTR PE32::RVAToOffset(ULONG_PTR rva) const
{

	if (rva > this->SizeOfImage())
	{
		return NULL;
	}
	const IMAGE_SECTION_HEADER* sections = this->sections;
	//проходим по всем секци€м и ищем
	//в какую попадает RVA
	for (WORD i = 0; i < this->NumberOfSections(); ++i)
	{
		if (const auto section_i_va = sections[i].VirtualAddress;
			rva >= section_i_va &&
			rva <= static_cast<ULONG_PTR>(section_i_va) + sections[i].Misc.VirtualSize)
		{
			return rva - section_i_va + sections[i].PointerToRawData;
		}
	}

	return NULL;
}

std::pair<DWORD, DWORD> PE32::ExtendLastSection(DWORD additional_size)
{
	IMAGE_SECTION_HEADER* last_section = this->Sections() + this->NumberOfSections() - 1;

	// ¬ качестве нового размера секции в пам€ти и на диске берЄм максимум из 
	// размеров файла на диске и в пам€ти плюс добавл€емое значение.
	// Ќе всегда будет работать, так как если размер на диске больше размера в пам€ти,
	// то он может иметь любое (большое) значение - будет учитыватьс€ только размер в пам€ти.
	const DWORD offset_to_new_section_data = std::max(last_section->SizeOfRawData, last_section->Misc.VirtualSize);
	DWORD new_virtual_and_file_size = offset_to_new_section_data + additional_size;

	// ¬ыравниваем новый размер по величине выравнивани€ в пам€ти.
	const DWORD alignment = this->SectionAlignment();
	new_virtual_and_file_size = AlignToTop(new_virtual_and_file_size, alignment);

	// на сколько увеличиваетс€ размер файла
	const DWORD deltaFileSize = new_virtual_and_file_size - last_section->SizeOfRawData;

	this->mapd = CreateFileMapping(
		this->fd,
		nullptr,
		PAGE_READWRITE,
		NULL,
		this->filesize += deltaFileSize,
		nullptr);

	this->mem = static_cast<PBYTE>(MapViewOfFile(
		this->mapd,
		FILE_MAP_ALL_ACCESS,
		0,
		0,
		0));

	last_section = this->Sections() + this->NumberOfSections() - 1;

	// обновл€ем размер образа программы (если надо)
	this->SizeOfImage(this->SizeOfImage() + AlignToTop(new_virtual_and_file_size, alignment) - AlignToTop(last_section->Misc.VirtualSize, alignment));

	// обновл€ем размеры секции в файле и в пам€ти
	last_section->SizeOfRawData = new_virtual_and_file_size;
	last_section->Misc.VirtualSize = new_virtual_and_file_size;

	const auto new_data_rva = last_section->VirtualAddress + offset_to_new_section_data;
	const auto new_data_offset = last_section->PointerToRawData + offset_to_new_section_data;

	return std::make_pair(new_data_rva, new_data_offset);
}

DWORD PE32::CreateNewSection(const std::string& new_name = ".custom")
{
	const DWORD raw_size = this->FileAlignment();
	const DWORD virtual_size = this->SectionAlignment();

	this->NumberOfSections(this->NumberOfSections() + 1);
	auto& last_section = this->Sections()[this->NumberOfSections() - 1];
	std::fill_n(last_section.Name, std::size(last_section.Name), NULL);
	std::copy_n(
		new_name.c_str(),
		new_name.size() > std::size(last_section.Name) ? std::size(last_section.Name) : new_name.size(),
		last_section.Name);

	last_section.VirtualAddress = this->CalculateNewVA(virtual_size);
	last_section.SizeOfRawData = raw_size;
	last_section.PointerToRawData = this->CalculateNewRawAddress(raw_size);
	last_section.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

	this->SizeOfImage(RoundUpToNumber(last_section.VirtualAddress + virtual_size, this->SectionAlignment()));

	this->filesize += raw_size;
	this->mapd = CreateFileMapping(
		this->fd,
		nullptr,
		PAGE_READWRITE,
		NULL,
		this->filesize,
		nullptr);
	this->mem = static_cast<decltype(this->mem)>(MapViewOfFile(
		this->mapd,
		FILE_MAP_ALL_ACCESS,
		NULL,
		NULL,
		NULL));

	return raw_size;
}

DWORD PE32::InsertNewString(const std::string& value)
{
	const auto value_size_with_null = static_cast<DWORD>(value.size()) + 1;
	const auto [ext_rva, ext_offset] = this->ExtendLastSection(value_size_with_null);
	std::copy_n(value.c_str(), value_size_with_null, this->mem + ext_offset);
	return ext_rva;
}

DWORD PE32::InsertNewFirstThunkArray()
{
	const auto [rva, offset] = this->ExtendLastSection(sizeof IMAGE_THUNK_DATA32);
	std::fill_n(reinterpret_cast<IMAGE_THUNK_DATA32*>(this->mem + offset), 1, IMAGE_THUNK_DATA32{ NULL });
	return rva;
}

DWORD PE32Plus::InsertNewFirstThunkArray()
{
	const auto [rva, offset] = this->ExtendLastSection(sizeof IMAGE_THUNK_DATA64);
	std::fill_n(reinterpret_cast<IMAGE_THUNK_DATA64*>(this->mem + offset), 1, IMAGE_THUNK_DATA64{ NULL });
	return rva;
}

void PE32::InsertNewOrReplaceString(DWORD& rva, const std::string& value)
{
	if (const auto old_len = std::strlen(reinterpret_cast<char*>(this->GetRawPointer(rva))); value.size() > old_len)
	{
		rva = this->InsertNewString(value);
	}
	else
	{
		std::copy(value.cbegin(), value.cend(), this->GetRawPointer(rva));
	}
}

bool PE32::is_empty_reloc_block(const BASE_RELOCATION_ENTRY* block, SIZE_T entries_num)
{
	if (entries_num == 0)
	{
		return true;
	}
	for (SIZE_T i = 0; i < entries_num; ++i)
	{
		if (block->Type != 0)
		{
			return false; //найден непустой блок
		}
		++block;
	}
	return true;
}

bool PE32::process_reloc_block(BASE_RELOCATION_ENTRY* block, SIZE_T entries_num, DWORD page, std::shared_ptr<RelocEntryCallback> entry_callback)
{
	if (entries_num == 0)
	{
		return true;
	}
	BASE_RELOCATION_ENTRY* entry = block;
	SIZE_T i;
	for (i = 0; i < entries_num; ++i)
	{
		if (entry->Type == 0)
		{
			break;
		}

		/*if (type != RELOC_32BIULONGLONG && type != RELOC_64BIULONGLONG) {
			return false;
		}*/

		const DWORD reloc_field = page + entry->Offset;
		/*if (reloc_field >= this->filesize)
		{
			return false;
		}*/
		if (entry_callback)
		{
			entry_callback->processRelocField(entry, reinterpret_cast<ULONG_PTR>(this->GetRawPointer(reloc_field)));
		}
		++entry;
	}
	return i != 0;
}

bool PE32::ProcessRelocationTable(std::shared_ptr<RelocBlockHeaderCallback> header_callback, std::shared_ptr<RelocEntryCallback> entry_callback)
{
	auto [reloc_addr, max_size] = this->DirectoryEntryBaseReloc();
	if (reloc_addr == nullptr)
	{
		return false;
	}

	decltype(max_size) parsed_size = 0;
	auto valid_blocks = 0;
	while (parsed_size < max_size)
	{
		auto reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<ULONG_PTR>(reloc_addr) + parsed_size);
		if (header_callback)
		{
			header_callback->processRelocHeader(reloc);
		}
		if (reloc->SizeOfBlock == 0)
		{
			break;
		}
		constexpr auto header_size = 2 * sizeof(DWORD);
		const auto entries_num = (reloc->SizeOfBlock - header_size) / sizeof(WORD);
		const auto page = reloc->VirtualAddress;

		if (const auto block = reinterpret_cast<BASE_RELOCATION_ENTRY*>(reinterpret_cast<ULONG_PTR>(reloc) + header_size);
			!is_empty_reloc_block(block, entries_num))
		{
			if (process_reloc_block(block, entries_num, page, entry_callback))
			{
				++valid_blocks;
			}
			else
			{
				return false; // блок плохо сформирован
			}
		}
		parsed_size += reloc->SizeOfBlock;
		if (entry_callback)
		{
			entry_callback->incrementBlockCounter();
		}
	}
	return valid_blocks != 0;
}

bool PE32::process_imp_functions(DWORD call_via, DWORD thunk_addr, std::shared_ptr<ImportThunksCallback> callback)
{
	bool is_ok = true;

	auto thunks = reinterpret_cast<DWORD*>(this->GetRawPointer(thunk_addr));
	auto callers = reinterpret_cast<DWORD*>(this->GetRawPointer(call_via));

	for (size_t index = 0; true; ++index)
	{
		if (!this->validate_ptr(&callers[index], sizeof(DWORD)) ||
			!this->validate_ptr(&thunks[index], sizeof(DWORD)))
		{
			break;
		}
		if (callers[index] == 0)
		{
			return true;
		}
		const LPVOID thunk_ptr = &thunks[index];
		const auto desc = static_cast<IMAGE_THUNK_DATA32*>(thunk_ptr);
		if (!this->validate_ptr(desc, sizeof(IMAGE_THUNK_DATA32)))
		{
			break;
		}
		if (desc->u1.Function == NULL)
		{
			break;
		}

		if (const bool is_by_ord = IMAGE_SNAP_BY_ORDINAL32(desc->u1.Ordinal); !is_by_ord)
		{
			const auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(this->GetRawPointer(desc->u1.AddressOfData));
			if (!this->validate_ptr(by_name, sizeof(IMAGE_IMPORT_BY_NAME)))
			{
				break;
			}
		}

		if (callback && !callback->processThunks(
			reinterpret_cast<ULONG_PTR>(thunk_ptr),
			reinterpret_cast<ULONG_PTR>(&callers[index])))
		{
			is_ok = false;
		}
	}
	return is_ok;
}

bool PE32Plus::process_imp_functions(DWORD call_via, DWORD thunk_addr, std::shared_ptr<ImportThunksCallback> callback)
{
	bool is_ok = true;

	auto thunks = reinterpret_cast<ULONGLONG*>(this->GetRawPointer(thunk_addr));
	auto callers = reinterpret_cast<ULONGLONG*>(this->GetRawPointer(call_via));

	for (size_t index = 0; true; ++index) {
		if (!this->validate_ptr(&callers[index], sizeof(ULONGLONG)) ||
			!this->validate_ptr(&thunks[index], sizeof(ULONGLONG)))
		{
			break;
		}
		if (callers[index] == 0)
		{
			return true; //nothing to fill, probably the last record
		}
		const LPVOID thunk_ptr = &thunks[index];
		const auto desc = static_cast<IMAGE_THUNK_DATA64*>(thunk_ptr);
		if (!this->validate_ptr(desc, sizeof(IMAGE_THUNK_DATA64)))
		{
			break;
		}
		if (desc->u1.Function == NULL)
		{
			break;
		}

		if (const bool is_by_ord = IMAGE_SNAP_BY_ORDINAL64(desc->u1.Ordinal); !is_by_ord)
		{
			const auto by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(this->GetRawPointer(desc->u1.AddressOfData));
			if (!this->validate_ptr(by_name, sizeof(IMAGE_IMPORT_BY_NAME)))
			{
				break;
			}
		}

		if (callback && !callback->processThunks(
			reinterpret_cast<ULONG_PTR>(thunk_ptr),
			reinterpret_cast<ULONG_PTR>(&callers[index])))
		{
			is_ok = false;
		}
	}
	return is_ok;
}

bool PE32::ProcessImportTable(std::shared_ptr<ImportDescriptorCallback> desc_callback, std::shared_ptr<ImportThunksCallback> thunks_callback)
{
	IMAGE_IMPORT_DESCRIPTOR* first_desc = this->DirectoryEntryImport();
	if (!first_desc)
	{
		return true; //нет таблицы импорта
	}

	bool isAllFilled = true;

	for (size_t i = 0; true; ++i) {
		IMAGE_IMPORT_DESCRIPTOR* lib_desc = &first_desc[i];
		if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL)
		{
			break;
		}
		if (desc_callback)
		{
			desc_callback->processDescriptor(lib_desc);
		}
		const auto lib_name = reinterpret_cast<LPSTR>(this->GetRawPointer(lib_desc->Name));
		/*if (!is_valid_import_name(lib_name))
		{
			return false;
		}*/
		const DWORD call_via = lib_desc->FirstThunk;
		DWORD thunk_addr = lib_desc->OriginalFirstThunk;
		if (thunk_addr == NULL)
		{
			thunk_addr = lib_desc->FirstThunk;
		}

		if (const std::size_t all_solved = this->process_imp_functions(call_via, thunk_addr, thunks_callback); !all_solved)
		{
			isAllFilled = false;
		}

		if (thunks_callback)
		{
			thunks_callback->incrementDescCounter();
		}
	}

	return isAllFilled;
}

void PE32::Relocate(ULONGLONG new_base)
{
	const auto callback = std::make_shared<ApplyRelocCallback>(ApplyRelocCallback(false, this->ImageBase(), new_base));
	this->ProcessRelocationTable(nullptr, callback);
}

void PE32Plus::Relocate(ULONGLONG new_base)
{
	const auto callback = std::make_shared<ApplyRelocCallback>(ApplyRelocCallback(true, this->ImageBase(), new_base));
	this->ProcessRelocationTable(nullptr, callback);
}

void PE32::AddRelocBlock(const IMAGE_BASE_RELOCATION& block)
{
	auto& reloc = this->data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	const DWORD new_reloc_table_size = reloc.Size + sizeof block;
	const auto [new_rva, new_offset] = this->ExtendLastSection(new_reloc_table_size);
	std::copy_n(this->GetRawPointer(reloc.VirtualAddress), reloc.Size, this->mem + new_offset);
	*reinterpret_cast<IMAGE_BASE_RELOCATION*>(this->mem + new_offset + reloc.Size) = block;
	reloc.VirtualAddress = new_rva;
	reloc.Size = new_reloc_table_size;
}

void PE32::InsertRelocEntry(std::size_t block_num, const BASE_RELOCATION_ENTRY& entry)
{
	auto& [rva, size] = this->DataDirectory()[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	std::size_t size_before_needed_block = 0, size_with_needed_block = 0;
	class CountBlockSizes : public RelocBlockHeaderCallback
	{
	public:
		CountBlockSizes(std::size_t block_num, std::size_t& size_before_needed_block, std::size_t& size_with_needed_block) :
			block_num(block_num), size_before_needed_block(size_before_needed_block), size_with_needed_block(size_with_needed_block) {}
		void processRelocHeader(IMAGE_BASE_RELOCATION* reloc) override
		{
			if (this->current_block < block_num)
			{
				size_before_needed_block += reloc->SizeOfBlock;
				size_with_needed_block += reloc->SizeOfBlock;
			}
			if (this->current_block == block_num)
			{
				size_with_needed_block += reloc->SizeOfBlock;
			}
			++current_block;
		}
	private:
		std::size_t current_block = 0;
		std::size_t block_num;
		std::size_t& size_before_needed_block;
		std::size_t& size_with_needed_block;
	};
	const std::shared_ptr<RelocBlockHeaderCallback> callback = std::make_shared<CountBlockSizes>(block_num,
		size_before_needed_block, size_with_needed_block);
	this->ProcessRelocationTable(callback, nullptr);
	const auto new_size = size + sizeof entry;
	const auto [new_rva, new_offset] = this->ExtendLastSection(static_cast<DWORD>(new_size));
	const auto old_relocs = reinterpret_cast<IMAGE_BASE_RELOCATION*>(this->GetRawPointer(rva));
	const auto new_relocs = reinterpret_cast<IMAGE_BASE_RELOCATION*>(this->mem + new_offset);
	std::copy_n(reinterpret_cast<BYTE*>(old_relocs), size_with_needed_block, reinterpret_cast<BYTE*>(new_relocs));
	const auto new_entry = reinterpret_cast<BASE_RELOCATION_ENTRY*>(reinterpret_cast<BYTE*>(new_relocs) + size_with_needed_block);
	*new_entry = entry;
	const auto block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(new_relocs) + size_before_needed_block);
	block->SizeOfBlock += sizeof entry;
	std::copy_n(
		reinterpret_cast<BYTE*>(old_relocs) + size_with_needed_block,
		size - size_with_needed_block,
		reinterpret_cast<BYTE*>(new_relocs) + size_with_needed_block + sizeof entry);
	rva = new_rva;
	size = static_cast<decltype(size)>(new_size);
}

std::shared_ptr<RelocEntryCallback> PE32::RelocateImportDirectoryRelated(DWORD new_import_rva)
{
	const auto [rva, size] = this->DataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT];
	return std::make_shared<RelocateImportRelatedCallback32>(this->shared_from_this(), rva, size, new_import_rva);
}

std::shared_ptr<RelocEntryCallback> PE32Plus::RelocateImportDirectoryRelated(DWORD new_import_rva)
{
	const auto [rva, size] = this->DataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT];
	return std::make_shared<RelocateImportRelatedCallback64>(
		std::static_pointer_cast<PE32Plus>(this->shared_from_this()), rva, size, new_import_rva);
}

std::shared_ptr<RelocEntryCallback> PE32::RelocateImportThunkRelated(
	DWORD old_orig_first_thunk,
	DWORD size_of_thunks_data,
	DWORD new_orig_first_thunk_rva)
{
	return std::make_shared<RelocateImportRelatedCallback32>(
		this->shared_from_this(), old_orig_first_thunk, size_of_thunks_data, new_orig_first_thunk_rva);
}

std::shared_ptr<RelocEntryCallback> PE32Plus::RelocateImportThunkRelated(
	DWORD old_orig_first_thunk,
	DWORD size_of_thunks_data,
	DWORD new_orig_first_thunk_rva)
{
	return std::make_shared<RelocateImportRelatedCallback64>(
		std::static_pointer_cast<PE32Plus>(this->shared_from_this()),
		old_orig_first_thunk, size_of_thunks_data, new_orig_first_thunk_rva);
}

void PE32::AddImportDesc(const IMAGE_IMPORT_DESCRIPTOR& desc)
{
	auto& [rva, size] = this->DataDirectory()[IMAGE_DIRECTORY_ENTRY_IMPORT];
	const auto old_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(this->GetRawPointer(rva));
	const auto new_size = size + sizeof desc;
	auto [new_rva, new_offset] = this->ExtendLastSection(static_cast<DWORD>(new_size));
	auto new_table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(this->mem + new_offset);
	const auto desc_count = size / sizeof IMAGE_IMPORT_DESCRIPTOR;
	if (desc_count > 1)
	{
		std::copy_n(old_table, desc_count - 1, new_table);
	}
	new_table += desc_count - 1;
	*new_table++ = desc;
	*new_table = IMAGE_IMPORT_DESCRIPTOR{ NULL, NULL, NULL, NULL, NULL };
	this->ProcessRelocationTable(nullptr, this->RelocateImportDirectoryRelated(new_rva));
	rva = new_rva;
	size = static_cast<decltype(size)>(new_size);
}

void PE32::AddImportFunction(std::size_t lib_num, const std::string& name)
{
	class GetFirstThunksVA : public ImportDescriptorCallback
	{
	public:
		GetFirstThunksVA(std::size_t desc_num, DWORD& orig_first_thunk, DWORD& first_thunk)
			: desc_num(desc_num), orig_first_thunk(orig_first_thunk), first_thunk(first_thunk) {}

		bool processDescriptor(IMAGE_IMPORT_DESCRIPTOR* desc) override
		{
			if (this->current_desc == this->desc_num)
			{
				orig_first_thunk = desc->OriginalFirstThunk;
				first_thunk = desc->FirstThunk;
			}
			++this->current_desc;
			return true;
		}
	private:
		std::size_t desc_num;
		std::size_t current_desc = 0;
		DWORD& orig_first_thunk;
		DWORD& first_thunk;
	};

	class CountImportFunctions : public ImportThunksCallback
	{
	public:
		CountImportFunctions(std::size_t desc_num, std::size_t& func_count) :
			desc_num(desc_num), func_count(func_count) {}

		bool processThunks(ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) override
		{
			if (this->desc_num == this->current_desc)
			{
				++func_count;
			}
			return true;
		}
	protected:
		std::size_t desc_num;
		std::size_t& func_count;
	};

	std::size_t func_count = 0;
	DWORD old_orig_first_thunk_rva;
	DWORD old_first_thunk_rva;
	const auto desc_callback = std::make_shared<GetFirstThunksVA>(lib_num, old_orig_first_thunk_rva, old_first_thunk_rva);
	const auto func_callback = std::make_shared<CountImportFunctions>(lib_num, func_count);
	this->ProcessImportTable(desc_callback, func_callback);

	const auto size_of_image_thunk_data = dynamic_cast<PE32Plus*>(this) ? sizeof IMAGE_THUNK_DATA64 : sizeof IMAGE_THUNK_DATA32;
	const auto sizeof_old_thunks = func_count * size_of_image_thunk_data;
	const auto sizeof_new_thunks = (func_count + 2) * size_of_image_thunk_data;
	auto [rva, offset] = this->ExtendLastSection(
		static_cast<DWORD>(sizeof std::declval<IMAGE_IMPORT_BY_NAME>().Hint + name.size() + 1 + 2 * sizeof_new_thunks));

	const auto import_by_name_raw = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(this->mem + offset);
	std::copy_n(name.c_str(), name.size() + 1, import_by_name_raw->Name);
	const auto import_by_name_rva = rva;

	const DWORD new_orig_first_thunk_rva = static_cast<DWORD>(import_by_name_rva + sizeof std::declval<
		IMAGE_IMPORT_BY_NAME>().Hint + name.size() + 1);
	const DWORD new_first_thunk_rva = static_cast<DWORD>(new_orig_first_thunk_rva + sizeof_new_thunks);

	const auto new_orig_first_thunk_raw = reinterpret_cast<BYTE*>(import_by_name_raw) + sizeof std::declval<
		IMAGE_IMPORT_BY_NAME>().Hint + name.size() + 1;
	const auto new_first_thunk_raw = new_orig_first_thunk_raw + sizeof_new_thunks;

	for (auto [old_rva, new_raw_data] :
		{
			std::make_pair(old_orig_first_thunk_rva, new_orig_first_thunk_raw),
			std::make_pair(old_first_thunk_rva, new_first_thunk_raw)
		})
	{
		std::copy_n(this->GetRawPointer(old_rva), sizeof_old_thunks, new_raw_data);

		const auto new_thunk_data = static_cast<const ULONG_PTR>(import_by_name_rva);
		const auto raw_new_thunk = new_raw_data + sizeof_old_thunks;
		std::copy_n(reinterpret_cast<BYTE const*>(&new_thunk_data), size_of_image_thunk_data, raw_new_thunk);

		const auto raw_last_thunk = raw_new_thunk + size_of_image_thunk_data;
		std::fill_n(raw_last_thunk, size_of_image_thunk_data, '\0');
	}

	for (auto [old_thunk_rva, new_thunk_rva] :
		{
			std::make_pair(old_orig_first_thunk_rva, new_orig_first_thunk_rva),
			std::make_pair(old_first_thunk_rva, new_first_thunk_rva)
		})
	{
		const std::shared_ptr<RelocEntryCallback> callback = this->RelocateImportThunkRelated(
			old_thunk_rva, sizeof_old_thunks, new_thunk_rva);
		this->ProcessRelocationTable(nullptr, callback);
	}

	class UpdateImportDescriptorValues : public ImportDescriptorCallback
	{
	public:
		UpdateImportDescriptorValues(std::size_t desc_index, DWORD new_orig_first_thunk, DWORD new_first_thunk) :
			ImportDescriptorCallback(), desc_index(desc_index), new_orig_first_thunk(new_orig_first_thunk), new_first_thunk(new_first_thunk) { }

		bool processDescriptor(IMAGE_IMPORT_DESCRIPTOR* desc) override
		{
			if (current_desc == desc_index)
			{
				desc->OriginalFirstThunk = new_orig_first_thunk;
				desc->FirstThunk = new_first_thunk;
			}
			++current_desc;
			return true;
		}
	private:
		std::size_t current_desc = 0;
		const std::size_t desc_index;
		const DWORD new_orig_first_thunk;
		const DWORD new_first_thunk;
	};
	const auto update_import_desc_callback = std::make_shared<UpdateImportDescriptorValues>(
		lib_num, new_orig_first_thunk_rva, new_first_thunk_rva);
	this->ProcessImportTable(update_import_desc_callback, nullptr);

	//TODO: мен€ть права на секцию автоматически
}