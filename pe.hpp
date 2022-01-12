#pragma once
#include <filesystem>
#include <windows.h>

template<typename T>
T AlignToTop(T value, T align)
{
	T mask = ~(align - 1);
	return value + align - 1 & mask;
}

template<typename T>
T RoundUpToNumber(T value, T border)
{
	T num = value + (border - 1);
	return num - num % border;
}

class PE32;
class PE32Plus;

std::shared_ptr<PE32> LoadPE(const std::filesystem::path& filename);
void UnloadPE(std::shared_ptr<PE32> pe);

template<typename T>
void InsertNewOrReplaceImportName(std::shared_ptr<PE32>, T& rva, const std::string& value);

class RelocBlockHeaderCallback
{
public:
	virtual ~RelocBlockHeaderCallback() = default;
	RelocBlockHeaderCallback() {}
	virtual void processRelocHeader(IMAGE_BASE_RELOCATION* reloc) = 0;
};

struct BASE_RELOCATION_ENTRY
{
	WORD Offset : 12;
	WORD Type : 4;
};

class RelocEntryCallback
{
public:
	virtual ~RelocEntryCallback() = default;

	RelocEntryCallback(bool is_pe32plus)
		: is_pe32plus(is_pe32plus)
	{
	}

	virtual void processRelocField(BASE_RELOCATION_ENTRY* entry, ULONG_PTR reloc_field) = 0;

	virtual void incrementBlockCounter()
	{
		++this->current_block;
	}

protected:
	bool is_pe32plus;
	std::size_t current_block = 0;
};

class ImportDescriptorCallback
{
public:
	virtual ~ImportDescriptorCallback() = default;
	ImportDescriptorCallback() {}

	virtual bool processDescriptor(IMAGE_IMPORT_DESCRIPTOR* desc) = 0;
};

class ImportThunksCallback
{
public:
	virtual ~ImportThunksCallback() = default;
	ImportThunksCallback() {}

	virtual bool processThunks(ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) = 0;

	virtual void incrementDescCounter()
	{
		++this->current_desc;
	}

protected:
	std::size_t current_desc = 0;
};

class PE32: public std::enable_shared_from_this<PE32>
{
public:

	friend std::shared_ptr<PE32> LoadPE(const std::filesystem::path& filename);
	friend void UnloadPE(std::shared_ptr<PE32> pe);
	template<typename T>
	friend void InsertNewOrReplaceImportName(std::shared_ptr<PE32> pe, T& rva, const std::string& value);

	auto Signature() const
	{
		return this->doshead->e_magic;
	}

	auto NumberOfSections() const
	{
		return this->nthead->FileHeader.NumberOfSections;
	}

	auto TimeDateStamp() const
	{
		return this->nthead->FileHeader.TimeDateStamp;
	}

	auto SizeOfOptionalHeader() const
	{
		return this->nthead->FileHeader.SizeOfOptionalHeader;
	}

	auto Characteristics() const
	{
		return this->nthead->FileHeader.Characteristics;
	}

	auto Magic() const
	{
		return this->nthead->OptionalHeader.Magic;
	}

	auto AddressEntryPoint() const
	{
		return this->nthead->OptionalHeader.AddressOfEntryPoint;
	}

	auto ImageBase() const
	{
		return this->nthead->OptionalHeader.ImageBase;
	}

	auto Sections()
	{
		return this->sections;
	}

	auto DataDirectory()
	{
		return this->data_dir;
	}

	auto GetRawPointer(ULONG_PTR rva = 0)
	{
		return this->mem + this->RVAToOffset(rva);
	}

	std::pair<IMAGE_BASE_RELOCATION*, DWORD> DirectoryEntryBaseReloc()
	{
		const auto [VirtualAddress, Size] = data_dir[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (VirtualAddress)
		{
			return std::make_pair(reinterpret_cast<IMAGE_BASE_RELOCATION*>(this->GetRawPointer(VirtualAddress)), Size);
		}
		return std::make_pair(nullptr, Size);
	}

	IMAGE_EXPORT_DIRECTORY* DirectoryEntryExport()
	{
		if (const auto [VirtualAddress, Size] = data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT]; VirtualAddress)
		{
			return reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(this->GetRawPointer(VirtualAddress));
		}
		return nullptr;
	}

	IMAGE_IMPORT_DESCRIPTOR* DirectoryEntryImport()
	{
		if (const auto [VirtualAddress, Size] = data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT]; VirtualAddress)
		{
			return reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(this->GetRawPointer(VirtualAddress));
		}
		return nullptr;
	}

	auto ExportName()
	{
		return reinterpret_cast<const char*>(this->GetRawPointer(DirectoryEntryExport()->Name));
	}

	virtual DWORD SectionAlignment() const
	{
		return this->nthead->OptionalHeader.SectionAlignment;
	}

	virtual DWORD FileAlignment() const
	{
		return this->nthead->OptionalHeader.FileAlignment;
	}

	virtual DWORD SizeOfImage() const
	{
		return this->nthead->OptionalHeader.SizeOfImage;
	}

	virtual DWORD SizeOfHeaders() const
	{
		return this->nthead->OptionalHeader.SizeOfHeaders;
	}

	virtual WORD Subsystem() const
	{
		return this->nthead->OptionalHeader.Subsystem;
	}

	virtual DWORD NumberOfRvaAndSizes() const
	{
		return this->nthead->OptionalHeader.NumberOfRvaAndSizes;
	}

	//

	void Signature(WORD value)
	{
		this->doshead->e_magic = value;
	}

	void NumberOfSections(WORD value)
	{
		this->nthead->FileHeader.NumberOfSections = value;
	}

	void TimeDateStamp(DWORD value)
	{
		this->nthead->FileHeader.TimeDateStamp = value;
	}

	void SizeOfOptionalHeader(WORD value)
	{
		this->nthead->FileHeader.SizeOfOptionalHeader = value;
	}

	void Characteristics(WORD value)
	{
		this->nthead->FileHeader.Characteristics = value;
	}

	void Magic(WORD value)
	{
		this->nthead->OptionalHeader.Magic = value;
	}

	void AddressEntryPoint(DWORD value)
	{
		this->nthead->OptionalHeader.AddressOfEntryPoint = value;
	}

	void ImageBase(DWORD value)
	{
		this->Relocate(value);
		this->nthead->OptionalHeader.ImageBase = value;
	}

	virtual void SectionAlignment(DWORD value)
	{
		this->nthead->OptionalHeader.SectionAlignment = value;
	}

	virtual void FileAlignment(DWORD value)
	{
		this->nthead->OptionalHeader.FileAlignment = value;
	}

	virtual void SizeOfImage(DWORD value)
	{
		this->nthead->OptionalHeader.SizeOfImage = AlignToTop(value, this->nthead->OptionalHeader.SectionAlignment);
	}

	virtual void SizeOfHeaders(DWORD value)
	{
		this->nthead->OptionalHeader.SizeOfHeaders = value;
	}

	virtual void Subsystem(WORD value)
	{
		this->nthead->OptionalHeader.Subsystem = value;
	}

	virtual void NumberOfRvaAndSizes(DWORD value)
	{
		this->nthead->OptionalHeader.NumberOfRvaAndSizes = value;
	}


	void InsertNewOrReplaceString(DWORD& rva, const std::string& value);

	bool ProcessRelocationTable(std::shared_ptr<RelocBlockHeaderCallback> header_callback, std::shared_ptr<RelocEntryCallback> entry_callback);

	bool ProcessImportTable(std::shared_ptr<ImportDescriptorCallback> desc_callback, std::shared_ptr<ImportThunksCallback> thunks_callback);

	virtual void Relocate(ULONGLONG new_base);

	void AddRelocBlock(const IMAGE_BASE_RELOCATION& block);

	void InsertRelocEntry(std::size_t block_num, const BASE_RELOCATION_ENTRY& entry);

	void AddImportDesc(const IMAGE_IMPORT_DESCRIPTOR& desc);

	DWORD InsertNewString(const std::string& value);

	static bool is_valid_import_name(LPCSTR lib_name)
	{
		for (; *lib_name; ++lib_name)
		{
			if (const char next_char = *lib_name; next_char <= 0x20 || next_char >= 0x7E)
			{
				return false;
			}
		}
		return true;
	}

	virtual DWORD InsertNewFirstThunkArray();

	void AddImportFunction(std::size_t lib_num, const std::string& name);

private:
	IMAGE_NT_HEADERS32* nthead;        // указатель на NT заголовок
	class RelocateImportRelatedCallback32;
protected:
	friend ImportDescriptorCallback;
	friend ImportThunksCallback;

	PE32(
		HANDLE fd,
		HANDLE mapd,
		PBYTE mem,
		DWORD filesize,
		IMAGE_DOS_HEADER* doshead,
		IMAGE_NT_HEADERS32* nthead,
		IMAGE_SECTION_HEADER* sections,
		IMAGE_DATA_DIRECTORY* data_dir);

	DWORD CalculateNewVA(DWORD border)
	{
		if (this->NumberOfSections() > 2)
		{
			const auto& section = this->Sections()[this->NumberOfSections() - 2];
			return RoundUpToNumber(section.VirtualAddress + section.Misc.VirtualSize, border);
		}

		return RoundUpToNumber(static_cast<DWORD>(0), border);
	}

	DWORD CalculateNewRawAddress(DWORD border)
	{
		if (this->NumberOfSections() > 2)
		{
			const auto& section = this->Sections()[this->NumberOfSections() - 2];
			return RoundUpToNumber(section.PointerToRawData + section.SizeOfRawData, border);
		}

		return RoundUpToNumber(static_cast<DWORD>(0), border);
	}

	bool validate_ptr(const void* const field_bgn, SIZE_T field_size) const
	{
		if (field_bgn == nullptr)
		{
			return false;
		}
		const auto start = static_cast<const BYTE* const>(this->mem);
		const auto end = start + this->filesize;

		const auto field_start = static_cast<const BYTE* const>(field_bgn);
		const auto field_end = field_start + field_size;

		if (field_start < start || field_end > end)
		{
			return false;
		}
		return true;
	}

	class ApplyRelocCallback;

	virtual bool process_imp_functions(DWORD call_via, DWORD thunk_addr, std::shared_ptr<ImportThunksCallback> callback);

	static bool is_empty_reloc_block(const BASE_RELOCATION_ENTRY* block, SIZE_T entries_num);
	bool process_reloc_block(BASE_RELOCATION_ENTRY* block, SIZE_T entries_num, DWORD page,
		std::shared_ptr<RelocEntryCallback> entry_callback);
	class RelocateImportRelatedCallback;
	virtual std::shared_ptr<RelocEntryCallback> RelocateImportDirectoryRelated(DWORD new_import_rva);
	virtual std::shared_ptr<RelocEntryCallback> RelocateImportThunkRelated(
		DWORD old_orig_first_thunk,
		DWORD size_of_thunks_data,
		DWORD new_orig_first_thunk_rva);
	HANDLE              fd;             // хендл открытого файла
	HANDLE              mapd;           // хендл файловой проекции
	PBYTE               mem;            // указатель на память спроецированного файла
	DWORD               filesize;       // размер спроецированной части файла

	IMAGE_DOS_HEADER* doshead;       // указатель на DOS заголовок

	IMAGE_SECTION_HEADER* sections;  // указатель на таблицу секций (на первый элемент)

	IMAGE_DATA_DIRECTORY* data_dir;

	ULONG_PTR RVAToOffset(ULONG_PTR rva) const;

	std::pair<DWORD, DWORD> ExtendLastSection(DWORD additional_size);
	DWORD CreateNewSection(const std::string& new_name);
};

class PE32Plus final : public PE32
{
public:

	friend std::shared_ptr<PE32> LoadPE(const std::filesystem::path& filename);
	friend void UnloadPE(std::shared_ptr<PE32> pe);
	template<typename T>
	friend void InsertNewOrReplaceImportName(std::shared_ptr<PE32> pe, T& rva, const std::string& value);

	DWORD SectionAlignment() const override
	{
		return this->nthead->OptionalHeader.SectionAlignment;
	}

	DWORD FileAlignment() const override
	{
		return this->nthead->OptionalHeader.FileAlignment;
	}

	DWORD SizeOfImage() const override
	{
		return this->nthead->OptionalHeader.SizeOfImage;
	}

	DWORD SizeOfHeaders() const override
	{
		return this->nthead->OptionalHeader.SizeOfHeaders;
	}

	WORD Subsystem() const override
	{
		return this->nthead->OptionalHeader.Subsystem;
	}

	DWORD NumberOfRvaAndSizes() const override
	{
		return this->nthead->OptionalHeader.NumberOfRvaAndSizes;
	}

	auto ImageBase() const
	{
		return this->nthead->OptionalHeader.ImageBase;
	}

	void ImageBase(ULONGLONG value)
	{
		this->Relocate(value);
		this->nthead->OptionalHeader.ImageBase = value;
	}

	void SectionAlignment(DWORD value) override
	{
		this->nthead->OptionalHeader.SectionAlignment = value;
	}

	void FileAlignment(DWORD value) override
	{
		this->nthead->OptionalHeader.FileAlignment = value;
	}

	void SizeOfImage(DWORD value) override
	{
		this->nthead->OptionalHeader.SizeOfImage = AlignToTop(value, this->nthead->OptionalHeader.SectionAlignment);
	}

	void SizeOfHeaders(DWORD value) override
	{
		this->nthead->OptionalHeader.SizeOfHeaders = value;
	}

	void Subsystem(WORD value) override
	{
		this->nthead->OptionalHeader.Subsystem = value;
	}

	void NumberOfRvaAndSizes(DWORD value) override
	{
		this->nthead->OptionalHeader.NumberOfRvaAndSizes = value;
	}

	void Relocate(ULONGLONG new_base) override;

	DWORD InsertNewFirstThunkArray() override;

private:
	friend ImportDescriptorCallback;
	friend ImportThunksCallback;

	class RelocateImportRelatedCallback64;

	PE32Plus(
		HANDLE fd,
		HANDLE mapd,
		PBYTE mem,
		DWORD filesize,
		IMAGE_DOS_HEADER* doshead,
		IMAGE_NT_HEADERS64* nthead,
		IMAGE_SECTION_HEADER* sections,
		IMAGE_DATA_DIRECTORY* data_dir) :
		PE32(fd, mapd, mem, filesize, doshead, reinterpret_cast<IMAGE_NT_HEADERS32*>(nthead), sections, data_dir),
		nthead(nthead) {}

	IMAGE_NT_HEADERS64* nthead;        // указатель на NT заголовок

	bool process_imp_functions(DWORD call_via, DWORD thunk_addr, std::shared_ptr<ImportThunksCallback> callback) override;
	std::shared_ptr<RelocEntryCallback> RelocateImportDirectoryRelated(DWORD new_import_rva) override;
	std::shared_ptr<RelocEntryCallback> RelocateImportThunkRelated(
		DWORD old_orig_first_thunk,
		DWORD size_of_thunks_data,
		DWORD new_orig_first_thunk_rva) override;
};

template<typename T>
void InsertNewOrReplaceImportName(std::shared_ptr<PE32> pe, T& rva, const std::string& value)
{
	const auto by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pe->GetRawPointer(rva));
	if (const auto old_name = std::string(by_name->Name); value != old_name)
	{
		if (value.size() > old_name.size())
		{
			const auto value_size_with_null = static_cast<DWORD>(value.size()) + 1;
			const auto [ext_rva, ext_offset] = pe->ExtendLastSection(
				sizeof std::declval<IMAGE_IMPORT_BY_NAME>().Hint + value_size_with_null);
			const auto hint = reinterpret_cast<WORD*>(pe->mem + ext_offset);
			*hint = by_name->Hint;
			const auto name = reinterpret_cast<CHAR*>(hint) + sizeof std::declval<IMAGE_IMPORT_BY_NAME>().Hint;
			std::copy_n(value.c_str(), value_size_with_null, name);

			rva = ext_rva;
		}
		else
		{
			std::copy(value.cbegin(), value.cend(), by_name->Name);
		}
	}
}