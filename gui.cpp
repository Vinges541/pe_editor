#include <vector>
#include <variant>

#include "pe.hpp"
#include "util.hpp"
#include "gui.hpp"

#include <iostream>
#include <nana/gui/msgbox.hpp>
#include <nana/gui/widgets/button.hpp>
#include <nana/gui/widgets/group.hpp>
#include <nana/gui/widgets/label.hpp>

using namespace nana;

listbox::oresolver& operator<<(listbox::oresolver& orr, const IMAGE_SECTION_HEADER& section)
{
	orr << to_string(section.Name);
	orr << to_string_hex(section.VirtualAddress);
	orr << to_string_hex(section.SizeOfRawData);
	orr << to_string_hex(section.PointerToRawData);
	orr << to_string_hex(section.PointerToRelocations);
	orr << to_string_hex(section.PointerToLinenumbers);
	orr << to_string_hex(section.NumberOfRelocations);
	orr << to_string_hex(section.NumberOfLinenumbers);
	orr << to_string_hex(section.Characteristics);
	orr << to_string_hex(section.Misc.PhysicalAddress);
	return orr;
}

listbox::oresolver& operator<<(listbox::oresolver& orr, const IMAGE_DATA_DIRECTORY& entry)
{
	return orr << to_string_hex(entry.VirtualAddress) << to_string_hex(entry.Size);
}

listbox::oresolver& operator<<(listbox::oresolver& orr, const IMAGE_BASE_RELOCATION& header)
{
	return orr << to_string_hex(header.VirtualAddress) << to_string_hex(header.SizeOfBlock);
}

listbox::iresolver& operator>>(listbox::iresolver& irr, IMAGE_BASE_RELOCATION& header)
{
	std::string buf;
	irr >> buf;
	header.VirtualAddress = to_integer<decltype(header.VirtualAddress)>(buf);
	irr >> buf;
	header.SizeOfBlock = to_integer<decltype(header.SizeOfBlock)>(buf);
	return irr;
}

listbox::oresolver& operator<<(listbox::oresolver& orr, const BASE_RELOCATION_ENTRY& header)
{
	orr << to_string_hex(header.Type);
	orr << to_string_hex(header.Offset);
	return orr;
}

bool section_properties_verifier(
	window handle,
	inputbox::text& name,
	inputbox::text& virtual_address,
	inputbox::text& size_of_raw_data,
	inputbox::text& ptr_to_raw_data,
	inputbox::text& ptr_to_reloc,
	inputbox::text& ptr_to_linenumbers,
	inputbox::text& num_of_relocs,
	inputbox::text& num_of_linenumbers,
	inputbox::text& characteristics,
	inputbox::text& phys_addr_virt_size)
{
	if (name.value().size() > IMAGE_SIZEOF_SHORT_NAME)
	{
		msgbox mb(handle, "Invalid input");
		mb << "Name is longer than IMAGE_SIZEOF_SHORT_NAME (" << IMAGE_SIZEOF_SHORT_NAME << " bytes)";
		mb.show();
		return false;
	}
	for (const auto& [property_name, itext] :
		std::vector<std::pair<const char*, inputbox::text&>>{
			{"VirtualAddress", virtual_address},
			{"SizeOfRawData", size_of_raw_data},
			{"PointerToRawData", ptr_to_raw_data},
			{"PointerToRelocations", ptr_to_reloc},
			{"PointerToLinenumbers", ptr_to_linenumbers},
			{"Characteristics", characteristics},
			{"PhysicalAddress/VirtualSize", phys_addr_virt_size}
		})
	{
		using T = DWORD;
		if (!is_valid_hex_value<T>(itext.value()))
		{
			msgbox mb(handle, "Invalid input");
			mb << property_name << " is invalid. Must be as hex and " << sizeof T << " bytes";
			mb.show();
			return false;
		}
	}
	for (const auto& [property_name, itext] :
		std::vector<std::pair<const char*, inputbox::text&>>{
			{"NumberOfRelocations", num_of_relocs},
			{"NumberOfLinenumbers", num_of_linenumbers}
		})
	{
		using T = WORD;
		if (!is_valid_hex_value<T>(itext.value()))
		{
			msgbox mb(handle, "Invalid input");
			mb << property_name << " is invalid. Must be as hex and " << sizeof T << " bytes";
			mb.show();
			return false;
		}
	}
	return true;
}

void change_section_properties(const arg_listbox& arg, form& fm, std::mutex& mtx_selected, std::shared_ptr<PE32> pe32)
{
	const std::unique_lock lock(mtx_selected, std::try_to_lock);
	if (!lock)
	{
		return;
	}
	arg.item.select(false);

	const auto item = arg.item.pos().item;
	auto& section = pe32->Sections()[item];
	inputbox::text name{ "Name", to_string(section.Name) };
	inputbox::text virtual_address{ "VirtualAddress", to_string_hex(section.VirtualAddress) };
	inputbox::text size_of_raw_data{ "SizeOfRawData", to_string_hex(section.SizeOfRawData) };
	inputbox::text ptr_to_raw_data{ "PointerToRawData", to_string_hex(section.PointerToRawData) };
	inputbox::text ptr_to_reloc{ "PointerToRelocations", to_string_hex(section.PointerToRelocations) };
	inputbox::text ptr_to_linenumbers{ "PointerToLinenumbers", to_string_hex(section.PointerToLinenumbers) };
	inputbox::text num_of_relocs{ "NumberOfRelocations", to_string_hex(section.NumberOfRelocations) };
	inputbox::text num_of_linenumbers{ "NumberOfLinenumbers", to_string_hex(section.NumberOfLinenumbers) };
	inputbox::text characteristics{ "Characteristics", to_string_hex(section.Characteristics) };
	inputbox::text phys_addr_virt_size{ "PhysicalAddress/VirtualSize", to_string_hex(section.Misc.PhysicalAddress) };

	inputbox inbox{ fm, "Properties of Section", "Section " + std::to_string(item) };

	inbox.verify(std::bind(section_properties_verifier, std::placeholders::_1,
		std::ref(name), std::ref(virtual_address), std::ref(size_of_raw_data), std::ref(ptr_to_raw_data), std::ref(ptr_to_reloc),
		std::ref(ptr_to_linenumbers), std::ref(num_of_relocs), std::ref(num_of_linenumbers), std::ref(characteristics),
		std::ref(phys_addr_virt_size)));

	if (inbox.show(name, virtual_address, size_of_raw_data, ptr_to_raw_data, ptr_to_reloc,
		ptr_to_linenumbers, num_of_relocs, num_of_linenumbers, characteristics, phys_addr_virt_size))
	{
		std::copy_n(name.value().c_str(), IMAGE_SIZEOF_SHORT_NAME, section.Name);
		section.VirtualAddress = to_integer<decltype(section.VirtualAddress)>(virtual_address.value());
		section.SizeOfRawData = to_integer<decltype(section.SizeOfRawData)>(size_of_raw_data.value());
		section.PointerToRawData = to_integer<decltype(section.PointerToRawData)>(ptr_to_raw_data.value());
		section.PointerToRelocations = to_integer<decltype(section.PointerToRelocations)>(ptr_to_reloc.value());
		section.PointerToLinenumbers = to_integer<decltype(section.PointerToLinenumbers)>(ptr_to_linenumbers.value());
		section.NumberOfRelocations = to_integer<decltype(section.NumberOfRelocations)>(num_of_relocs.value());
		section.NumberOfLinenumbers = to_integer<decltype(section.NumberOfLinenumbers)>(num_of_linenumbers.value());
		section.Characteristics = to_integer<decltype(section.Characteristics)>(characteristics.value());
		section.Misc.PhysicalAddress = to_integer<decltype(section.Misc.PhysicalAddress)>(phys_addr_virt_size.value());
		arg.item.resolve_from(section);
	}

}

void show_sections(form& main_form, std::shared_ptr<PE32> pe32)
{
	form fm{ main_form, size{1050, 600} };
	listbox lbox{ fm };

	lbox.sortable(false);
	lbox.checkable(false);
	lbox.column_movable(false);
	lbox.column_resizable(true);
	lbox.enable_single(true, false);
	for (const auto property_name : {
		"Name" , "VirtualAddress", "SizeOfRawData", "PointerToRawData", "PointerToRelocations",
		"PointerLineNumbers", "NumberOfRelocations", "NumberOfLinenumbers", "Characteristics", "PhysicalAddress/VirtualSize"
		})
	{
		lbox.append_header(property_name, 0);
	}

	for (WORD i = 0; i < pe32->NumberOfSections(); ++i)
	{
		lbox.at(0).append(pe32->Sections()[i]);
	}

	lbox.column_at(0).fit_content();

	std::mutex mtx_selected;
	lbox.events().selected(std::bind(change_section_properties, std::placeholders::_1, std::ref(fm), std::ref(mtx_selected), pe32));

	fm.div("<lbox>");
	fm["lbox"] << lbox;
	fm.collocate();
	fm.show();
	fm.modality();
}

bool data_directory_properties_verifier(window handle, inputbox::text& virtual_address, inputbox::text& size)
{
	for (const auto& [property_name, itext] :
		std::vector<std::pair<const char*, inputbox::text&>>{
			{"VirtualAddress", virtual_address},
			{"Size", size},
		})
	{
		using T = DWORD;
		if (!is_valid_hex_value<T>(itext.value()))
		{
			msgbox mb(handle, "Invalid input");
			mb << property_name << " is invalid. Must be as hex and " << sizeof T << " bytes";
			mb.show();
			return false;
		}
	}
	return true;
}

void change_data_directory_properties(const arg_listbox& arg, form& fm, std::mutex& mtx_selected, std::shared_ptr<PE32> pe32)
{
	const std::unique_lock lock(mtx_selected, std::try_to_lock);
	if (!lock)
	{
		return;
	}
	arg.item.select(false);

	const auto item = arg.item.pos().item;
	auto& data_directory_entry = pe32->DataDirectory()[item];
	inputbox::text virtual_address{ "VirtualAddress", to_string_hex(data_directory_entry.VirtualAddress) };
	inputbox::text size{ "SizeOfRawData", to_string_hex(data_directory_entry.Size) };

	inputbox inbox{ fm, "Properties of Data Directory", "Data Directory " + std::to_string(item) };

	inbox.verify(std::bind(data_directory_properties_verifier,
		std::placeholders::_1, std::ref(virtual_address), std::ref(size)));

	if (inbox.show(virtual_address, size))
	{
		data_directory_entry.VirtualAddress = to_integer<decltype(data_directory_entry.VirtualAddress)>(virtual_address.value());
		data_directory_entry.Size = to_integer<decltype(data_directory_entry.Size)>(size.value());
		arg.item.resolve_from(data_directory_entry);
	}

}

void show_data_directories(form& main_form, std::shared_ptr<PE32> pe32)
{
	form fm{ main_form, size{350, 400} };
	listbox lbox{ fm };

	lbox.sortable(false);
	lbox.checkable(false);
	lbox.column_movable(false);
	lbox.column_resizable(true);
	lbox.enable_single(true, false);
	for (const auto property_name : { "Address" , "Size" })
	{
		lbox.append_header(property_name, 0);
	}

	for (WORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
	{
		lbox.at(0).append(pe32->DataDirectory()[i]);
	}

	lbox.column_at(0).fit_content();

	std::mutex mtx_selected;
	lbox.events().selected(std::bind(change_data_directory_properties,
		std::placeholders::_1, std::ref(fm), std::ref(mtx_selected), pe32));

	fm.div("<lbox>");
	fm["lbox"] << lbox;
	fm.collocate();
	fm.show();
	fm.modality();
}

bool reloc_block_header_verifier(window handle, inputbox::text& virtual_address, inputbox::text& size_of_block)
{
	for (const auto& [property_name, itext] :
		std::vector<std::pair<const char*, inputbox::text&>>{
			{"VirtualAddress", virtual_address},
			{"SizeOfBlock", size_of_block}
		})
	{
		using T = DWORD;
		if (!is_valid_hex_value<T>(itext.value()))
		{
			msgbox mb(handle, "Invalid input");
			mb << property_name << " is invalid. Must be as hex and " << sizeof T << " bytes";
			mb.show();
			return false;
		}
	}
	return true;
}

void change_reloc_header_values(form& fm, listbox::item_proxy item, std::shared_ptr<PE32> pe32)
{
	inputbox::text virtual_address{ "VirtualAddress", item.text(0) };
	inputbox::text size_of_block{ "SizeOfBlock", item.text(1) };

	inputbox inbox{ fm, "Block Header Values", "Block Header" };
	inbox.verify(std::bind(reloc_block_header_verifier,
		std::placeholders::_1, std::ref(virtual_address), std::ref(size_of_block)));

	if (inbox.show(virtual_address, size_of_block))
	{
		const IMAGE_BASE_RELOCATION new_header{
			to_integer<decltype(std::declval<IMAGE_BASE_RELOCATION>().VirtualAddress)>(
				virtual_address.value()),
			to_integer<decltype(std::declval<IMAGE_BASE_RELOCATION>().SizeOfBlock)>(
				size_of_block.value())
		};

		class ChangeHeaderValuesCallback : public RelocBlockHeaderCallback
		{
		public:
			ChangeHeaderValuesCallback(std::size_t block_num,
				const IMAGE_BASE_RELOCATION& new_header) :
				block_num(block_num), new_header(new_header)
			{
			}

			void processRelocHeader(IMAGE_BASE_RELOCATION* reloc) override
			{
				if (current_block == block_num)
				{
					*reloc = new_header;
				}
				++current_block;
			}

		private:
			std::size_t current_block = 0;
			std::size_t block_num;
			const IMAGE_BASE_RELOCATION& new_header;
		};

		const auto change_header_values_callback = std::make_shared<ChangeHeaderValuesCallback>(
			item.pos().item, new_header);
		pe32->ProcessRelocationTable(change_header_values_callback, nullptr);
		item.resolve_from(new_header);
	}
}

bool reloc_entry_verifier(window handle, inputbox::text& type, inputbox::text& offset)
{
	using T = WORD;
	for (const auto& [property_name, itext,
		bits_count, mask] :
		std::vector<std::tuple<const char*, inputbox::text&, std::size_t, WORD>>{
			{"Type", type, 4, static_cast<WORD>(~0xF)},
			{"Offset", offset, 12, static_cast<WORD>(~0xFFF)}
		})
	{
		if (!is_valid_hex_value<T>(itext.value()) || (to_integer<T>(itext.value()) & mask) != 0)
		{
			msgbox mb(handle, "Invalid input");
			mb << property_name << " is invalid. Must be as hex and " << bits_count << " bits";
			mb.show();
			return false;
		}
	}
	if (to_integer<T>(type.value()) == NULL)
	{
		msgbox mb(handle, "Invalid input");
		mb << "Type is invalid. Must not be NULL";
		mb.show();
		return false;
	}
	return true;
}

void change_reloc_entry(
	const arg_listbox& arg, form& fm,
	std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus,
	listbox::size_type block_num, std::mutex& mtx_selected_nested)
{
	const std::unique_lock lock(mtx_selected_nested, std::try_to_lock);
	if (!lock)
	{
		return;
	}
	arg.item.select(false);

	inputbox::text type{ "Type", arg.item.text(0) };
	inputbox::text offset{ "Offset", arg.item.text(1) };

	inputbox inbox{ fm, "Entry Values", "Entry " + std::to_string(arg.item.pos().item) };
	inbox.verify(std::bind(reloc_entry_verifier, std::placeholders::_1, std::ref(type), std::ref(offset)));

	if (inbox.show(type, offset))
	{
		const BASE_RELOCATION_ENTRY new_entry{
			to_integer<decltype(std::declval<BASE_RELOCATION_ENTRY>().Offset)>(
				offset.value()),
			to_integer<decltype(std::declval<BASE_RELOCATION_ENTRY>().Type)>(
				type.value())
		};

		class ChangeEntryValuesCallback : public RelocEntryCallback
		{
		public:
			ChangeEntryValuesCallback(
				bool is_pe32plus,
				std::size_t block_num,
				std::size_t entry_num,
				const BASE_RELOCATION_ENTRY& new_entry) : RelocEntryCallback(is_pe32plus),
				block_num(block_num), entry_num(entry_num), new_entry(new_entry)
			{
			}

			void processRelocField(BASE_RELOCATION_ENTRY* entry, ULONG_PTR reloc_field) override
			{
				if (this->current_block == this->block_num && this->current_entry == this->entry_num)
				{
					*entry = new_entry;
				}
				++current_entry;
			}

			void incrementBlockCounter() override
			{
				++current_block;
				current_entry = 0;
			}

		private:
			std::size_t block_num;
			std::size_t entry_num;
			std::size_t current_entry = 0;
			const BASE_RELOCATION_ENTRY& new_entry;
		};

		const auto change_entry_values_callback = std::make_shared<ChangeEntryValuesCallback>(
			static_cast<bool>(pe32plus), block_num, arg.item.pos().item, new_entry);
		pe32->ProcessRelocationTable(nullptr, change_entry_values_callback);
		arg.item.resolve_from(new_entry);
	}
}

void add_reloc_entry(form& fm, listbox::cat_proxy category, std::shared_ptr<PE32> pe32, std::size_t block_num, listbox::item_proxy parent_block)
{
	inputbox::text type{ "Type" };
	inputbox::text offset{ "Offset" };

	inputbox inbox{ fm, "Entry Values", "Entry " + std::to_string(category.size()) };
	inbox.verify(std::bind(reloc_entry_verifier, std::placeholders::_1, std::ref(type), std::ref(offset)));

	if (inbox.show(type, offset))
	{
		const BASE_RELOCATION_ENTRY new_entry{
			to_integer<decltype(std::declval<BASE_RELOCATION_ENTRY>().Offset)>(
				offset.value()),
			to_integer<decltype(std::declval<BASE_RELOCATION_ENTRY>().Type)>(
				type.value())
		};
		pe32->InsertRelocEntry(block_num, new_entry);
		category.append(new_entry);
		IMAGE_BASE_RELOCATION header;
		parent_block.resolve_to(header);
		header.SizeOfBlock += sizeof new_entry;
		parent_block.resolve_from(header);
	}
}

void show_block_entries(
	const arg_listbox& arg, form& main_form,
	std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus,
	std::mutex& mtx_selected)
{
	const std::unique_lock lock(mtx_selected, std::try_to_lock);
	if (!lock)
	{
		return;
	}
	arg.item.select(false);
	const auto block_num = arg.item.pos().item;
	form fm{ main_form, size{350, 400} };
	fm.caption("Block " + std::to_string(block_num));

	listbox lbox{ fm };
	lbox.sortable(false);
	lbox.checkable(false);
	lbox.column_movable(false);
	lbox.column_resizable(true);
	lbox.enable_single(true, false);
	for (const auto property_name : { "Type" , "Offset" })
	{
		lbox.append_header(property_name, 0);
	}

	class ShowRelocEntriesCallback : public RelocEntryCallback
	{
	public:

		ShowRelocEntriesCallback(bool is_pe32plus, std::size_t block_num, listbox::cat_proxy category) :
			RelocEntryCallback(is_pe32plus), category(category), block_num(block_num)
		{
		}

		void processRelocField(BASE_RELOCATION_ENTRY* entry, ULONG_PTR reloc_field) override
		{
			if (this->current_block == this->block_num)
			{
				this->category.append(*entry);
			}
		}
	private:
		listbox::cat_proxy category;
		std::size_t block_num;
	};
	const auto show_entries_callback = std::make_shared<ShowRelocEntriesCallback>(
		static_cast<bool>(pe32plus),
		block_num,
		lbox.at(0));
	pe32->ProcessRelocationTable(nullptr, show_entries_callback);

	button change_header_values{ fm, "Change Block Header Values" };
	change_header_values.events().click(std::bind(change_reloc_header_values,
		std::ref(fm), arg.item, pe32));

	std::mutex mtx_selected_nested;
	lbox.events().selected(std::bind(change_reloc_entry,
		std::placeholders::_1, std::ref(fm), pe32, pe32plus, block_num, std::ref(mtx_selected_nested)));

	button add_entry{ fm, "Add Entry" };
	add_entry.events().click(std::bind(add_reloc_entry, std::ref(fm), lbox.at(0), pe32, block_num, arg.item));

	fm.div("vertical <weight=5% change_values><lbox><weight=5% add_entry>");
	fm["change_values"] << change_header_values;
	fm["lbox"] << lbox;
	fm["add_entry"] << add_entry;
	fm.collocate();
	fm.show();
	fm.modality();

}

void relocate(form& fm, std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus, label& image_base_value)
{
	inputbox::text new_image_base{ "Image Base", image_base_value.caption() };

	inputbox inbox{ fm, "New Image Base" };

	std::variant<std::shared_ptr<PE32>, std::shared_ptr<PE32Plus>> pe = pe32plus ? pe32plus : pe32;

	std::visit([&inbox, &new_image_base](auto pe)
		{
			using T = decltype(pe->ImageBase());
			inbox.verify([&new_image_base](window handle)
				{
					if (!is_valid_hex_value<T>(new_image_base.value()))
					{
						msgbox mb(handle, "Invalid input");
						mb << "ImageBase is invalid. Must be as hex and " << sizeof T << " bytes";
						mb.show();
						return  false;
					}
					return true;
				});
		}, pe);

	if (inbox.show(new_image_base))
	{
		std::visit([&new_image_base](auto pe)
			{
				pe->ImageBase(to_integer<decltype(pe->ImageBase())>(new_image_base.value()));
			}, pe);
		image_base_value.caption(new_image_base.value());
	}
}

void add_reloc_block(form& fm, listbox::cat_proxy blocks, std::shared_ptr<PE32> pe32)
{
	inputbox::text virtual_address{ "VirtualAddress" };

	inputbox inbox{ fm, "Block Header Values", "Block Header" };
	inbox.verify(std::bind(reloc_block_header_verifier,
		std::placeholders::_1, std::ref(virtual_address), std::ref(virtual_address)));

	if (inbox.show(virtual_address))
	{
		const IMAGE_BASE_RELOCATION new_header{
			to_integer<decltype(std::declval<IMAGE_BASE_RELOCATION>().VirtualAddress)>(
				virtual_address.value()),
			sizeof IMAGE_BASE_RELOCATION };
		pe32->AddRelocBlock(new_header);
		blocks.append(new_header);
	}
}

void show_relocations(form& main_form, std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus)
{
	form fm{ main_form, size{350, 400} };

	group image_base_group{ fm, "Image Base" };
	label image_base_value{ image_base_group, to_string_hex(pe32plus ? pe32plus->ImageBase() : pe32->ImageBase()) };
	image_base_value.text_align(align::center, align_v::center)
		.events().click(std::bind(relocate, std::ref(fm), pe32, pe32plus, std::ref(image_base_value)));

	listbox lbox{ fm };
	lbox.sortable(false);
	lbox.checkable(false);
	lbox.column_movable(false);
	lbox.column_resizable(true);
	lbox.enable_single(true, false);
	for (const auto property_name : { "VirtualAddress" , "SizeOfBlock" })
	{
		lbox.append_header(property_name, 0);
	}

	class AppendRelocHeadersCallback : public RelocBlockHeaderCallback
	{
	public:

		AppendRelocHeadersCallback(listbox::cat_proxy category) : category(category) {}

		void processRelocHeader(IMAGE_BASE_RELOCATION* reloc) override
		{
			category.append(*reloc);
		}
	private:
		listbox::cat_proxy category;
	};
	const auto append_headers_callback = std::make_shared<AppendRelocHeadersCallback>(lbox.at(0));
	pe32->ProcessRelocationTable(append_headers_callback, nullptr);

	std::mutex mtx_selected;
	lbox.events().selected(std::bind(show_block_entries,
		std::placeholders::_1, std::ref(fm), pe32, pe32plus, std::ref(mtx_selected)));

	image_base_group.div("<margin=5 text>");
	image_base_group["text"] << image_base_value;

	button add_block{ fm, "Add Block" };
	add_block.events().click(std::bind(add_reloc_block, std::ref(fm), lbox.at(0), pe32));

	fm.div("<vertical <vertical weight=20% group><blocks><weight=5% add_block>>");
	fm["group"] << image_base_group;
	fm["blocks"] << lbox;
	fm["add_block"] << add_block;
	fm.collocate();
	fm.show();
	fm.modality();
}

bool import_desc_verifier(window handle, inputbox::text& characteristics, inputbox::text& timedatestamp,
	inputbox::text& forwarder_chain, inputbox::text& name, inputbox::text& first_thunk)
{
	for (const auto& [property_name, itext] :
		std::vector<std::pair<const char*, inputbox::text&>>{
			{"Characteristics/OriginalFirstThunk", characteristics},
			{"TimeDateStamp", timedatestamp},
			{"ForwarderChain", forwarder_chain},
			{"FirstThunk", first_thunk}
		})
	{
		using T = DWORD;
		if (!is_valid_hex_value<T>(itext.value()))
		{
			msgbox mb(handle, "Invalid input");
			mb << property_name << " is invalid. Must be as hex and " << sizeof T << " bytes";
			mb.show();
			return false;
		}
	}
	if (!PE32::is_valid_import_name(name.value().c_str()))
	{
		msgbox mb(handle, "Invalid input");
		mb << "Name is invalid. Characters must be in [0x20, 0x7E]";
		mb.show();
		return false;
	}
	return true;
}

void change_import_desc_values(form& fm, listbox::item_proxy item, std::shared_ptr<PE32> pe32)
{
	inputbox::text characteristics{ "Characteristics/OriginalFirstThunk", item.text(0) };
	inputbox::text timedatestamp{ "TimeDateStamp", item.text(1) };
	inputbox::text forwarder_chain{ "ForwarderChain", item.text(2) };
	inputbox::text name{ "Name", item.text(3) };
	inputbox::text first_thunk{ "FirstThunk", item.text(4) };

	inputbox inbox{ fm, "Descriptor Values", "Descriptor " + std::to_string(item.pos().item) };

	inbox.verify(std::bind(import_desc_verifier, std::placeholders::_1,
		std::ref(characteristics), std::ref(timedatestamp), std::ref(forwarder_chain),
		std::ref(name), std::ref(first_thunk)));

	if (inbox.show(characteristics, timedatestamp, forwarder_chain, name, first_thunk))
	{
		const IMAGE_IMPORT_DESCRIPTOR new_desc{
			to_integer<decltype(std::declval<IMAGE_IMPORT_DESCRIPTOR>().Characteristics)>(characteristics.value()),
			to_integer<decltype(std::declval<IMAGE_IMPORT_DESCRIPTOR>().TimeDateStamp)>(timedatestamp.value()),
			to_integer<decltype(std::declval<IMAGE_IMPORT_DESCRIPTOR>().ForwarderChain)>(forwarder_chain.value()),
			NULL,
			to_integer<decltype(std::declval<IMAGE_IMPORT_DESCRIPTOR>().FirstThunk)>(first_thunk.value())
		};

		class ChangeImportDescriptorValues : public ImportDescriptorCallback
		{
		public:
			ChangeImportDescriptorValues(
				std::size_t desc_index,
				const IMAGE_IMPORT_DESCRIPTOR& new_desc,
				const std::string new_name,
				std::shared_ptr<PE32> pe32) :
				ImportDescriptorCallback(), desc_index(desc_index), new_desc(new_desc), new_name(new_name), pe32(pe32) {}
			bool processDescriptor(IMAGE_IMPORT_DESCRIPTOR* desc) override
			{
				if (current_desc == desc_index)
				{
					const auto old_name_rva = desc->Name;
					*desc = new_desc;
					desc->Name = old_name_rva;
					const auto old_name = std::string(reinterpret_cast<char*>(pe32->GetRawPointer(old_name_rva)));
					if (old_name != new_name)
					{
						pe32->InsertNewOrReplaceString(desc->Name, new_name);
					}
				}
				++current_desc;
				return true;
			}
		private:
			std::size_t desc_index;
			std::size_t current_desc = 0;
			const IMAGE_IMPORT_DESCRIPTOR& new_desc;
			const std::string new_name;
			std::shared_ptr<PE32> pe32;
		};

		const auto callback = std::make_shared<ChangeImportDescriptorValues>(item.pos().item, new_desc, name.value(), pe32);
		pe32->ProcessImportTable(callback, nullptr);

		auto i = 0;
		for (const auto& property :
			{ characteristics.value(), timedatestamp.value(),  forwarder_chain.value(), name.value(), first_thunk.value() })
		{
			item.text(i++, property);
		}
	}
}

bool verify_import_function_name(window handle, inputbox::text& name)
{
	if (!PE32::is_valid_import_name(name.value().c_str()))
	{
		msgbox mb(handle, "Invalid input");
		mb << "Name is invalid. Characters must be in [0x20, 0x7E]";
		mb.show();
		return false;
	}
	return true;
}

void add_import_function(form& fm, std::shared_ptr<PE32> pe32, listbox::cat_proxy functions, std::size_t lib_num)
{
	inputbox::text name{ "Name" };

	inputbox inbox{ fm, "Function Name", "Import Function" };

	inbox.verify(std::bind(verify_import_function_name, std::placeholders::_1, std::ref(name)));

	if (inbox.show(name))
	{
		const auto name_value = name.value();
		pe32->AddImportFunction(lib_num, name_value);
		functions.append({ name_value, "false" });
	}
}

void change_import_function_name(
	const arg_listbox& arg, form& fm,
	std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus,
	listbox::item_proxy lib, listbox::size_type desc_num,
	std::mutex& mtx_selected_nested)
{
	const std::unique_lock lock(mtx_selected_nested, std::try_to_lock);
	if (!lock)
	{
		return;
	}
	arg.item.select(false);

	if (arg.item.text(1) == "true")
	{
		msgbox mb(fm, "Imported by ordinal");
		mb << "Can not change name! Function is imported by ordinal!";
		mb.show();
		return;
	}

	inputbox::text name{ "Name", arg.item.text(0) };

	inputbox inbox{ fm, "Function Name", "Function " + arg.item.text(0) };

	inbox.verify(std::bind(verify_import_function_name, std::placeholders::_1, std::ref(name)));

	class ChangeImportFunction : public ImportThunksCallback
	{
	public:
		ChangeImportFunction(std::string new_name, std::size_t desc_num, std::size_t func_num) :
			new_name(new_name), desc_num(desc_num), func_num(func_num) {}
		void incrementDescCounter() override
		{
			ImportThunksCallback::incrementDescCounter();
			current_function = 0;
		}
	protected:
		std::string new_name;
		std::size_t desc_num;
		std::size_t func_num;
		std::size_t current_function = 0;
	};

	class ChangeImportFunction32 : public ChangeImportFunction
	{
	public:
		ChangeImportFunction32(std::shared_ptr<PE32> pe32, std::string new_name,
			std::size_t desc_num, std::size_t func_num) :
			ChangeImportFunction(new_name, desc_num, func_num), pe32(pe32) {}
		bool processThunks(ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) override
		{
			if (desc_num == current_desc && func_num == current_function)
			{
				const auto desc = reinterpret_cast<IMAGE_THUNK_DATA32*>(origFirstThunkPtr);
				InsertNewOrReplaceImportName(pe32, desc->u1.AddressOfData, new_name);
			}
			++current_function;
			return true;
		}
	private:
		std::shared_ptr<PE32> pe32;
	};

	class ChangeImportFunction64 : public ChangeImportFunction
	{
	public:
		ChangeImportFunction64(std::shared_ptr<PE32Plus> pe32plus, std::string new_name,
			std::size_t desc_num, std::size_t func_num) :
			ChangeImportFunction(new_name, desc_num, func_num), pe32plus(pe32plus) {}
		bool processThunks(ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) override
		{
			if (desc_num == current_desc && func_num == current_function)
			{
				const auto desc = reinterpret_cast<IMAGE_THUNK_DATA64*>(origFirstThunkPtr);
				InsertNewOrReplaceImportName(pe32plus, desc->u1.AddressOfData, new_name);
			}
			++current_function;
			return true;
		}
	private:
		std::shared_ptr<PE32Plus> pe32plus;
	};

	if (inbox.show(name))
	{
		std::shared_ptr<ChangeImportFunction> callback;
		if (pe32plus)
		{
			callback = std::make_shared<ChangeImportFunction64>(pe32plus, name.value(), desc_num, lib.pos().item);
		}
		else
		{
			callback = std::make_shared<ChangeImportFunction32>(pe32, name.value(), desc_num, lib.pos().item);
		}
		pe32->ProcessImportTable(nullptr, callback);
		arg.item.text(0, name.value());
	}
}

void show_import_desc_functions(
	const arg_listbox& arg, form& main_form,
	std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus,
	std::mutex& mtx_selected)

{
	const std::unique_lock lock(mtx_selected, std::try_to_lock);
	if (!lock)
	{
		return;
	}
	arg.item.select(false);

	form fm{ main_form, size{650, 650} };
	fm.caption(arg.item.text(3));

	button change_desc_values{ fm, "Change Descriptor Values" };
	change_desc_values.events().click(std::bind(change_import_desc_values,
		std::ref(fm), arg.item, pe32));

	listbox lbox{ fm };
	lbox.sortable(false);
	lbox.checkable(false);
	lbox.column_movable(false);
	lbox.column_resizable(true);
	lbox.enable_single(true, false);
	for (const auto property_name :
		{ "Ordinal/Name" , "is Imported By Ordinal" })
	{
		lbox.append_header(property_name, 0);
	}

	class AppendImportFunctions : public ImportThunksCallback
	{
	public:
		AppendImportFunctions(listbox::cat_proxy category, std::size_t desc_num) :
			category(category), desc_num(desc_num) {}
	protected:
		listbox::cat_proxy category;
		std::size_t desc_num;
	};

	class AppendImportFunctions64 : public AppendImportFunctions
	{
	public:
		AppendImportFunctions64(std::shared_ptr<PE32Plus> pe32plus, listbox::cat_proxy category, std::size_t desc_num) :
			AppendImportFunctions(category, desc_num), pe32plus(pe32plus) {}
		bool processThunks(ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) override
		{
			if (desc_num == current_desc)
			{
				const auto desc = reinterpret_cast<IMAGE_THUNK_DATA64*>(origFirstThunkPtr);

				if (const bool is_by_ord = IMAGE_SNAP_BY_ORDINAL64(desc->u1.Ordinal); !is_by_ord)
				{
					const auto by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pe32plus->GetRawPointer(desc->u1.AddressOfData));
					const auto name = std::string(by_name->Name);
					category.append({ name,"true" });
				}
				else
				{
					category.append({ to_string_hex(desc->u1.Ordinal), "false" });
				}
			}
			return true;
		}
	private:
		std::shared_ptr<PE32Plus> pe32plus;
	};

	class AppendImportFunctions32 : public AppendImportFunctions
	{
	public:
		AppendImportFunctions32(std::shared_ptr<PE32> pe32, listbox::cat_proxy category, std::size_t desc_num) :
			AppendImportFunctions(category, desc_num), pe32(pe32) {}
		bool processThunks(ULONG_PTR origFirstThunkPtr, ULONG_PTR firstThunkPtr) override
		{
			if (desc_num == current_desc)
			{
				const auto desc = reinterpret_cast<IMAGE_THUNK_DATA32*>(origFirstThunkPtr);

				if (const bool is_by_ord = IMAGE_SNAP_BY_ORDINAL32(desc->u1.Ordinal); !is_by_ord)
				{
					const auto by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pe32->GetRawPointer(desc->u1.AddressOfData));
					const auto name = std::string(by_name->Name);
					category.append({ name,"false" });
				}
				else
				{
					category.append({ to_string_hex(desc->u1.Ordinal), "true" });
				}
			}
			return true;
		}
	private:
		std::shared_ptr<PE32> pe32;
	};

	std::shared_ptr<AppendImportFunctions> callback;
	if (pe32plus)
	{
		callback = std::make_shared<AppendImportFunctions64>(pe32plus, lbox.at(0), arg.item.pos().item);
	}
	else
	{
		callback = std::make_shared<AppendImportFunctions32>(pe32, lbox.at(0), arg.item.pos().item);
	}

	pe32->ProcessImportTable(nullptr, callback);
	lbox.column_at(0).fit_content();

	const auto lib_num = arg.item.pos().item;

	std::mutex mtx_selected_nested;
	lbox.events().selected(std::bind(change_import_function_name, std::placeholders::_1,
		std::ref(fm), pe32, pe32plus, arg.item, lib_num, std::ref(mtx_selected_nested)));

	button add_func{ fm, "Add Function" };
	add_func.events().click(std::bind(add_import_function, std::ref(fm), pe32, lbox.at(0), lib_num));

	fm.div("vertical <weight=5% change_desc><lbox><weight=5% add_func>");
	fm["lbox"] << lbox;
	fm["change_desc"] << change_desc_values;
	fm["add_func"] << add_func;
	fm.collocate();
	fm.show();
	fm.modality();

}

void add_import_descriptor(form& fm, listbox::cat_proxy category, std::shared_ptr<PE32> pe32)
{
	inputbox::text characteristics{ "Characteristics/OriginalFirstThunk", "0"};
	inputbox::text timedatestamp{ "TimeDateStamp", "0"};
	inputbox::text forwarder_chain{ "ForwarderChain", "0"};
	inputbox::text name{ "Name" };
	inputbox::text first_thunk{ "FirstThunk", "0"};

	inputbox inbox{ fm, "Descriptor Values", "Descriptor " + std::to_string(category.size()) };

	inbox.verify(std::bind(import_desc_verifier, std::placeholders::_1,
		std::ref(characteristics), std::ref(timedatestamp), std::ref(forwarder_chain),
		std::ref(name), std::ref(first_thunk)));

	if (inbox.show(name))
	{
		const DWORD rva_orig_first_thunk = pe32->InsertNewFirstThunkArray();
		const DWORD rva_name = pe32->InsertNewString(name.value());
		const DWORD rva_first_thunk = pe32->InsertNewFirstThunkArray();
		IMAGE_IMPORT_DESCRIPTOR new_desc{
			rva_orig_first_thunk,
			NULL,
			NULL,
			rva_name,
			rva_first_thunk
		};

		pe32->AddImportDesc(new_desc);

		category.append({ to_string_hex(rva_orig_first_thunk), "0", "0", name.value(), to_string_hex(rva_first_thunk)});
	}
}

void show_import_table(form& main_form, std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus)
{
	form fm{ main_form, size{650, 650} };
	fm.caption("Import Table Descriptors");

	listbox lbox{ fm };
	lbox.sortable(false);
	lbox.checkable(false);
	lbox.column_movable(false);
	lbox.column_resizable(true);
	lbox.enable_single(true, false);
	for (const auto property_name :
		{ "Characteristics/OriginalFirstThunk" , "TimeDateStamp", "ForwarderChain", "Name", "FirstThunk" })
	{
		lbox.append_header(property_name, 0);
	}

	class AppendImportDescriptor : public ImportDescriptorCallback
	{
	public:
		AppendImportDescriptor(listbox::cat_proxy category, std::shared_ptr<PE32> pe32) :
			category(category), pe32(pe32) {}
		bool processDescriptor(IMAGE_IMPORT_DESCRIPTOR* desc) override
		{
			category.append({
				to_string_hex(desc->Characteristics),
				to_string_hex(desc->TimeDateStamp),
				to_string_hex(desc->ForwarderChain),
				std::string(reinterpret_cast<char*>(pe32->GetRawPointer(desc->Name))),
				to_string_hex(desc->FirstThunk)
				});
			return true;
		}
	private:
		listbox::cat_proxy category;
		std::shared_ptr<PE32> pe32;
	};

	const auto desc_callback = std::make_shared<AppendImportDescriptor>(lbox.at(0), pe32);
	pe32->ProcessImportTable(desc_callback, nullptr);
	lbox.column_at(3).fit_content();

	std::mutex mtx_selected;
	lbox.events().selected(std::bind(show_import_desc_functions,
		std::placeholders::_1, std::ref(fm), pe32, pe32plus, std::ref(mtx_selected)));

	button add_desc{ fm, "Add Descriptor" };
	add_desc.events().click(std::bind(add_import_descriptor, std::ref(fm), lbox.at(0), pe32));

	fm.div("vertical <lbox><weight=5% add_desc>");
	fm["lbox"] << lbox;
	fm["add_desc"] << add_desc;
	fm.collocate();
	fm.show();
	fm.modality();
}

bool export_name_verifier(window handle, inputbox::text& module_name, std::size_t max_name_length)
{
	if (!PE32::is_valid_import_name(module_name.value().c_str()))
	{
		msgbox mb(handle, "Invalid input");
		mb << "Name is invalid. Characters must be in [0x20, 0x7E]";
		mb.show();
		return false;
	}
	if (module_name.value().size() > max_name_length)
	{
		msgbox mb(handle, "Invalid input");
		mb << "Name is too long. Max length: " << max_name_length;
		mb.show();
		return false;
	}
	return true;
}

void change_export_name(form& fm, std::shared_ptr<PE32> pe32, label& name_value, std::size_t max_name_length)
{
	const auto text = name_value.caption();
	inputbox::text module_name{ "Module Name", text };

	inputbox inbox{ fm, "Properties of Function", "Function" };
	inbox.verify(std::bind(export_name_verifier, std::placeholders::_1, std::ref(module_name), max_name_length));

	if (inbox.show(module_name))
	{
		pe32->InsertNewOrReplaceString(pe32->DirectoryEntryExport()->Name, module_name.value());
		name_value.caption(module_name.value());
	}
}

void change_export_function(
	const arg_listbox& arg, form& fm, std::shared_ptr<PE32> pe32,
	DWORD* functions, DWORD* names, WORD* name_ordinals,
	std::size_t max_name_length, std::mutex& mtx_selected)
{
	const std::unique_lock lock(mtx_selected, std::try_to_lock);
	if (!lock)
	{
		return;
	}
	arg.item.select(false);

	const auto i = arg.item.pos().item;

	inputbox::text func_name{ "Function Name", arg.item.text(0) };
	inputbox::text address{ "RVA", arg.item.text(1) };

	inputbox inbox{ fm, "Properties of Function", "Function" };
	using T = std::remove_reference_t<decltype(functions[name_ordinals[i]])>;
	inbox.verify([&func_name, &address, max_name_length](window handle)
		{
			if (!export_name_verifier(handle, func_name, max_name_length))
			{
				return false;
			}

			if (!is_valid_hex_value<T>(address.value()))
			{
				msgbox mb(handle, "Invalid input");
				mb << "RVA is invalid. Must be as hex and " << sizeof T << " bytes";
				mb.show();
				return false;
			}
			return true;
		});

	if (inbox.show(func_name, address))
	{
		pe32->InsertNewOrReplaceString(names[i], func_name.value());
		functions[name_ordinals[i]] = to_integer<T>(address.value());
		arg.item.text(0, func_name.value());
		arg.item.text(1, address.value());
	}

}

void show_export_table(form& main_form, std::shared_ptr<PE32> pe32)
{
	form fm{ main_form, size{350, 400} };
	listbox lbox{ fm };

	lbox.sortable(false);
	lbox.checkable(false);
	lbox.column_movable(false);
	lbox.column_resizable(true);
	lbox.enable_single(true, false);

	auto directory_entry_export = pe32->DirectoryEntryExport();

	if (!directory_entry_export)
	{
		msgbox mb("Invalid Export Table Virtual Address");
		mb << "Export Table Virtual Address is NULL";
		mb.show();
		return;
	}

	const auto name = pe32->ExportName();

	group name_group{ fm, "Name" };
	label name_value{ name_group, name };

	constexpr auto max_name_length = 80;

	name_value.events().click(std::bind(change_export_name,
		std::ref(fm), pe32, std::ref(name_value), max_name_length));

	for (const auto property_name : { "Name" , "RVA" })
	{
		lbox.append_header(property_name, 0);
	}

	const auto functions = reinterpret_cast<DWORD*>(pe32->GetRawPointer(directory_entry_export->AddressOfFunctions));
	auto names = reinterpret_cast<DWORD*>(pe32->GetRawPointer(directory_entry_export->AddressOfNames));
	const auto name_ordinals = reinterpret_cast<WORD*>(pe32->GetRawPointer(directory_entry_export->AddressOfNameOrdinals));

	for (DWORD i = 0; i < directory_entry_export->NumberOfNames; ++i)
	{
		lbox.at(0).append({
			std::string(reinterpret_cast<char*>(pe32->GetRawPointer(names[i]))),
			to_string_hex(functions[name_ordinals[i]]) });
	}

	lbox.column_at(0).fit_content();


	std::mutex mtx_selected;
	lbox.events().selected(std::bind(change_export_function, std::placeholders::_1,
		std::ref(fm), pe32, functions, names, name_ordinals, max_name_length, std::ref(mtx_selected)));

	name_group.div("<vertical <weight=75% margin=5 text>>");
	name_group["text"] << name_value;

	fm.div("<vertical <vertical weight=20% group><lbox>>");
	fm["group"] << name_group;
	fm["lbox"] << lbox;
	fm.collocate();
	fm.show();
	fm.modality();
}