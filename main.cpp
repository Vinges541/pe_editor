#include <charconv>
#include <map>
#include <utility>
#include <variant>
#include <nana/gui.hpp>
#include <nana/gui/filebox.hpp>
#include <nana/gui/widgets/button.hpp>
#include <nana/gui/widgets/group.hpp>
#include <nana/gui/widgets/label.hpp>
#include <nana/gui/widgets/listbox.hpp>
#include <nana/gui/widgets/textbox.hpp>

#include "gui.hpp"
#include "pe.hpp"
#include "util.hpp"

template<typename T>
void update_property(const nana::arg_textbox& arg, nana::label& lbl, std::function<void(T)> setter)
{
	auto& tb = arg.widget;
	T value;
	const auto text = tb.text();
	if (text.length() > sizeof T * 2)
	{
		std::ostringstream oss;
		oss << "Value must be " << sizeof T << " bytes";
		lbl.caption(oss.str());
		return;
	}
	std::from_chars(text.c_str(), text.c_str() + sizeof T * 2, value, 16);
	setter(value);
	lbl.caption("");
}

int main()
{
	using namespace nana;

	filebox fb{ nullptr, true };
	fb.add_filter("PE", "*.exe;*.dll");

	std::shared_ptr<PE32> pe32;
	std::shared_ptr<PE32Plus> pe32plus;
	try
	{
		const auto paths = fb.show();
		if (paths.size() < 1)
		{
			return 0;
		}
		pe32 = LoadPE(paths.front());
		pe32plus = std::dynamic_pointer_cast<PE32Plus>(pe32);
	}
	catch (const std::exception& e)
	{
		msgbox m{ "Error!" };
		m << e.what();
		m.show();
		exit(1);
	}

	form   fm{ API::make_center(480, 250) };
	fm.caption(std::string("PE Editor: PE32") + (pe32plus ? "Plus" : ""));

	const size message_size{ 115, 15 };
	const size group_size{ 125, 60 };

	const size textbox_size{ 20, 20 };
	const point textbox_point{ 60, 20 };

	const point message_point{ 5, 40 };

	const size button_size{ 90, 20 };

	std::map<std::string, group> groups;
	std::map<std::string, textbox> textboxes;
	std::map<std::string, label> labels;

	using word_property = std::pair<WORD(PE32::*)() const, void (PE32::*)(WORD)>;
	using dword_property = std::pair<DWORD(PE32::*)() const, void (PE32::*)(DWORD)>;

	std::map<std::string, std::variant<word_property, dword_property>> name_to_methods;
	{
		name_to_methods["Magic"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().Magic())(PE32::*)() const>(&PE32::Magic),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().Magic()))>(&PE32::Magic));

		name_to_methods["Signature"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().Signature())(PE32::*)() const>(&PE32::Signature),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().Signature()))>(&PE32::Signature));

		name_to_methods["TimeDateStamp"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().TimeDateStamp())(PE32::*)() const>(&PE32::TimeDateStamp),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().TimeDateStamp()))>(&PE32::TimeDateStamp));

		name_to_methods["NumberOfSections"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().NumberOfSections())(PE32::*)() const>(&PE32::NumberOfSections),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().NumberOfSections()))>(&PE32::NumberOfSections));

		name_to_methods["SizeOfOptionalHeader"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().SizeOfOptionalHeader())(PE32::*)() const>(&PE32::SizeOfOptionalHeader),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().SizeOfOptionalHeader()))>(&PE32::SizeOfOptionalHeader));

		name_to_methods["Characteristics"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().Characteristics())(PE32::*)() const>(&PE32::Characteristics),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().Characteristics()))>(&PE32::Characteristics));

		name_to_methods["AddressEntryPoint"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().AddressEntryPoint())(PE32::*)() const>(&PE32::AddressEntryPoint),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().AddressEntryPoint()))>(&PE32::AddressEntryPoint));

		name_to_methods["SectionAlignment"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().SectionAlignment())(PE32::*)() const>(&PE32::SectionAlignment),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().SectionAlignment()))>(&PE32::SectionAlignment));

		name_to_methods["FileAlignment"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().FileAlignment())(PE32::*)() const>(&PE32::FileAlignment),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().FileAlignment()))>(&PE32::FileAlignment));

		name_to_methods["SizeOfImage"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().SizeOfImage())(PE32::*)() const>(&PE32::SizeOfImage),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().SizeOfImage()))>(&PE32::SizeOfImage));

		name_to_methods["SizeOfHeaders"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().SizeOfHeaders())(PE32::*)() const>(&PE32::SizeOfHeaders),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().SizeOfHeaders()))>(&PE32::SizeOfHeaders));

		name_to_methods["Subsystem"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().Subsystem())(PE32::*)() const>(&PE32::Subsystem),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().Subsystem()))>(&PE32::Subsystem));

		name_to_methods["SizeOfHeaders"] = std::make_pair(
			static_cast<decltype(std::declval<PE32>().NumberOfRvaAndSizes())(PE32::*)() const>(&PE32::NumberOfRvaAndSizes),
			static_cast<void (PE32::*)(decltype(std::declval<PE32>().NumberOfRvaAndSizes()))>(&PE32::NumberOfRvaAndSizes));
	}

	int x = 0, y = 0;
	for (auto& [name, methods] : name_to_methods)
	{
		std::visit([&name = name, &groups, &fm, &x, &y, pe32, &textboxes,
			&message_point, &message_size, &labels, &textbox_point, &textbox_size, &group_size](auto arg)
			{
				using T = std::invoke_result_t<decltype(arg.first), decltype(pe32.get())>;
				auto [get_value, set_value] = arg;
				auto [grp, _] = groups.try_emplace(name, fm, name, false, 2,
					rectangle{ {static_cast<int>(x * group_size.width) + 5, static_cast<int>(group_size.height * y)}, group_size });
				auto [tb, __] = textboxes.try_emplace(name, grp->second,
					rectangle{ static_cast<int>(textbox_point.x / sizeof T) + 10,
						textbox_point.y,  textbox_size.width + sizeof T * 10, textbox_size.height });
				tb->second.multi_lines(false).set_accept(is_acceptable);
				T value = (pe32.get()->*get_value)();
				tb->second.append(to_string_hex(value), true);
				std::function<void(decltype(value))> setter = std::bind(
					set_value,
					pe32.get(),
					std::placeholders::_1);
				auto [lbl, ___] = labels.try_emplace(name, grp->second,
					rectangle{ message_point, message_size });
				lbl->second.fgcolor(colors::red);
				tb->second.events().text_changed(std::bind(
					update_property<decltype(value)>,
					std::placeholders::_1,
					std::ref(lbl->second),
					setter));
				++y;
				if (y != 0 && y % 4 == 0)
				{
					++x;
					y = 0;
				}
			}, methods);
	}

	button sections{ fm, rectangle{point{static_cast<int>(group_size.width * x) + 10, 10}, button_size} };
	sections.caption("Sections");
	sections.events().click(std::bind(show_sections, std::ref(fm), pe32));

	button data_directories{ fm, rectangle{
		point{static_cast<int>(group_size.width * x) + 10, 10 + static_cast<int>(sections.size().height) + 5},
		button_size } };
	data_directories.caption("Data Directories");
	data_directories.events().click(std::bind(show_data_directories, std::ref(fm), pe32));

	button relocations{ fm, rectangle{
		point{static_cast<int>(group_size.width * x) + 10, 15 + 2 * static_cast<int>(data_directories.size().height) + 5},
		button_size } };
	relocations.caption("Base Reloc Table");
	relocations.events().click(std::bind(show_relocations, std::ref(fm), pe32, pe32plus));

	button import_table{ fm, rectangle{
		point{static_cast<int>(group_size.width * x) + 10, 20 + 3 * static_cast<int>(data_directories.size().height) + 5},
		button_size } };
	import_table.caption("Import Table");
	import_table.events().click(std::bind(show_import_table, std::ref(fm), pe32, pe32plus));

	button export_table{ fm, rectangle{
		point{static_cast<int>(group_size.width * x) + 10, 25 + 4 * static_cast<int>(data_directories.size().height) + 5},
		button_size } };
	export_table.caption("Export Table");
	export_table.events().click(std::bind(show_export_table, std::ref(fm), pe32));

	fm.show();
	exec();
	UnloadPE(pe32);
	return 0;
}