#pragma once
#include <nana/gui.hpp>
#include <nana/gui/widgets/form.hpp>
#include <nana/gui/widgets/listbox.hpp>

#include "pe.hpp"

void show_sections(nana::form& main_form, std::shared_ptr<PE32> pe32);

void show_data_directories(nana::form& main_form, std::shared_ptr<PE32> pe32);

void show_relocations(nana::form& main_form, std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus);

void show_import_table(nana::form& main_form, std::shared_ptr<PE32> pe32, std::shared_ptr<PE32Plus> pe32plus);

void show_export_table(nana::form& main_form, std::shared_ptr<PE32> pe32);