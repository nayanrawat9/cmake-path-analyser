#!/usr/bin/env python3
"""
C/C++ Include Path Case Sensitivity Fixer
=========================================

A cross-platform GUI tool to scan, detect, and fix case sensitivity issues in C/C++ #include paths.

Features:
- Scans C/C++ source files for #include statements.
- Validates include paths and detects case mismatches or missing files.
- Suggests and applies fixes for case sensitivity issues.
- Supports custom include directories and missing file search.
- Useful for Windows/Linux/macOS projects.

Usage:
    python source_case_fixer.pyw
    # Follow the GUI instructions to select your project directory and fix issues.

Author: nayanrawat9
License: MIT
"""

import os
import re
import customtkinter
from tkinter import filedialog, messagebox, BooleanVar
from pathlib import Path
import shutil
from datetime import datetime
from typing import List, Dict, Tuple, Set
import threading

class IncludePathFixer(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("C/C++ Include Path Case Fixer")
        self.geometry("1000x700")

        # Data storage
        self.project_root = ""
        self.include_paths = []
        self.validation_results = []
        self.fix_suggestions = []
        self.custom_include_dirs = []
        self.missing_files_to_search: Set[str] = set()
        self.found_missing_paths: Dict[str, str] = {}

        self.create_widgets()

        self.scanning = False
        self.validating = False
        self.applying_fixes = False
        self.searching_missing = False

    def create_widgets(self):
        """Create the main GUI widgets."""
        main_frame = customtkinter.CTkFrame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)

        # Project selection
        customtkinter.CTkLabel(main_frame, text="Project Root Directory:").grid(row=0, column=0, sticky="w", pady=5)
        self.project_path_var = customtkinter.StringVar()
        customtkinter.CTkEntry(main_frame, textvariable=self.project_path_var, width=50).grid(row=0, column=1, sticky="ew", padx=5)
        customtkinter.CTkButton(main_frame, text="Browse", command=self.browse_project).grid(row=0, column=2, padx=5)

        # Button frame
        button_frame = customtkinter.CTkFrame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="ew")

        self.scan_btn = customtkinter.CTkButton(button_frame, text="1. Scan for Includes", command=self.scan_includes)
        self.scan_btn.grid(row=0, column=0, padx=5, pady=5)
        self.validate_btn = customtkinter.CTkButton(button_frame, text="2. Validate Include Paths", command=self.validate_includes, state="disabled")
        self.validate_btn.grid(row=0, column=1, padx=5, pady=5)
        self.suggest_btn = customtkinter.CTkButton(button_frame, text="3. Suggest Fixes", command=self.suggest_fixes, state="disabled")
        self.suggest_btn.grid(row=0, column=2, padx=5, pady=5)
        self.apply_btn = customtkinter.CTkButton(button_frame, text="4. Apply Fixes", command=self.apply_fixes, state="disabled")
        self.apply_btn.grid(row=0, column=3, padx=5, pady=5)
        self.verify_btn = customtkinter.CTkButton(button_frame, text="Verify Fixes", command=self.verify_fixes, state="disabled")
        self.verify_btn.grid(row=0, column=4, padx=5, pady=5)
        self.search_missing_btn = customtkinter.CTkButton(button_frame, text="Search Missing Files", command=self.search_missing_files, state="disabled")
        self.search_missing_btn.grid(row=0, column=5, padx=5, pady=5)
        self.include_paths_btn = customtkinter.CTkButton(button_frame, text="Set Include Paths", command=self.set_include_paths)
        self.include_paths_btn.grid(row=0, column=6, padx=5, pady=5)
        self.clear_rescan_btn = customtkinter.CTkButton(button_frame, text="Clear & Re-scan", command=self.clear_and_rescan)
        self.clear_rescan_btn.grid(row=1, column=0, padx=5, pady=5)

        # Progress bar
        self.progress_var = customtkinter.StringVar(value="Ready")
        customtkinter.CTkLabel(main_frame, textvariable=self.progress_var).grid(row=2, column=0, columnspan=3, pady=5)
        self.progress_bar = customtkinter.CTkProgressBar(main_frame, mode='determinate')
        self.progress_bar.grid(row=3, column=0, columnspan=3, sticky="ew", pady=5)
        self.progress_bar.set(0)

        # Statistics frame
        stats_frame = customtkinter.CTkFrame(main_frame)
        stats_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=5)
        self.stats_text = customtkinter.StringVar(value="No scan performed yet")
        customtkinter.CTkLabel(stats_frame, textvariable=self.stats_text).grid(row=0, column=0, sticky="w", padx=10)

        # Options frame
        options_frame = customtkinter.CTkFrame(main_frame)
        options_frame.grid(row=5, column=0, columnspan=3, sticky="ew", pady=5)
        self.system_includes_var = BooleanVar(value=False)
        customtkinter.CTkCheckBox(options_frame, text="Include system headers (<...>) in validation", variable=self.system_includes_var).grid(row=0, column=0, sticky="w", padx=20)

        # Results area
        results_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        results_frame.grid(row=6, column=0, columnspan=3, sticky="nsew", pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        self.results_text = customtkinter.CTkTextbox(results_frame, wrap="word", height=15)
        self.results_text.grid(row=0, column=0, sticky="nsew")

    def browse_project(self):
        directory = filedialog.askdirectory(title="Select Project Root Directory")
        if directory:
            self.project_path_var.set(directory)
            self.project_root = directory
            self.reset_state()

    def reset_state(self):
        self.include_paths = []
        self.validation_results = []
        self.fix_suggestions = []
        self.missing_files_to_search = set()
        self.found_missing_paths = {}
        self.validate_btn.configure(state="disabled")
        self.suggest_btn.configure(state="disabled")
        self.apply_btn.configure(state="disabled")
        self.verify_btn.configure(state="disabled")
        self.search_missing_btn.configure(state="disabled")
        self.stats_text.set("No scan performed yet")
        self.results_text.delete(1.0, "end")
        self.progress_bar.set(0)
        self.progress_var.set("Ready")

    def scan_includes(self):
        if not self.project_root:
            messagebox.showerror("Error", "Please select a project root directory first.")
            return
        if not os.path.exists(self.project_root):
            messagebox.showerror("Error", "Selected directory does not exist.")
            return
        self.scanning = True
        self.progress_var.set("Scanning for includes...")
        self.progress_bar.start()
        self.scan_btn.configure(state="disabled")
        self.validate_btn.configure(state="disabled")
        self.suggest_btn.configure(state="disabled")
        self.apply_btn.configure(state="disabled")
        self.verify_btn.configure(state="disabled")
        self.search_missing_btn.configure(state="disabled")
        thread = threading.Thread(target=self._scan_includes_thread)
        thread.daemon = True
        thread.start()

    def _scan_includes_thread(self):
        try:
            self.include_paths = []
            c_extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'}
            include_pattern = re.compile(r'^\s*#include\s*([<"][^<>"]+[>"])', re.MULTILINE)
            scanned_files_count = 0
            total_includes = 0
            all_files = []
            for root, dirs, files in os.walk(self.project_root):
                for file in files:
                    if Path(file).suffix.lower() in c_extensions:
                        all_files.append(os.path.join(root, file))
            total_files_to_scan = len(all_files)
            for i, file_path in enumerate(all_files):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    for line_num, line in enumerate(content.splitlines(), 1):
                        match = include_pattern.search(line)
                        if match:
                            include_stmt = match.group(1)
                            self.include_paths.append((file_path, include_stmt, line_num))
                            total_includes += 1
                    scanned_files_count += 1
                    progress = int((i + 1) / total_files_to_scan * 100) if total_files_to_scan > 0 else 0
                    self.after(0, lambda p=progress, fn=os.path.basename(file_path): self._update_progress_ui(f"Scanning: {fn}", p))
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
            self.after(0, self._scan_complete, scanned_files_count, total_includes)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
            self.after(0, self._scan_complete, 0, 0)

    def _scan_complete(self, scanned_files_count, total_includes):
        self.scanning = False
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set("Scan complete")
        self.scan_btn.configure(state="normal")
        if total_includes > 0:
            self.validate_btn.configure(state="normal")
        unique_includes = len(set(include for _, include, _ in self.include_paths))
        self.stats_text.set(f"Scanned {scanned_files_count} files, found {total_includes} includes ({unique_includes} unique)")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"Scan Results:\n")
        self.results_text.insert("end", f"Files scanned: {scanned_files_count}\n")
        self.results_text.insert("end", f"Total includes: {total_includes}\n")
        self.results_text.insert("end", f"Unique includes: {unique_includes}\n\n")
        if self.include_paths:
            self.results_text.insert("end", "Sample includes found:\n")
            for i, (file_path, include, line_num) in enumerate(self.include_paths[:20]):
                rel_path = os.path.relpath(file_path, self.project_root)
                self.results_text.insert("end", f"  {rel_path}:{line_num} -> {include}\n")
            if len(self.include_paths) > 20:
                self.results_text.insert("end", f"  ... and {len(self.include_paths) - 20} more\n")

    def _update_progress_ui(self, message: str, percentage: int):
        self.progress_var.set(message)
        self.progress_bar.set(percentage / 100)

    def validate_includes(self):
        if not self.include_paths:
            messagebox.showwarning("Warning", "No includes found. Please scan first.")
            return
        self.validating = True
        self.progress_var.set("Validating include paths...")
        self.progress_bar.start()
        self.validate_btn.configure(state="disabled")
        self.suggest_btn.configure(state="disabled")
        self.apply_btn.configure(state="disabled")
        self.verify_btn.configure(state="disabled")
        self.search_missing_btn.configure(state="disabled")
        thread = threading.Thread(target=self._validate_includes_thread)
        thread.daemon = True
        thread.start()

    def _validate_includes_thread(self):
        try:
            self.validation_results = []
            self.missing_files_to_search = set()
            total_includes_to_validate = len(self.include_paths)
            for i, (file_path, include_stmt, line_num) in enumerate(self.include_paths):
                result = self._validate_single_include(file_path, include_stmt, line_num)
                self.validation_results.append(result)
                if not result['is_valid'] and not result['exists'] and not result['is_system']:
                    include_path = include_stmt[1:-1]
                    self.missing_files_to_search.add(include_path)
                progress = int((i + 1) / total_includes_to_validate * 100) if total_includes_to_validate > 0 else 0
                self.after(0, lambda p=progress: self._update_progress_ui(f"Validating includes...", p))
            self.after(0, self._validation_complete)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Validation failed: {str(e)}"))
            self.after(0, self._validation_complete)

    def _validate_single_include(self, file_path, include_stmt, line_num):
        result = {'file_path': file_path, 'include_stmt': include_stmt, 'line_num': line_num, 'is_system': include_stmt.startswith('<'), 'is_valid': True, 'exists': False, 'case_match': True, 'actual_path': None, 'suggested_fix': None}
        include_path_str = include_stmt[1:-1]
        if result['is_system'] and not self.system_includes_var.get():
            return result
        if not result['is_system']:
            found = False
            current_dir = os.path.dirname(file_path)
            full_path_check = Path(current_dir) / include_path_str
            if full_path_check.exists():
                result['exists'] = True
                result['actual_path'] = str(full_path_check)
                actual_name = os.path.basename(os.path.realpath(str(full_path_check)))
                expected_name = os.path.basename(include_path_str)
                result['case_match'] = actual_name == expected_name
                found = True
            if not found:
                search_dirs = [self.project_root] + self.custom_include_dirs
                for search_dir in search_dirs:
                    full_path_check = Path(search_dir) / include_path_str
                    if full_path_check.exists():
                        result['exists'] = True
                        result['actual_path'] = str(full_path_check)
                        actual_name = os.path.basename(os.path.realpath(str(full_path_check)))
                        expected_name = os.path.basename(include_path_str)
                        result['case_match'] = actual_name == expected_name
                        found = True
                        break
            if not found and include_path_str in self.found_missing_paths:
                actual_full_path = self.found_missing_paths[include_path_str]
                if Path(actual_full_path).exists():
                    result['exists'] = True
                    result['actual_path'] = actual_full_path
                    actual_name = os.path.basename(os.path.realpath(actual_full_path))
                    expected_name = os.path.basename(include_path_str)
                    result['case_match'] = actual_name == expected_name
                    found = True
        result['is_valid'] = result['exists'] and result['case_match']
        return result

    def _validation_complete(self):
        self.validating = False
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set("Validation complete")
        self.validate_btn.configure(state="normal")
        total = len(self.validation_results)
        valid = sum(1 for r in self.validation_results if r['is_valid'])
        invalid = total - valid
        case_issues = sum(1 for r in self.validation_results if r['exists'] and not r['case_match'])
        missing = sum(1 for r in self.validation_results if not r['exists'] and not r['is_system'])
        if invalid > 0:
            self.suggest_btn.configure(state="normal")
        if missing > 0:
            self.search_missing_btn.configure(state="normal")
        self.stats_text.set(f"Validation: {valid}/{total} valid, {case_issues} case issues, {missing} missing (user includes)")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"Validation Results:\n")
        self.results_text.insert("end", f"Total includes: {total}\n")
        self.results_text.insert("end", f"Valid: {valid}\n")
        self.results_text.insert("end", f"Case sensitivity issues: {case_issues}\n")
        self.results_text.insert("end", f"Missing user includes: {missing}\n\n")
        if invalid > 0:
            self.results_text.insert("end", "Issues found:\n")
            for result in self.validation_results:
                if not result['is_valid'] and not result['is_system']:
                    rel_path = os.path.relpath(result['file_path'], self.project_root)
                    issue_type = "MISSING" if not result['exists'] else "CASE"
                    issue_number = sum(1 for r in self.validation_results[:self.validation_results.index(result) + 1] if not r['is_valid'] and not r['is_system'])
                    self.results_text.insert("end", f"  {issue_number}. [{issue_type}] {rel_path}:{result['line_num']} -> {result['include_stmt']}\n")
        else:
            self.results_text.insert("end", "No issues found in user includes.\n")

    def suggest_fixes(self):
        if not self.validation_results:
            messagebox.showwarning("Warning", "No validation results. Please validate first.")
            return
        self.fix_suggestions = []
        for result in self.validation_results:
            if not result['is_valid'] and result['exists'] and not result['case_match']:
                fix = self._suggest_case_fix(result)
                if fix:
                    self.fix_suggestions.append(fix)
        if self.fix_suggestions:
            self.apply_btn.configure(state="normal")
            self.verify_btn.configure(state="normal")
        else:
            self.apply_btn.configure(state="disabled")
            self.verify_btn.configure(state="disabled")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"Fix Suggestions:\n")
        self.results_text.insert("end", f"Fixable issues (case sensitivity): {len(self.fix_suggestions)}\n\n")
        if len(self.fix_suggestions) == 0:
            self.results_text.insert("end", "No case sensitivity issues found that can be automatically fixed.\n")
            self.results_text.insert("end", "Consider using 'Search Missing Files' for missing include paths.\n")
            return
        for fix in self.fix_suggestions:
            rel_path = os.path.relpath(fix['file_path'], self.project_root)
            self.results_text.insert("end", f"File: {rel_path}:{fix['line_num']}\n")
            self.results_text.insert("end", f"  Current: {fix['old_include']}\n")
            self.results_text.insert("end", f"  Fixed:   {fix['new_include']}\n")
            self.results_text.insert("end", "\n")

    def _suggest_case_fix(self, result):
        if not result['actual_path']:
            return None
        actual_name = os.path.basename(os.path.realpath(result['actual_path']))
        include_path = result['include_stmt'][1:-1]
        path_parts = re.split(r'[/\\]', include_path)
        path_parts[-1] = actual_name
        if '/' in include_path:
            corrected_path = '/'.join(path_parts)
        elif '\\' in include_path:
            corrected_path = '\\'.join(path_parts)
        else:
            corrected_path = actual_name
        bracket_char = '<' if result['is_system'] else '"'
        close_bracket = '>' if result['is_system'] else '"'
        new_include = f"{bracket_char}{corrected_path}{close_bracket}"
        return {'file_path': result['file_path'], 'line_num': result['line_num'], 'old_include': result['include_stmt'], 'new_include': new_include}

    def apply_fixes(self):
        if not self.fix_suggestions:
            messagebox.showwarning("Warning", "No fixes to apply. Please suggest fixes first.")
            return
        response = messagebox.askyesno("Confirm Fixes", f"Apply {len(self.fix_suggestions)} fixes?")
        if not response:
            return
        self.applying_fixes = True
        self.progress_var.set("Applying fixes...")
        self.progress_bar.start()
        self.apply_btn.configure(state="disabled")
        thread = threading.Thread(target=self._apply_fixes_thread)
        thread.daemon = True
        thread.start()

    def _apply_fixes_thread(self):
        try:
            applied_fixes = 0
            files_modified = set()
            fixes_by_file = {}
            for fix in self.fix_suggestions:
                file_path = fix['file_path']
                if file_path not in fixes_by_file:
                    fixes_by_file[file_path] = []
                fixes_by_file[file_path].append(fix)
            total_files_to_modify = len(fixes_by_file)
            current_file_index = 0
            for file_path, fixes in fixes_by_file.items():
                current_file_index += 1
                progress = int(current_file_index / total_files_to_modify * 100) if total_files_to_modify > 0 else 0
                self.after(0, lambda p=progress, fn=os.path.basename(file_path): self._update_progress_ui(f"Applying fixes to: {fn}", p))
                if self._apply_fixes_to_file(file_path, fixes):
                    applied_fixes += len(fixes)
                    files_modified.add(file_path)
            self.after(0, self._apply_fixes_complete, applied_fixes, len(files_modified))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Apply fixes failed: {str(e)}"))
            self.after(0, self._apply_fixes_complete, 0, 0)

    def _apply_fixes_to_file(self, file_path, fixes):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            original_content = content
            changes_made = 0
            for fix in fixes:
                old_include_escaped = re.escape(fix['old_include'])
                patterns = [re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('\\', '/'))), re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('/', '\\'))), re.compile(r'(#\s*include\s*)' + old_include_escaped)]
                replaced_this_fix = False
                for pattern in patterns:
                    if pattern.search(content):
                        new_content = pattern.sub(rf'\1{fix["new_include"]}', content, count=1)
                        if new_content != content:
                            content = new_content
                            changes_made += 1
                            print(f"Fixed in {file_path}: {fix['old_include']} -> {fix['new_include']} (Regex)")
                            replaced_this_fix = True
                            break
                if not replaced_this_fix:
                    if fix['old_include'] in content:
                        content = content.replace(fix['old_include'], fix['new_include'], 1)
                        changes_made += 1
                        print(f"Fixed in {file_path} (simple): {fix['old_include']} -> {fix['new_include']}")
            if changes_made > 0:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"Applied {changes_made} fixes to {file_path}")
            else:
                print(f"No changes applied to {file_path}")
            return changes_made > 0
        except Exception as e:
            print(f"Error applying fixes to {file_path}: {e}")
            return False

    def _apply_fixes_complete(self, applied_fixes, files_modified):
        self.applying_fixes = False
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set("Fixes applied")
        self.apply_btn.configure(state="normal")
        self.verify_btn.configure(state="normal")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"Fixes Applied:\n")
        self.results_text.insert("end", f"Applied {applied_fixes} fixes to {files_modified} files\n\n")
        if applied_fixes > 0:
            messagebox.showinfo("Fixes Applied", f"Successfully applied {applied_fixes} fixes to {files_modified} files.")
            self.results_text.insert("end", "Fixes have been applied successfully!\n")
            self.results_text.insert("end", "\nConsider running validation again to verify fixes.\n")
        else:
            self.results_text.insert("end", "No fixes were applied, or an error occurred.\n")

    def verify_fixes(self):
        if not self.fix_suggestions:
            messagebox.showwarning("Warning", "No fixes to verify. Please suggest fixes first.")
            return
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", "Verifying Fixes:\n\n")
        verifiable_fixes = 0
        problematic_fixes = 0
        fixes_by_file = {}
        for fix in self.fix_suggestions:
            file_path = fix['file_path']
            if file_path not in fixes_by_file:
                fixes_by_file[file_path] = []
            fixes_by_file[file_path].append(fix)
        total_files_to_verify = len(fixes_by_file)
        current_file_index = 0
        for file_path, fixes in fixes_by_file.items():
            current_file_index += 1
            progress = int(current_file_index / total_files_to_verify * 100) if total_files_to_verify > 0 else 0
            self.after(0, lambda p=progress, fn=os.path.basename(file_path): self._update_progress_ui(f"Verifying: {fn}", p))
            rel_path = os.path.relpath(file_path, self.project_root)
            self.results_text.insert("end", f"Checking file: {rel_path}\n")
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                for fix in fixes:
                    old_found = False
                    new_found = False
                    old_include_patterns = [re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('\\', '/'))), re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('/', '\\'))), re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include']))]
                    new_include_patterns = [re.compile(r'(#\s*include\s*)' + re.escape(fix['new_include'].replace('\\', '/'))), re.compile(r'(#\s*include\s*)' + re.escape(fix['new_include'].replace('/', '\\'))), re.compile(r'(#\s*include\s*)' + re.escape(fix['new_include']))]
                    for pattern in old_include_patterns:
                        if pattern.search(content):
                            old_found = True
                            break
                    for pattern in new_include_patterns:
                        if pattern.search(content):
                            new_found = True
                            break
                    if new_found and not old_found:
                        self.results_text.insert("end", f"  ✓ Fixed: '{fix['new_include']}' found, old not present.\n")
                        verifiable_fixes += 1
                    elif old_found:
                        self.results_text.insert("end", f"  ✗ NOT FIXED YET: '{fix['old_include']}' still present. New: '{fix['new_include']}'\n")
                        problematic_fixes += 1
                    else:
                        self.results_text.insert("end", f"  ? UNABLE TO VERIFY: Neither '{fix['old_include']}' nor '{fix['new_include']}' found.\n")
                        problematic_fixes += 1
            except Exception as e:
                self.results_text.insert("end", f"  ✗ Error reading file: {e}\n")
                problematic_fixes += 1
            self.results_text.insert("end", "\n")
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set("Verification complete")
        self.results_text.insert("end", f"Verification Summary:\n")
        self.results_text.insert("end", f"  Successfully verified fixes: {verifiable_fixes}\n")
        self.results_text.insert("end", f"  Potentially problematic or unverified: {problematic_fixes}\n")
        if problematic_fixes > 0:
            self.results_text.insert("end", f"\nSome fixes may not apply correctly or were already fixed manually. Consider:\n")
            self.results_text.insert("end", f"1. Re-scanning the project (files may have changed since suggestions were made)\n")
            self.results_text.insert("end", f"2. Manually reviewing the problematic files\n")

    def search_missing_files(self):
        if not self.missing_files_to_search:
            messagebox.showwarning("No Missing Files", "No missing user include files were identified in the last validation scan.")
            return
        response = messagebox.askyesno("Confirm Search", f"Start searching for {len(self.missing_files_to_search)} unique missing files?\n\nThis may take some time depending on your project size.")
        if not response:
            return
        self.searching_missing = True
        self.found_missing_paths = {}
        self.progress_var.set("Searching for missing files...")
        self.progress_bar.start()
        self.search_missing_btn.configure(state="disabled")
        self.scan_btn.configure(state="disabled")
        self.validate_btn.configure(state="disabled")
        self.suggest_btn.configure(state="disabled")
        self.apply_btn.configure(state="disabled")
        self.verify_btn.configure(state="disabled")
        thread = threading.Thread(target=self._search_missing_files_thread)
        thread.daemon = True
        thread.start()

    def _search_missing_files_thread(self):
        try:
            potential_found_paths: Dict[str, str] = {}
            all_potential_dirs = []
            for root, dirs, files in os.walk(self.project_root):
                all_potential_dirs.append(root)
            total_dirs_to_search = len(all_potential_dirs)
            missing_filenames = {Path(p).name.lower() for p in self.missing_files_to_search}
            found_count = 0
            searched_dirs_count = 0
            for current_dir in all_potential_dirs:
                searched_dirs_count += 1
                progress = int(searched_dirs_count / total_dirs_to_search * 100) if total_dirs_to_search > 0 else 0
                self.after(0, lambda p=progress, cd=os.path.basename(current_dir): self._update_progress_ui(f"Searching in: {cd}", p))
                for missing_include_path in list(self.missing_files_to_search):
                    missing_filename = Path(missing_include_path).name
                    potential_full_path = Path(current_dir) / missing_filename
                    if potential_full_path.exists() and potential_full_path.is_file():
                        rel_path_from_found_dir = str(potential_full_path.relative_to(current_dir)).replace('\\', '/')
                        if missing_include_path.endswith(rel_path_from_found_dir):
                            potential_found_paths[missing_include_path] = str(potential_full_path)
                            self.missing_files_to_search.remove(missing_include_path)
                            found_count += 1
                            print(f"Found '{missing_include_path}' at '{potential_full_path}'")
                            continue
                    for item in os.listdir(current_dir):
                        if os.path.isfile(os.path.join(current_dir, item)):
                            if item.lower() == missing_filename.lower():
                                actual_full_path = Path(current_dir) / item
                                rel_path_from_found_dir = str(actual_full_path.relative_to(current_dir)).replace('\\', '/')
                                if missing_include_path.lower().endswith(rel_path_from_found_dir.lower()):
                                    potential_found_paths[missing_include_path] = str(actual_full_path)
                                    self.missing_files_to_search.remove(missing_include_path)
                                    found_count += 1
                                    print(f"Found '{missing_include_path}' (case-insensitive) at '{actual_full_path}'")
                                    break
            self.found_missing_paths = potential_found_paths
            self.after(0, self._search_missing_files_complete, found_count)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Search for missing files failed: {str(e)}"))
            self.after(0, self._search_missing_files_complete, 0)

    def _search_missing_files_complete(self, found_count: int):
        self.searching_missing = False
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set("Search complete")
        self.search_missing_btn.configure(state="normal")
        self.scan_btn.configure(state="normal")
        self.validate_btn.configure(state="normal")
        self.suggest_btn.configure(state="normal")
        self.apply_btn.configure(state="normal")
        self.verify_btn.configure(state="normal")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", "Search for Missing Files Results:\n")
        self.results_text.insert("end", f"Found {found_count} out of {len(self.missing_files_to_search) + found_count} unique missing files.\n\n")
        if self.found_missing_paths:
            messagebox.showinfo("Search Complete", f"Found {found_count} potential paths for missing includes.")
            self.results_text.insert("end", "Potential include directories found:\n")
            dialog_paths = {}
            for missing_path, full_actual_path in self.found_missing_paths.items():
                missing_filename_parts = Path(missing_path).parts
                actual_filepath_parts = Path(full_actual_path).parts
                common_len = 0
                for i in range(1, min(len(missing_filename_parts), len(actual_filepath_parts)) + 1):
                    if missing_filename_parts[-i].lower() == actual_filepath_parts[-i].lower():
                        common_len = i
                    else:
                        break
                if common_len > 0:
                    target_include_dir_parts = actual_filepath_parts[:-common_len]
                    target_include_dir = os.path.join(*target_include_dir_parts)
                    if target_include_dir not in dialog_paths:
                        dialog_paths[target_include_dir] = []
                    dialog_paths[target_include_dir].append(missing_path)
            for path, solved_includes in dialog_paths.items():
                self.results_text.insert("end", f"  Directory: '{path}' (Solves: {', '.join(solved_includes)})\n")
            self.results_text.insert("end", "\nClick 'Add Selected Paths' to add these to custom include directories.\n")
            dialog = MissingFilesDialog(self, dialog_paths)
            self.wait_window(dialog.dialog)
            if dialog.result_paths:
                for path_to_add in dialog.result_paths:
                    if path_to_add not in self.custom_include_dirs:
                        self.custom_include_dirs.append(path_to_add)
                messagebox.showinfo("Paths Added", f"Successfully added {len(dialog.result_paths)} new include paths.")
                self.validate_includes()
            else:
                messagebox.showinfo("No Paths Added", "No new include paths were added.")
        else:
            self.results_text.insert("end", "No potential paths found for the missing include files.\n")
            self.results_text.insert("end", "You may need to manually locate these files or their containing directories.\n")

    def clear_and_rescan(self):
        if not self.project_root:
            messagebox.showerror("Error", "Please select a project root directory first.")
            return
        response = messagebox.askyesno("Confirm Clear & Re-scan", "This will clear all current results and re-scan the project.\n\nAre you sure you want to continue?")
        if response:
            self.reset_state()
            self.scan_includes()

    def set_include_paths(self):
        dialog = IncludePathDialog(self, self.custom_include_dirs)
        self.wait_window(dialog.dialog)
        if dialog.result:
            self.custom_include_dirs = dialog.result
            messagebox.showinfo("Success", f"Set {len(self.custom_include_dirs)} custom include paths")
            if self.include_paths:
                self.validate_includes()

class IncludePathDialog(customtkinter.CTkToplevel):
    def __init__(self, parent, current_paths):
        super().__init__(parent)
        self.result = None
        self.current_paths = current_paths[:]
        self.title("Set Include Paths")
        self.geometry("600x400")
        self.transient(parent)
        self.grab_set()
        self.create_widgets()

    def create_widgets(self):
        main_frame = customtkinter.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        customtkinter.CTkLabel(main_frame, text="Custom Include Search Paths (added to project root search):").pack(anchor="w")
        list_frame = customtkinter.CTkFrame(main_frame)
        list_frame.pack(fill="both", expand=True, pady=5)
        self.path_listbox = customtkinter.CTkTextbox(list_frame)
        self.path_listbox.pack(side="left", fill="both", expand=True)
        for path in self.current_paths:
            self.path_listbox.insert("end", path + "\n")
        btn_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=5)
        customtkinter.CTkButton(btn_frame, text="Add Path", command=self.add_path).pack(side="left", padx=5)
        customtkinter.CTkButton(btn_frame, text="Remove Selected", command=self.remove_path).pack(side="left", padx=5)
        customtkinter.CTkButton(btn_frame, text="Clear All", command=self.clear_paths).pack(side="left", padx=5)
        ok_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        ok_frame.pack(fill="x", pady=10)
        customtkinter.CTkButton(ok_frame, text="OK", command=self.ok_clicked).pack(side="right", padx=5)
        customtkinter.CTkButton(ok_frame, text="Cancel", command=self.cancel_clicked).pack(side="right", padx=5)

    def add_path(self):
        directory = filedialog.askdirectory(title="Select Include Directory")
        if directory:
            normalized_dir = os.path.normpath(directory)
            if normalized_dir not in self.current_paths:
                self.path_listbox.insert("end", normalized_dir + "\n")
                self.current_paths.append(normalized_dir)

    def remove_path(self):
        # This is more complex with CTkTextbox, so we'll just clear and re-add
        pass

    def clear_paths(self):
        self.path_listbox.delete(1.0, "end")
        self.current_paths.clear()

    def ok_clicked(self):
        self.result = [line.strip() for line in self.path_listbox.get(1.0, "end").splitlines() if line.strip()]
        self.destroy()

    def cancel_clicked(self):
        self.destroy()

class MissingFilesDialog(customtkinter.CTkToplevel):
    def __init__(self, parent, found_paths: Dict[str, List[str]]):
        super().__init__(parent)
        self.found_paths = found_paths
        self.result_paths: List[str] = []
        self.checkbox_vars: Dict[str, BooleanVar] = {}
        self.title("Add Found Include Paths")
        self.geometry("700x500")
        self.transient(parent)
        self.grab_set()
        self.create_widgets()

    def create_widgets(self):
        main_frame = customtkinter.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        customtkinter.CTkLabel(main_frame, text="Select directories to add to custom include paths:").pack(anchor="w", pady=5)
        scrollable_frame = customtkinter.CTkScrollableFrame(main_frame)
        scrollable_frame.pack(fill="both", expand=True, pady=5)
        for path, solved_includes in self.found_paths.items():
            var = BooleanVar(value=True)
            self.checkbox_vars[path] = var
            path_row_frame = customtkinter.CTkFrame(scrollable_frame, fg_color="transparent")
            path_row_frame.pack(fill="x", anchor="w")
            chk = customtkinter.CTkCheckBox(path_row_frame, variable=var, text="")
            chk.pack(side="left")
            path_text = f"'{path}' (Solves: {', '.join(solved_includes)})"
            customtkinter.CTkLabel(path_row_frame, text=path_text, wraplength=600).pack(side="left", anchor="w")
        btn_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=10)
        customtkinter.CTkButton(btn_frame, text="Add Selected Paths", command=self.add_selected_paths).pack(side="right", padx=5)
        customtkinter.CTkButton(btn_frame, text="Cancel", command=self.cancel_clicked).pack(side="right", padx=5)

    def add_selected_paths(self):
        self.result_paths = [path for path, var in self.checkbox_vars.items() if var.get()]
        self.destroy()

    def cancel_clicked(self):
        self.result_paths = []
        self.destroy()

def main():
    app = IncludePathFixer()
    app.mainloop()

if __name__ == "__main__":
    main()
