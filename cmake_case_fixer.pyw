#!/usr/bin/env python3
"""
CMake Path Case Sensitivity Fixer
==================================

A cross-platform GUI tool to scan, detect, and optionally fix case mismatches in CMake path references.

Features:
- Scans CMake files for path references.
- Detects case mismatches and missing paths.
- Suggests and applies fixes for case sensitivity issues.
- Useful for Windows/Linux/macOS projects.

Usage:
    python cmake_case_fixer.pyw
    # Follow the GUI instructions to select your project directory and fix issues.

Author: nayanrawat9
License: MIT
"""

import os
import re
import customtkinter
from tkinter import filedialog, messagebox, BooleanVar
from pathlib import Path
from datetime import datetime
import threading
import shutil
from typing import List, Dict, Tuple, Set

# --- Regex patterns for extracting paths from CMake files ---
PATH_PATTERNS = [
    r'add_subdirectory\s*\(([^)]+)\)',
    r'include_directories\s*\(([^)]+)\)',
    r'include\s*\(([^)]+)\)',
    r'set\s*\([^\s]+\s+"([^"]*?/[^\"]*)"',
    r'set\s*\([^\s]+\s+\$\{CMAKE_CURRENT_SOURCE_DIR\}([^)]+)',
    r'"([^"]*?/[^\"]*)"',
    r'"([^"]*?\\[^\"]*)"',
    r'\$\{CMAKE_CURRENT_SOURCE_DIR\}([^)]+)',
    r'\.\./[^\s)]+',
    r'\./[^\s)]+',
]

CMAKE_FILE_PATTERNS = ["CMakeLists.txt", ".cmake"]

class CMakePathFixer(customtkinter.CTk):
    def __init__(self):
        super().__init__()
        self.title("CMake Path Case Fixer")
        self.geometry("1000x700")

        # Data
        self.project_root = ""
        self.cmake_files: List[str] = []
        self.path_refs: List[Dict] = []  # Each: {file, line, raw, path, matchobj}
        self.mismatches: List[Dict] = []
        self.fix_suggestions: List[Dict] = []
        self.patterns = PATH_PATTERNS[:]

        self.create_widgets()

    def create_widgets(self):
        main_frame = customtkinter.CTkFrame(self)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)

        # Project selection
        customtkinter.CTkLabel(main_frame, text="Project Root Directory:").grid(row=0, column=0, sticky="w", pady=5)
        self.project_path_var = customtkinter.StringVar()
        customtkinter.CTkEntry(main_frame, textvariable=self.project_path_var, width=50).grid(row=0, column=1, sticky="ew", padx=5)
        customtkinter.CTkButton(main_frame, text="Browse", command=self.browse_project).grid(row=0, column=2, padx=5)

        # Buttons
        button_frame = customtkinter.CTkFrame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky="ew")
        self.scan_btn = customtkinter.CTkButton(button_frame, text="1. Scan CMake Files", command=self.scan_cmake)
        self.scan_btn.grid(row=0, column=0, padx=5, pady=5)
        self.validate_btn = customtkinter.CTkButton(button_frame, text="2. Validate Paths", command=self.validate_paths, state="disabled")
        self.validate_btn.grid(row=0, column=1, padx=5, pady=5)
        self.suggest_btn = customtkinter.CTkButton(button_frame, text="3. Suggest Fixes", command=self.suggest_fixes, state="disabled")
        self.suggest_btn.grid(row=0, column=2, padx=5, pady=5)
        self.apply_btn = customtkinter.CTkButton(button_frame, text="4. Apply Fixes", command=self.apply_fixes, state="disabled")
        self.apply_btn.grid(row=0, column=3, padx=5, pady=5)
        self.pattern_btn = customtkinter.CTkButton(button_frame, text="Set Patterns", command=self.set_patterns)
        self.pattern_btn.grid(row=0, column=4, padx=5, pady=5)

        # Progress
        self.progress_var = customtkinter.StringVar(value="Ready")
        customtkinter.CTkLabel(main_frame, textvariable=self.progress_var).grid(row=2, column=0, columnspan=3, pady=5)
        self.progress_bar = customtkinter.CTkProgressBar(main_frame, mode='determinate')
        self.progress_bar.grid(row=3, column=0, columnspan=3, sticky="ew", pady=5)
        self.progress_bar.set(0)

        # Results
        results_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        results_frame.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        self.results_text = customtkinter.CTkTextbox(results_frame, wrap="word", height=20)
        self.results_text.grid(row=0, column=0, sticky="nsew")
        self.fix_checkbox_frame = None

    def browse_project(self):
        directory = filedialog.askdirectory(title="Select Project Root Directory")
        if directory:
            self.project_path_var.set(directory)
            self.project_root = directory
            self.reset_state()

    def reset_state(self):
        self.cmake_files = []
        self.path_refs = []
        self.mismatches = []
        self.fix_suggestions = []
        self.validate_btn.configure(state="disabled")
        self.suggest_btn.configure(state="disabled")
        self.apply_btn.configure(state="disabled")
        self.results_text.delete(1.0, "end")
        self.progress_bar.set(0)
        self.progress_var.set("Ready")

    def scan_cmake(self):
        if not self.project_root:
            messagebox.showerror("Error", "Please select a project root directory first.")
            return
        self.progress_var.set("Scanning for CMake files...")
        self.progress_bar.start()
        self.scan_btn.configure(state="disabled")
        thread = threading.Thread(target=self._scan_cmake_thread)
        thread.daemon = True
        thread.start()

    def _scan_cmake_thread(self):
        try:
            self.cmake_files = []
            for root, dirs, files in os.walk(self.project_root):
                for file in files:
                    if any(file.endswith(pat) for pat in CMAKE_FILE_PATTERNS):
                        self.cmake_files.append(os.path.join(root, file))
            self.after(0, self._scan_cmake_complete)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
            self.after(0, self._scan_cmake_complete)

    def _scan_cmake_complete(self):
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set(f"Found {len(self.cmake_files)} CMake files.")
        self.scan_btn.configure(state="normal")
        if self.cmake_files:
            self.validate_btn.configure(state="normal")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"CMake Files Found ({len(self.cmake_files)}):\n")
        for f in self.cmake_files[:20]:
            self.results_text.insert("end", f"  {os.path.relpath(f, self.project_root)}\n")
        if len(self.cmake_files) > 20:
            self.results_text.insert("end", f"  ... and {len(self.cmake_files) - 20} more\n")

    def validate_paths(self):
        if not self.cmake_files:
            messagebox.showwarning("Warning", "No CMake files found. Please scan first.")
            return
        self.progress_var.set("Extracting and validating paths...")
        self.progress_bar.start()
        self.validate_btn.configure(state="disabled")
        thread = threading.Thread(target=self._validate_paths_thread)
        thread.daemon = True
        thread.start()

    def _validate_paths_thread(self):
        try:
            self.path_refs = []
            self.mismatches = []
            for file_path in self.cmake_files:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                for idx, line in enumerate(lines, 1):
                    for pat in self.patterns:
                        for match in re.finditer(pat, line):
                            raw = match.group(0)
                            path = match.groups()[-1] if match.groups() else raw
                            self.path_refs.append({
                                'file': file_path,
                                'line': idx,
                                'raw': raw,
                                'path': path.strip(),
                                'matchobj': match
                            })
            # Validate
            for ref in self.path_refs:
                resolved, exists, case_match, actual = self._validate_path(ref['file'], ref['path'])
                if not exists or not case_match:
                    self.mismatches.append({
                        **ref,
                        'resolved': resolved,
                        'exists': exists,
                        'case_match': case_match,
                        'actual': actual
                    })
            self.after(0, self._validate_paths_complete)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Validation failed: {str(e)}"))
            self.after(0, self._validate_paths_complete)

    def _validate_path(self, cmake_file, path):
        # Try to resolve path relative to cmake_file or project root
        if path.startswith("${CMAKE_CURRENT_SOURCE_DIR}"):
            rel = path.replace("${CMAKE_CURRENT_SOURCE_DIR}", "").lstrip("/\\")
            base = os.path.dirname(cmake_file)
            resolved = os.path.normpath(os.path.join(base, rel))
        elif path.startswith("./") or path.startswith("../"):
            base = os.path.dirname(cmake_file)
            resolved = os.path.normpath(os.path.join(base, path))
        else:
            resolved = os.path.normpath(os.path.join(self.project_root, path))
        exists = os.path.exists(resolved)
        case_match = True
        actual = None
        if exists:
            # Check case sensitivity by comparing each path part
            actual = self._get_actual_case(resolved)
            case_match = (actual == resolved)
        return resolved, exists, case_match, actual

    def _get_actual_case(self, path):
        # Returns the actual path as found on disk (with correct case)
        parts = Path(path).parts
        cur = Path(parts[0])
        for part in parts[1:]:
            if not cur.is_dir():
                break
            entries = os.listdir(cur)
            match = next((e for e in entries if e.lower() == part.lower()), part)
            cur = cur / match
        return str(cur)

    def _validate_paths_complete(self):
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set("Validation complete")
        self.validate_btn.configure(state="normal")
        if self.mismatches:
            self.suggest_btn.configure(state="normal")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"Validation Results:\n")
        self.results_text.insert("end", f"Total path refs: {len(self.path_refs)}\n")
        self.results_text.insert("end", f"Mismatches: {len(self.mismatches)}\n\n")
        for i, m in enumerate(self.mismatches[:30]):
            rel = os.path.relpath(m['file'], self.project_root)
            self.results_text.insert("end", f"{i+1}. {rel}:{m['line']}\n   Path: {m['path']}\n   Resolved: {m['resolved']}\n   Exists: {m['exists']}  Case match: {m['case_match']}\n")
            if m['actual'] and not m['case_match']:
                self.results_text.insert("end", f"   Actual: {m['actual']}\n")
            self.results_text.insert("end", "\n")
        if len(self.mismatches) > 30:
            self.results_text.insert("end", f"... and {len(self.mismatches)-30} more\n")

    def suggest_fixes(self):
        self.fix_suggestions = []
        for m in self.mismatches:
            if m['exists'] and not m['case_match'] and m['actual']:
                orig_path = m['path']
                actual_path = m['actual']
                if orig_path.startswith("${CMAKE_CURRENT_SOURCE_DIR}"):
                    var_prefix = "${CMAKE_CURRENT_SOURCE_DIR}"
                    orig_suffix = orig_path[len(var_prefix):]
                    corrected_suffix = self._get_corrected_cmake_suffix(orig_suffix, os.path.dirname(m['file']), actual_path)
                    new_path = f"{var_prefix}{corrected_suffix}"
                else:
                    new_path = self._relative_to_cmake(actual_path, m['file'])
                self.fix_suggestions.append({
                    'file': m['file'],
                    'line': m['line'],
                    'old': m['path'],
                    'new': new_path,
                    'raw': m['raw'],
                    'selected': BooleanVar(value=True)
                })
        self.apply_btn.configure(state="normal" if self.fix_suggestions else "disabled")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"Fix Suggestions ({len(self.fix_suggestions)}):\n\n")
        if self.fix_suggestions:
            self._open_fix_selection_dialog()

    def _open_fix_selection_dialog(self):
        dialog = customtkinter.CTkToplevel(self)
        dialog.title("Select Fixes to Apply")
        dialog.geometry("900x500")
        dialog.transient(self)
        dialog.grab_set()

        scrollable_frame = customtkinter.CTkScrollableFrame(dialog, label_text="Select fixes to apply")
        scrollable_frame.pack(fill="both", expand=True, padx=10, pady=10)

        for i, fix in enumerate(self.fix_suggestions):
            rel = os.path.relpath(fix['file'], self.project_root)
            text = f"{rel}:{fix['line']} | Old: {fix['old']} | New: {fix['new']}"
            cb = customtkinter.CTkCheckBox(scrollable_frame, text=text, variable=fix['selected'])
            cb.pack(anchor="w", pady=2, padx=10)

        btn_frame = customtkinter.CTkFrame(dialog)
        btn_frame.pack(fill="x", pady=10, padx=10)

        def ok():
            dialog.destroy()

        def cancel():
            for fix in self.fix_suggestions:
                fix['selected'].set(False)
            dialog.destroy()

        customtkinter.CTkButton(btn_frame, text="OK", command=ok).pack(side="right", padx=5)
        customtkinter.CTkButton(btn_frame, text="Cancel", command=cancel).pack(side="right", padx=5)


    def _get_corrected_cmake_suffix(self, orig_suffix, cmake_dir, actual_path):
        try:
            clean_suffix = orig_suffix.lstrip("/\\")
            orig_parts = clean_suffix.replace('\\', '/').split('/')
            actual_rel = os.path.relpath(actual_path, cmake_dir)
            actual_parts = actual_rel.replace('\\', '/').split('/')
            if len(orig_parts) == len(actual_parts):
                corrected_suffix = '/' + '/'.join(actual_parts)
            else:
                corrected_parts = []
                current_path = Path(cmake_dir)
                for orig_part in orig_parts:
                    if orig_part in ['..', '.']:
                        corrected_parts.append(orig_part)
                        if orig_part == '..':
                            current_path = current_path.parent
                    else:
                        if current_path.is_dir():
                            try:
                                entries = os.listdir(current_path)
                                correct_case = next((e for e in entries if e.lower() == orig_part.lower()), orig_part)
                                corrected_parts.append(correct_case)
                                current_path = current_path / correct_case
                            except (OSError, StopIteration):
                                corrected_parts.append(orig_part)
                                current_path = current_path / orig_part
                        else:
                            corrected_parts.append(orig_part)
                            current_path = current_path / orig_part
                corrected_suffix = '/' + '/'.join(corrected_parts)
            return corrected_suffix
        except Exception:
            return orig_suffix

    def _relative_to_cmake(self, actual_path, cmake_file):
        try:
            rel = os.path.relpath(actual_path, os.path.dirname(cmake_file))
            if not rel.startswith(".") and not rel.startswith(".."):
                rel = f"./{rel}"
            return rel.replace('\\', '/')
        except Exception:
            return actual_path.replace('\\', '/')

    def apply_fixes(self):
        selected_fixes = [fix for fix in self.fix_suggestions if fix['selected'].get()]
        if not selected_fixes:
            messagebox.showwarning("Warning", "No fixes selected to apply.")
            return
        if not messagebox.askyesno("Confirm Fixes", f"Apply {len(selected_fixes)} fixes?"):
            return
        self.progress_var.set("Applying fixes...")
        self.progress_bar.start()
        self.apply_btn.configure(state="disabled")
        thread = threading.Thread(target=self._apply_fixes_thread, args=(selected_fixes,))
        thread.daemon = True
        thread.start()

    def _apply_fixes_thread(self, selected_fixes):
        try:
            applied = 0
            files_modified = set()
            fixes_by_file = {}
            for fix in selected_fixes:
                fixes_by_file.setdefault(fix['file'], []).append(fix)
            for file_path, fixes in fixes_by_file.items():
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                changed = False
                for fix in fixes:
                    idx = fix['line'] - 1
                    if 0 <= idx < len(lines):
                        new_line = lines[idx].replace(fix['old'], fix['new'], 1)
                        if new_line != lines[idx]:
                            lines[idx] = new_line
                            changed = True
                            applied += 1
                if changed:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.writelines(lines)
                    files_modified.add(file_path)
            self.after(0, self._apply_fixes_complete, applied, len(files_modified))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Error", f"Apply fixes failed: {str(e)}"))
            self.after(0, self._apply_fixes_complete, 0, 0)

    def _apply_fixes_complete(self, applied, files_modified):
        self.progress_bar.stop()
        self.progress_bar.set(1)
        self.progress_var.set("Fixes applied")
        self.apply_btn.configure(state="normal")
        self.results_text.delete(1.0, "end")
        self.results_text.insert("end", f"Fixes Applied:\nApplied {applied} fixes to {files_modified} files\n\n")
        if applied > 0:
            messagebox.showinfo("Fixes Applied", f"Successfully applied {applied} fixes to {files_modified} files.")
            self.results_text.insert("end", "\nConsider running validation again to verify fixes.\n")
        else:
            self.results_text.insert("end", "No fixes were applied, or an error occurred.\n")

    def set_patterns(self):
        dialog = PatternDialog(self, self.patterns)
        self.wait_window(dialog)
        if dialog.result:
            self.patterns = dialog.result
            messagebox.showinfo("Patterns Updated", f"Set {len(self.patterns)} path patterns.")

class PatternDialog(customtkinter.CTkToplevel):
    def __init__(self, parent, current_patterns):
        super().__init__(parent)
        self.result = None
        self.current_patterns = current_patterns[:]
        self.title("Set Path Patterns")
        self.geometry("700x400")
        self.transient(parent)
        self.grab_set()
        self.create_widgets()

    def create_widgets(self):
        main_frame = customtkinter.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        customtkinter.CTkLabel(main_frame, text="Regex patterns for extracting paths from CMake files:").pack(anchor="w")
        self.text = customtkinter.CTkTextbox(main_frame, wrap="word", height=15)
        self.text.pack(fill="both", expand=True, pady=5)
        for pat in self.current_patterns:
            self.text.insert("end", pat + "\n")
        btn_frame = customtkinter.CTkFrame(main_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=10)
        customtkinter.CTkButton(btn_frame, text="OK", command=self.ok_clicked).pack(side="right", padx=5)
        customtkinter.CTkButton(btn_frame, text="Cancel", command=self.cancel_clicked).pack(side="right", padx=5)

    def ok_clicked(self):
        self.result = [line.strip() for line in self.text.get(1.0, "end").splitlines() if line.strip()]
        self.destroy()

    def cancel_clicked(self):
        self.destroy()

def main():
    app = CMakePathFixer()
    app.mainloop()

if __name__ == "__main__":
    main()
