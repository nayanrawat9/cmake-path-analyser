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
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import shutil
from datetime import datetime
from typing import List, Dict, Tuple, Set
import threading
import ctypes
ctypes.windll.shcore.SetProcessDpiAwareness(1)  # 1 = system DPI aware
ctypes.windll.shcore.SetProcessDpiAwareness(2)  # 2 = per-monitor DPI aware


class IncludePathFixer:
    def __init__(self, root):
        self.root = root
        self.root.title("C/C++ Include Path Case Fixer")
        self.root.geometry("1000x700")

        # Data storage
        self.project_root = ""
        self.include_paths = []  # List of (file_path, include_statement, line_number)
        self.validation_results = []  # List of validation results
        self.fix_suggestions = []  # List of suggested fixes
        self.custom_include_dirs = []  # Custom include search paths
        self.missing_files_to_search: Set[str] = set() # Stores unique missing include paths (e.g., "missing/file.h")
        self.found_missing_paths: Dict[str, str] = {} # Stores {missing_path_from_include: actual_found_full_path}

        # Create GUI
        self.create_widgets()

        # Status tracking
        self.scanning = False
        self.validating = False
        self.applying_fixes = False
        self.searching_missing = False

    def create_widgets(self):
        """Create the main GUI widgets."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)

        # Project selection
        ttk.Label(main_frame, text="Project Root Directory:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.project_path_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.project_path_var, width=50).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_project).grid(row=0, column=2, padx=5)

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E))

        # Main action buttons
        self.scan_btn = ttk.Button(button_frame, text="1. Scan for Includes", command=self.scan_includes)
        self.scan_btn.grid(row=0, column=0, padx=5, pady=5)

        self.validate_btn = ttk.Button(button_frame, text="2. Validate Include Paths", command=self.validate_includes, state=tk.DISABLED)
        self.validate_btn.grid(row=0, column=1, padx=5, pady=5)

        self.suggest_btn = ttk.Button(button_frame, text="3. Suggest Fixes", command=self.suggest_fixes, state=tk.DISABLED)
        self.suggest_btn.grid(row=0, column=2, padx=5, pady=5)

        self.apply_btn = ttk.Button(button_frame, text="4. Apply Fixes", command=self.apply_fixes, state=tk.DISABLED)
        self.apply_btn.grid(row=0, column=3, padx=5, pady=5)

        # Additional buttons
        self.verify_btn = ttk.Button(button_frame, text="Verify Fixes", command=self.verify_fixes, state=tk.DISABLED)
        self.verify_btn.grid(row=0, column=4, padx=5, pady=5)
        
        self.search_missing_btn = ttk.Button(button_frame, text="Search Missing Files", command=self.search_missing_files, state=tk.DISABLED)
        self.search_missing_btn.grid(row=0, column=5, padx=5, pady=5)

        self.include_paths_btn = ttk.Button(button_frame, text="Set Include Paths", command=self.set_include_paths)
        self.include_paths_btn.grid(row=0, column=6, padx=5, pady=5)
        
        # Second row of buttons
        self.clear_rescan_btn = ttk.Button(button_frame, text="Clear & Re-scan", command=self.clear_and_rescan)
        self.clear_rescan_btn.grid(row=1, column=0, padx=5, pady=5)

        # Progress bar
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(main_frame, textvariable=self.progress_var).grid(row=2, column=0, columnspan=3, pady=5)

        self.progress_bar = ttk.Progressbar(main_frame, mode='determinate') # Changed to determinate
        self.progress_bar.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        # Statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Statistics", padding="5")
        stats_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        self.stats_text = tk.StringVar(value="No scan performed yet")
        ttk.Label(stats_frame, textvariable=self.stats_text).grid(row=0, column=0, sticky=tk.W)

        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="5")
        options_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)

        # Removed backup_var and its Checkbutton
        self.system_includes_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Include system headers (<...>) in validation", variable=self.system_includes_var).grid(row=0, column=0, sticky=tk.W, padx=20)

        # Removed debug_var and its Checkbutton

        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="5")
        results_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, height=15)
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    def browse_project(self):
        """Browse for project root directory."""
        directory = filedialog.askdirectory(title="Select Project Root Directory")
        if directory:
            self.project_path_var.set(directory)
            self.project_root = directory
            self.reset_state()

    def reset_state(self):
        """Reset the tool state when a new project is selected."""
        self.include_paths = []
        self.validation_results = []
        self.fix_suggestions = []
        self.missing_files_to_search = set()
        self.found_missing_paths = {}
        self.validate_btn.config(state=tk.DISABLED)
        self.suggest_btn.config(state=tk.DISABLED)
        self.apply_btn.config(state=tk.DISABLED)
        self.verify_btn.config(state=tk.DISABLED)
        self.search_missing_btn.config(state=tk.DISABLED)
        self.stats_text.set("No scan performed yet")
        self.results_text.delete(1.0, tk.END)
        self.progress_bar.stop()
        self.progress_bar['value'] = 0
        self.progress_var.set("Ready")

    def scan_includes(self):
        """Scan for all include statements in the project."""
        if not self.project_root:
            messagebox.showerror("Error", "Please select a project root directory first.")
            return

        if not os.path.exists(self.project_root):
            messagebox.showerror("Error", "Selected directory does not exist.")
            return

        # Run scan in a separate thread to avoid GUI blocking
        self.scanning = True
        self.progress_var.set("Scanning for includes...")
        self.progress_bar.start()
        self.scan_btn.config(state=tk.DISABLED)
        self.validate_btn.config(state=tk.DISABLED)
        self.suggest_btn.config(state=tk.DISABLED)
        self.apply_btn.config(state=tk.DISABLED)
        self.verify_btn.config(state=tk.DISABLED)
        self.search_missing_btn.config(state=tk.DISABLED)

        thread = threading.Thread(target=self._scan_includes_thread)
        thread.daemon = True
        thread.start()

    def _scan_includes_thread(self):
        """Thread function for scanning includes."""
        try:
            self.include_paths = []
            c_extensions = {'.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hxx'}
            include_pattern = re.compile(r'^\s*#include\s*([<"][^<>"]+[>"])', re.MULTILINE)

            scanned_files_count = 0
            total_includes = 0
            
            # Get total files for progress bar
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
                    # Update progress bar
                    progress = int((i + 1) / total_files_to_scan * 100) if total_files_to_scan > 0 else 0
                    self.root.after(0, lambda p=progress, fn=os.path.basename(file_path): self._update_progress_ui(f"Scanning: {fn}", p))

                except Exception as e:
                    print(f"Error reading {file_path}: {e}")

            # Update UI on main thread
            self.root.after(0, self._scan_complete, scanned_files_count, total_includes)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
            self.root.after(0, self._scan_complete, 0, 0)

    def _scan_complete(self, scanned_files_count, total_includes):
        """Called when scan is complete."""
        self.scanning = False
        self.progress_bar.stop()
        self.progress_bar['value'] = 100
        self.progress_var.set("Scan complete")
        self.scan_btn.config(state=tk.NORMAL)

        if total_includes > 0:
            self.validate_btn.config(state=tk.NORMAL)

        # Update statistics
        unique_includes = len(set(include for _, include, _ in self.include_paths))
        self.stats_text.set(f"Scanned {scanned_files_count} files, found {total_includes} includes ({unique_includes} unique)")

        # Show results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Scan Results:\n")
        self.results_text.insert(tk.END, f"Files scanned: {scanned_files_count}\n")
        self.results_text.insert(tk.END, f"Total includes: {total_includes}\n")
        self.results_text.insert(tk.END, f"Unique includes: {unique_includes}\n\n")

        # Show sample includes
        if self.include_paths:
            self.results_text.insert(tk.END, "Sample includes found:\n")
            for i, (file_path, include, line_num) in enumerate(self.include_paths[:20]):
                rel_path = os.path.relpath(file_path, self.project_root)
                self.results_text.insert(tk.END, f"  {rel_path}:{line_num} -> {include}\n")
            if len(self.include_paths) > 20:
                self.results_text.insert(tk.END, f"  ... and {len(self.include_paths) - 20} more\n")
    
    def _update_progress_ui(self, message: str, percentage: int):
        self.progress_var.set(message)
        self.progress_bar['value'] = percentage


    def validate_includes(self):
        """Validate all found include paths."""
        if not self.include_paths:
            messagebox.showwarning("Warning", "No includes found. Please scan first.")
            return

        self.validating = True
        self.progress_var.set("Validating include paths...")
        self.progress_bar.start() # Use indeterminate for validation as total steps are not easily quantifiable
        self.validate_btn.config(state=tk.DISABLED)
        self.suggest_btn.config(state=tk.DISABLED)
        self.apply_btn.config(state=tk.DISABLED)
        self.verify_btn.config(state=tk.DISABLED)
        self.search_missing_btn.config(state=tk.DISABLED)


        thread = threading.Thread(target=self._validate_includes_thread)
        thread.daemon = True
        thread.start()

    def _validate_includes_thread(self):
        """Thread function for validating includes."""
        try:
            self.validation_results = []
            self.missing_files_to_search = set() # Clear previous missing files
            
            total_includes_to_validate = len(self.include_paths)
            for i, (file_path, include_stmt, line_num) in enumerate(self.include_paths):
                result = self._validate_single_include(file_path, include_stmt, line_num)
                self.validation_results.append(result)
                if not result['is_valid'] and not result['exists'] and not result['is_system']:
                    # Add to missing files set if it's a user include and doesn't exist
                    include_path = include_stmt[1:-1] # Remove " "
                    self.missing_files_to_search.add(include_path)
                
                # Update progress
                progress = int((i + 1) / total_includes_to_validate * 100) if total_includes_to_validate > 0 else 0
                self.root.after(0, lambda p=progress: self._update_progress_ui(f"Validating includes...", p))

            self.root.after(0, self._validation_complete)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Validation failed: {str(e)}"))
            self.root.after(0, self._validation_complete)

    def _validate_single_include(self, file_path, include_stmt, line_num):
        """Validate a single include statement."""
        result = {
            'file_path': file_path,
            'include_stmt': include_stmt,
            'line_num': line_num,
            'is_system': include_stmt.startswith('<'),
            'is_valid': True,
            'exists': False,
            'case_match': True,
            'actual_path': None,
            'suggested_fix': None
        }

        # Extract the include path
        include_path_str = include_stmt[1:-1]  # Remove < > or " "
        
        # Skip system includes unless explicitly requested
        if result['is_system'] and not self.system_includes_var.get():
            return result
            
        # For user includes, check if file exists
        if not result['is_system']:
            found = False
            # 1. Try relative to current file's directory
            current_dir = os.path.dirname(file_path)
            full_path_check = Path(current_dir) / include_path_str
            if full_path_check.exists():
                result['exists'] = True
                result['actual_path'] = str(full_path_check)
                # Check case sensitivity
                actual_name = os.path.basename(os.path.realpath(str(full_path_check)))
                expected_name = os.path.basename(include_path_str)
                result['case_match'] = actual_name == expected_name
                found = True
            
            if not found:
                # 2. Try searching in custom include directories and project root
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
            
            # 3. Check if this missing file was previously found and added as a custom include path
            if not found and include_path_str in self.found_missing_paths:
                # Re-validate against the known good path
                actual_full_path = self.found_missing_paths[include_path_str]
                if Path(actual_full_path).exists():
                    result['exists'] = True
                    result['actual_path'] = actual_full_path
                    actual_name = os.path.basename(os.path.realpath(actual_full_path))
                    expected_name = os.path.basename(include_path_str)
                    result['case_match'] = actual_name == expected_name
                    found = True # Found via previously identified path

        result['is_valid'] = result['exists'] and result['case_match']
        return result

    def _validation_complete(self):
        """Called when validation is complete."""
        self.validating = False
        self.progress_bar.stop()
        self.progress_bar['value'] = 100
        self.progress_var.set("Validation complete")
        self.validate_btn.config(state=tk.NORMAL)

        # Count results
        total = len(self.validation_results)
        valid = sum(1 for r in self.validation_results if r['is_valid'])
        invalid = total - valid
        case_issues = sum(1 for r in self.validation_results if r['exists'] and not r['case_match'])
        missing = sum(1 for r in self.validation_results if not r['exists'] and not r['is_system']) # Count only non-system missing

        if invalid > 0:
            self.suggest_btn.config(state=tk.NORMAL)
        if missing > 0:
            self.search_missing_btn.config(state=tk.NORMAL)

        # Update statistics
        self.stats_text.set(f"Validation: {valid}/{total} valid, {case_issues} case issues, {missing} missing (user includes)")

        # Show results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Validation Results:\n")
        self.results_text.insert(tk.END, f"Total includes: {total}\n")
        self.results_text.insert(tk.END, f"Valid: {valid}\n")
        self.results_text.insert(tk.END, f"Case sensitivity issues: {case_issues}\n")
        self.results_text.insert(tk.END, f"Missing user includes: {missing}\n\n")

        # Show problematic includes
        if invalid > 0:
            self.results_text.insert(tk.END, "Issues found:\n")
            for result in self.validation_results:
                if not result['is_valid'] and not result['is_system']: # Only show non-system issues
                    rel_path = os.path.relpath(result['file_path'], self.project_root)
                    issue_type = "MISSING" if not result['exists'] else "CASE"
                    issue_number = sum(
                        1 for r in self.validation_results[:self.validation_results.index(result) + 1]
                        if not r['is_valid'] and not r['is_system']
                    )
                    self.results_text.insert(
                        tk.END,
                        f"  {issue_number}. [{issue_type}] {rel_path}:{result['line_num']} -> {result['include_stmt']}\n"
                    )
        else:
            self.results_text.insert(tk.END, "No issues found in user includes.\n")

    def suggest_fixes(self):
        """Suggest fixes for validation issues."""
        if not self.validation_results:
            messagebox.showwarning("Warning", "No validation results. Please validate first.")
            return

        self.fix_suggestions = []

        for result in self.validation_results:
            if not result['is_valid'] and result['exists'] and not result['case_match']:
                # We can fix case sensitivity issues
                fix = self._suggest_case_fix(result)
                if fix:
                    self.fix_suggestions.append(fix)

        if self.fix_suggestions:
            self.apply_btn.config(state=tk.NORMAL)
            self.verify_btn.config(state=tk.NORMAL)
        else:
            self.apply_btn.config(state=tk.DISABLED)
            self.verify_btn.config(state=tk.DISABLED)


        # Show suggestions
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Fix Suggestions:\n")
        self.results_text.insert(tk.END, f"Fixable issues (case sensitivity): {len(self.fix_suggestions)}\n\n")
        
        if len(self.fix_suggestions) == 0:
            self.results_text.insert(tk.END, "No case sensitivity issues found that can be automatically fixed.\n")
            self.results_text.insert(tk.END, "Consider using 'Search Missing Files' for missing include paths.\n")
            return

        for fix in self.fix_suggestions:
            rel_path = os.path.relpath(fix['file_path'], self.project_root)
            self.results_text.insert(tk.END, f"File: {rel_path}:{fix['line_num']}\n")
            self.results_text.insert(tk.END, f"  Current: {fix['old_include']}\n")
            self.results_text.insert(tk.END, f"  Fixed:   {fix['new_include']}\n")

            # Show debug info if enabled
            # Removed debug_var.get()
            self.results_text.insert(tk.END, "\n")

    def _get_line_context(self, file_path, line_num):
        """Get the actual line content for debugging."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            if line_num <= len(lines):
                actual_line = lines[line_num - 1].strip()
                return f"Actual line: '{actual_line}'"
            else:
                return f"Line {line_num} not found (file has {len(lines)} lines)"

        except Exception as e:
            return f"Error reading line: {e}"

    def _suggest_case_fix(self, result):
        """Suggest a case sensitivity fix for a validation result."""
        if not result['actual_path']:
            return None

        # Get the actual filename with correct case
        actual_name = os.path.basename(os.path.realpath(result['actual_path']))
        include_path = result['include_stmt'][1:-1]  # Remove quotes/brackets

        # Replace the filename part with the correct case
        # Handle both Windows and Unix style paths
        path_parts = re.split(r'[/\\]', include_path)
        path_parts[-1] = actual_name
        
        # Determine original separator and use it
        if '/' in include_path:
            corrected_path = '/'.join(path_parts)
        elif '\\' in include_path:
            corrected_path = '\\'.join(path_parts)
        else: # Single file, no path separators
            corrected_path = actual_name

        # Reconstruct the include statement
        bracket_char = '<' if result['is_system'] else '"'
        close_bracket = '>' if result['is_system'] else '"'
        new_include = f"{bracket_char}{corrected_path}{close_bracket}"

        return {
            'file_path': result['file_path'],
            'line_num': result['line_num'],
            'old_include': result['include_stmt'],
            'new_include': new_include
        }

    def apply_fixes(self):
        """Apply all suggested fixes."""
        if not self.fix_suggestions:
            messagebox.showwarning("Warning", "No fixes to apply. Please suggest fixes first.")
            return

        # Confirm with user (removed backup info)
        response = messagebox.askyesno("Confirm Fixes",
            f"Apply {len(self.fix_suggestions)} fixes?")

        if not response:
            return

        self.applying_fixes = True
        self.progress_var.set("Applying fixes...")
        self.progress_bar.start()
        self.apply_btn.config(state=tk.DISABLED)

        thread = threading.Thread(target=self._apply_fixes_thread)
        thread.daemon = True
        thread.start()

    def _apply_fixes_thread(self):
        """Thread function for applying fixes."""
        try:
            applied_fixes = 0
            files_modified = set()

            # Group fixes by file
            fixes_by_file = {}
            for fix in self.fix_suggestions:
                file_path = fix['file_path']
                if file_path not in fixes_by_file:
                    fixes_by_file[file_path] = []
                fixes_by_file[file_path].append(fix)
            
            total_files_to_modify = len(fixes_by_file)
            current_file_index = 0

            # Apply fixes file by file
            for file_path, fixes in fixes_by_file.items():
                current_file_index += 1
                progress = int(current_file_index / total_files_to_modify * 100) if total_files_to_modify > 0 else 0
                self.root.after(0, lambda p=progress, fn=os.path.basename(file_path): self._update_progress_ui(f"Applying fixes to: {fn}", p))

                if self._apply_fixes_to_file(file_path, fixes):
                    applied_fixes += len(fixes)
                    files_modified.add(file_path)

            self.root.after(0, self._apply_fixes_complete, applied_fixes, len(files_modified))

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Apply fixes failed: {str(e)}"))
            self.root.after(0, self._apply_fixes_complete, 0, 0)

    def _apply_fixes_to_file(self, file_path, fixes):
        """Apply fixes to a single file."""
        try:
            # Removed backup creation code
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            original_content = content
            changes_made = 0

            for fix in fixes:
                # Create a more specific pattern to match the include statement
                old_include_escaped = re.escape(fix['old_include'])

                # Pattern to match #include followed by the old include path
                # This pattern is more robust to variations in whitespace and path separators
                patterns = [
                    re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('\\', '/'))), # Standard with /
                    re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('/', '\\'))), # Standard with \
                    re.compile(r'(#\s*include\s*)' + old_include_escaped), # Original escaped
                ]
                
                replaced_this_fix = False
                for pattern in patterns:
                    if pattern.search(content):
                        new_content = pattern.sub(rf'\1{fix["new_include"]}', content, count=1) # Replace only first occurrence
                        if new_content != content:
                            content = new_content
                            changes_made += 1
                            # Removed debug_var.get()
                            print(f"Fixed in {file_path}: {fix['old_include']} -> {fix['new_include']} (Regex)")
                            replaced_this_fix = True
                            break
                
                if not replaced_this_fix:
                    # Fallback to simple string replace if regex didn't work, though less precise
                    # This is a last resort and might have unintended side effects
                    if fix['old_include'] in content:
                        content = content.replace(fix['old_include'], fix['new_include'], 1) # Replace only first
                        changes_made += 1
                        # Removed debug_var.get()
                        print(f"Fixed in {file_path} (simple): {fix['old_include']} -> {fix['new_include']}")

            # Only write back if we made changes
            if changes_made > 0:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                # Removed debug_var.get()
                print(f"Applied {changes_made} fixes to {file_path}")
            else:
                # Removed debug_var.get()
                print(f"No changes applied to {file_path}")

            return changes_made > 0

        except Exception as e:
            print(f"Error applying fixes to {file_path}: {e}")
            return False

    def _apply_fixes_complete(self, applied_fixes, files_modified):
        """Called when applying fixes is complete."""
        self.applying_fixes = False
        self.progress_bar.stop()
        self.progress_bar['value'] = 100
        self.progress_var.set("Fixes applied")
        self.apply_btn.config(state=tk.NORMAL)
        self.verify_btn.config(state=tk.NORMAL)

        # Show results
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Fixes Applied:\n")
        self.results_text.insert(tk.END, f"Applied {applied_fixes} fixes to {files_modified} files\n\n")

        if applied_fixes > 0:
            messagebox.showinfo("Fixes Applied", f"Successfully applied {applied_fixes} fixes to {files_modified} files.")
            self.results_text.insert(tk.END, "Fixes have been applied successfully!\n")
            # Removed backup info
            self.results_text.insert(tk.END, "\nConsider running validation again to verify fixes.\n")
        else:
            self.results_text.insert(tk.END, "No fixes were applied, or an error occurred.\n")

    def verify_fixes(self):
        """Verify that the suggested fixes can be applied by checking the actual file content."""
        if not self.fix_suggestions:
            messagebox.showwarning("Warning", "No fixes to verify. Please suggest fixes first.")
            return

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Verifying Fixes:\n\n")

        verifiable_fixes = 0
        problematic_fixes = 0

        # Group fixes by file to avoid reading the same file multiple times
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
            self.root.after(0, lambda p=progress, fn=os.path.basename(file_path): self._update_progress_ui(f"Verifying: {fn}", p))

            rel_path = os.path.relpath(file_path, self.project_root)
            self.results_text.insert(tk.END, f"Checking file: {rel_path}\n")

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for fix in fixes:
                    # Check if the old include exists anywhere in the file (considering variations)
                    # And check if the new include already exists (meaning it was fixed)
                    old_found = False
                    new_found = False

                    # Patterns for old include
                    old_include_patterns = [
                        re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('\\', '/'))),
                        re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'].replace('/', '\\'))),
                        re.compile(r'(#\s*include\s*)' + re.escape(fix['old_include'])),
                    ]
                    
                    # Patterns for new include
                    new_include_patterns = [
                        re.compile(r'(#\s*include\s*)' + re.escape(fix['new_include'].replace('\\', '/'))),
                        re.compile(r'(#\s*include\s*)' + re.escape(fix['new_include'].replace('/', '\\'))),
                        re.compile(r'(#\s*include\s*)' + re.escape(fix['new_include'])),
                    ]

                    for pattern in old_include_patterns:
                        if pattern.search(content):
                            old_found = True
                            break
                    
                    for pattern in new_include_patterns:
                        if pattern.search(content):
                            new_found = True
                            break

                    if new_found and not old_found:
                        self.results_text.insert(tk.END, f"  ✓ Fixed: '{fix['new_include']}' found, old not present.\n")
                        verifiable_fixes += 1
                    elif old_found:
                        self.results_text.insert(tk.END, f"  ✗ NOT FIXED YET: '{fix['old_include']}' still present. New: '{fix['new_include']}'\n")
                        problematic_fixes += 1
                    else: # Neither old nor new found
                        self.results_text.insert(tk.END, f"  ? UNABLE TO VERIFY: Neither '{fix['old_include']}' nor '{fix['new_include']}' found.\n")
                        problematic_fixes += 1
                        
                    # Removed debug_var.get()

            except Exception as e:
                self.results_text.insert(tk.END, f"  ✗ Error reading file: {e}\n")
                problematic_fixes += 1

            self.results_text.insert(tk.END, "\n")
            
        self.progress_bar.stop()
        self.progress_bar['value'] = 100
        self.progress_var.set("Verification complete")

        self.results_text.insert(tk.END, f"Verification Summary:\n")
        self.results_text.insert(tk.END, f"  Successfully verified fixes: {verifiable_fixes}\n")
        self.results_text.insert(tk.END, f"  Potentially problematic or unverified: {problematic_fixes}\n")

        if problematic_fixes > 0:
            self.results_text.insert(tk.END, f"\nSome fixes may not apply correctly or were already fixed manually. Consider:\n")
            self.results_text.insert(tk.END, f"1. Re-scanning the project (files may have changed since suggestions were made)\n")
            self.results_text.insert(tk.END, f"2. Manually reviewing the problematic files\n")
            
    def search_missing_files(self):
        """Searches for missing include files identified during validation."""
        if not self.missing_files_to_search:
            messagebox.showwarning("No Missing Files", "No missing user include files were identified in the last validation scan.")
            return

        response = messagebox.askyesno("Confirm Search", 
            f"Start searching for {len(self.missing_files_to_search)} unique missing files?\n\n"
            "This may take some time depending on your project size.")
        
        if not response:
            return

        self.searching_missing = True
        self.found_missing_paths = {} # Reset found paths
        self.progress_var.set("Searching for missing files...")
        self.progress_bar.start() # Start indeterminate, will switch to determinate if total dirs are known
        self.search_missing_btn.config(state=tk.DISABLED)
        self.scan_btn.config(state=tk.DISABLED)
        self.validate_btn.config(state=tk.DISABLED)
        self.suggest_btn.config(state=tk.DISABLED)
        self.apply_btn.config(state=tk.DISABLED)
        self.verify_btn.config(state=tk.DISABLED)
        
        thread = threading.Thread(target=self._search_missing_files_thread)
        thread.daemon = True
        thread.start()

    def _search_missing_files_thread(self):
        """Thread function to search for missing files."""
        try:
            potential_found_paths: Dict[str, str] = {} # {missing_include_path_from_stmt: actual_full_path_found}
            
            # Create a list of directories to search in
            # Start with project root, then its subdirectories
            search_dirs_queue = [self.project_root]
            searched_dirs = set()
            
            all_potential_dirs = []
            for root, dirs, files in os.walk(self.project_root):
                all_potential_dirs.append(root)
            
            total_dirs_to_search = len(all_potential_dirs)
            
            # Convert missing files to just their filenames for easier searching
            missing_filenames = {Path(p).name.lower() for p in self.missing_files_to_search}
            
            found_count = 0
            searched_dirs_count = 0

            for current_dir in all_potential_dirs:
                searched_dirs_count += 1
                if current_dir in searched_dirs:
                    continue
                searched_dirs.add(current_dir)
                
                # Update progress
                progress = int(searched_dirs_count / total_dirs_to_search * 100) if total_dirs_to_search > 0 else 0
                self.root.after(0, lambda p=progress, cd=os.path.basename(current_dir): self._update_progress_ui(f"Searching in: {cd}", p))

                # Iterate through missing files and check for their existence in current_dir
                for missing_include_path in list(self.missing_files_to_search): # Use list to allow modification of set
                    missing_filename = Path(missing_include_path).name
                    
                    # Try direct match
                    potential_full_path = Path(current_dir) / missing_filename
                    if potential_full_path.exists() and potential_full_path.is_file():
                        # Found a direct match, but need to check if the relative path from current_dir matches
                        # the expected path structure of the original include statement.
                        # E.g., if #include "dir/file.h" and we found /path/to/dir/file.h, then /path/to/dir is the base.
                        # So, check if 'missing_include_path' ends with 'rel_path_from_current_dir'
                        rel_path_from_found_dir = str(potential_full_path.relative_to(current_dir)).replace('\\', '/')
                        if missing_include_path.endswith(rel_path_from_found_dir):
                            potential_found_paths[missing_include_path] = str(potential_full_path)
                            self.missing_files_to_search.remove(missing_include_path) # Remove from set to avoid re-searching
                            found_count += 1
                            print(f"Found '{missing_include_path}' at '{potential_full_path}'")
                            continue # Move to next missing_include_path
                    
                    # If not found directly, try case-insensitive search for the filename
                    # This is more expensive, do it only if direct match fails.
                    for item in os.listdir(current_dir):
                        if os.path.isfile(os.path.join(current_dir, item)):
                            if item.lower() == missing_filename.lower():
                                # Found a case-insensitive match for the filename.
                                # Now construct the full path and check if the relative path matches.
                                actual_full_path = Path(current_dir) / item
                                rel_path_from_found_dir = str(actual_full_path.relative_to(current_dir)).replace('\\', '/')
                                
                                # Compare the 'tail' of the missing include path with the actual filename found
                                # E.g., for missing "path/to/File.h" and found "file.h" in "path/to"
                                # We need to ensure that the original "path/to/File.h" maps to this "path/to/file.h"
                                # This is a heuristic, and might not always be perfect for complex nested includes.
                                # The goal is to find a directory that, if added to include paths, would resolve the original include.
                                
                                # A more robust check: does original_include_path (case-insensitive) end with actual_relative_path?
                                if missing_include_path.lower().endswith(rel_path_from_found_dir.lower()):
                                    potential_found_paths[missing_include_path] = str(actual_full_path)
                                    self.missing_files_to_search.remove(missing_include_path)
                                    found_count += 1
                                    print(f"Found '{missing_include_path}' (case-insensitive) at '{actual_full_path}'")
                                    break # Break from inner loop (found for this missing file)

            self.found_missing_paths = potential_found_paths # Store the results
            self.root.after(0, self._search_missing_files_complete, found_count)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Search for missing files failed: {str(e)}"))
            self.root.after(0, self._search_missing_files_complete, 0)

    def _search_missing_files_complete(self, found_count: int):
        """Called when search for missing files is complete."""
        self.searching_missing = False
        self.progress_bar.stop()
        self.progress_bar['value'] = 100
        self.progress_var.set("Search complete")
        self.search_missing_btn.config(state=tk.NORMAL)
        self.scan_btn.config(state=tk.NORMAL)
        self.validate_btn.config(state=tk.NORMAL)
        self.suggest_btn.config(state=tk.NORMAL)
        self.apply_btn.config(state=tk.NORMAL)
        self.verify_btn.config(state=tk.NORMAL)

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "Search for Missing Files Results:\n")
        self.results_text.insert(tk.END, f"Found {found_count} out of {len(self.missing_files_to_search) + found_count} unique missing files.\n\n")

        if self.found_missing_paths:
            messagebox.showinfo("Search Complete", f"Found {found_count} potential paths for missing includes.")
            self.results_text.insert(tk.END, "Potential include directories found:\n")
            
            # Prepare paths for the dialog
            dialog_paths = {} # {actual_parent_dir: [list of missing_include_paths_it_solves]}
            for missing_path, full_actual_path in self.found_missing_paths.items():
                # The directory to be added to include paths is the parent directory of the found file
                # relative to the structure of the missing_path
                
                # Example: missing_path = "subdir/header.h", full_actual_path = "/a/b/c/subdir/header.h"
                # The include path to add should be "/a/b/c"
                
                # Get the part of the missing_path that is the file name
                missing_filename_parts = Path(missing_path).parts
                actual_filepath_parts = Path(full_actual_path).parts

                # Find the common suffix to determine the actual base directory to add
                common_len = 0
                for i in range(1, min(len(missing_filename_parts), len(actual_filepath_parts)) + 1):
                    if missing_filename_parts[-i].lower() == actual_filepath_parts[-i].lower():
                        common_len = i
                    else:
                        break
                
                # The actual base directory to add is the path up to (but not including) the common suffix
                if common_len > 0:
                    target_include_dir_parts = actual_filepath_parts[:-common_len]
                    target_include_dir = os.path.join(*target_include_dir_parts)
                    
                    if target_include_dir not in dialog_paths:
                        dialog_paths[target_include_dir] = []
                    dialog_paths[target_include_dir].append(missing_path)

            for path, solved_includes in dialog_paths.items():
                self.results_text.insert(tk.END, f"  Directory: '{path}' (Solves: {', '.join(solved_includes)})\n")
            
            self.results_text.insert(tk.END, "\nClick 'Add Selected Paths' to add these to custom include directories.\n")
            
            # Open the dialog to let the user select paths
            dialog = MissingFilesDialog(self.root, dialog_paths)
            self.root.wait_window(dialog.dialog)
            
            if dialog.result_paths:
                for path_to_add in dialog.result_paths:
                    if path_to_add not in self.custom_include_dirs:
                        self.custom_include_dirs.append(path_to_add)
                messagebox.showinfo("Paths Added", f"Successfully added {len(dialog.result_paths)} new include paths.")
                # After adding paths, it's a good idea to re-validate
                self.validate_includes()
            else:
                messagebox.showinfo("No Paths Added", "No new include paths were added.")

        else:
            self.results_text.insert(tk.END, "No potential paths found for the missing include files.\n")
            self.results_text.insert(tk.END, "You may need to manually locate these files or their containing directories.\n")

    def clear_and_rescan(self):
        """Clear all results and re-scan the project."""
        if not self.project_root:
            messagebox.showerror("Error", "Please select a project root directory first.")
            return

        response = messagebox.askyesno("Confirm Clear & Re-scan",
            "This will clear all current results and re-scan the project.\n\n"
            "Are you sure you want to continue?")

        if response:
            self.reset_state()
            self.scan_includes()

    def set_include_paths(self):
        """Set custom include search paths."""
        dialog = IncludePathDialog(self.root, self.custom_include_dirs)
        self.root.wait_window(dialog.dialog)

        if dialog.result:
            self.custom_include_dirs = dialog.result
            messagebox.showinfo("Success", f"Set {len(self.custom_include_dirs)} custom include paths")
            # If custom include paths changed, re-validate to see effect
            if self.include_paths:
                self.validate_includes()


class IncludePathDialog:
    def __init__(self, parent, current_paths):
        self.result = None
        self.current_paths = current_paths[:]

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Set Include Paths")
        self.dialog.geometry("600x400")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (400 // 2)
        self.dialog.geometry(f"600x400+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Custom Include Search Paths (added to project root search):").pack(anchor=tk.W)

        # Listbox with scrollbar
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.path_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        self.path_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.path_listbox.yview)

        # Populate with current paths
        for path in self.current_paths:
            self.path_listbox.insert(tk.END, path)

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, text="Add Path", command=self.add_path).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove Selected", command=self.remove_path).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear All", command=self.clear_paths).pack(side=tk.LEFT, padx=5)

        # OK/Cancel buttons
        ok_frame = ttk.Frame(main_frame)
        ok_frame.pack(fill=tk.X, pady=10)

        ttk.Button(ok_frame, text="OK", command=self.ok_clicked).pack(side=tk.RIGHT, padx=5)
        ttk.Button(ok_frame, text="Cancel", command=self.cancel_clicked).pack(side=tk.RIGHT, padx=5)

    def add_path(self):
        directory = filedialog.askdirectory(title="Select Include Directory")
        if directory:
            # Normalize path to ensure consistency (e.g., / vs \)
            normalized_dir = os.path.normpath(directory)
            if normalized_dir not in self.current_paths:
                self.path_listbox.insert(tk.END, normalized_dir)
                self.current_paths.append(normalized_dir)

    def remove_path(self):
        selection = self.path_listbox.curselection()
        if selection:
            index = selection[0]
            self.path_listbox.delete(index)
            del self.current_paths[index]

    def clear_paths(self):
        self.path_listbox.delete(0, tk.END)
        self.current_paths.clear()

    def ok_clicked(self):
        self.result = self.current_paths[:]
        self.dialog.destroy()

    def cancel_clicked(self):
        self.dialog.destroy()


class MissingFilesDialog:
    def __init__(self, parent, found_paths: Dict[str, List[str]]):
        # found_paths: {actual_parent_dir: [list of missing_include_paths_it_solves]}
        self.found_paths = found_paths
        self.result_paths: List[str] = [] # Paths selected by the user to be added
        self.checkbox_vars: Dict[str, tk.BooleanVar] = {} # {path: BooleanVar}

        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Add Found Include Paths")
        self.dialog.geometry("700x500")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (700 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (500 // 2)
        self.dialog.geometry(f"700x500+{x}+{y}")

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.dialog, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Select directories to add to custom include paths:").pack(anchor=tk.W, pady=5)

        # Frame for checkboxes with scrollbar
        checkbox_frame = ttk.Frame(main_frame)
        checkbox_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        canvas = tk.Canvas(checkbox_frame)
        scrollbar = ttk.Scrollbar(checkbox_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Populate with found paths and checkboxes
        for path, solved_includes in self.found_paths.items():
            var = tk.BooleanVar(value=True) # Default to true
            self.checkbox_vars[path] = var
            
            # Create a frame for each path to group checkbox and label
            path_row_frame = ttk.Frame(scrollable_frame, padding=(0,2))
            path_row_frame.pack(fill=tk.X, anchor=tk.W)

            chk = ttk.Checkbutton(path_row_frame, variable=var)
            chk.pack(side=tk.LEFT)
            
            # Use a label for the path and the list of solved includes
            path_text = f"'{path}' (Solves: {', '.join(solved_includes)})"
            ttk.Label(path_row_frame, text=path_text, wraplength=600).pack(side=tk.LEFT, anchor=tk.W)


        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Add Selected Paths", command=self.add_selected_paths).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.cancel_clicked).pack(side=tk.RIGHT, padx=5)

    def add_selected_paths(self):
        self.result_paths = [path for path, var in self.checkbox_vars.items() if var.get()]
        self.dialog.destroy()

    def cancel_clicked(self):
        self.result_paths = [] # No paths selected
        self.dialog.destroy()


def main():
    root = tk.Tk()
    app = IncludePathFixer(root)
    root.mainloop()


if __name__ == "__main__":
    main()