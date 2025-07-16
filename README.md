# Cross-Platform Path Case Fixer

A set of GUI tools to scan, detect, and fix case sensitivity issues in CMake and C/C++ source file paths for cross-platform compatibility.

## Features
- **CMake Path Case Fixer**: Scans CMake files for path references, detects case mismatches, and suggests or applies fixes.
- **C/C++ Include Path Case Fixer**: Scans C/C++ source files for `#include` statements, validates include paths, and fixes case sensitivity issues.
- Easy-to-use graphical interface for both tools.
- Supports custom include directories and missing file search.

## Installation
1. Ensure you have Python 3 installed.
2. Install required dependencies (if any):
   ```sh
   pip install tkinter
   ```
   (Tkinter is usually included with Python, but you may need to install it separately on some systems.)

## Usage
### CMake Path Case Fixer
Run:
```sh
python cmake_case_fixer.pyw
```

### C/C++ Include Path Case Fixer
Run:
```sh
python source_case_fixer.pyw
```

Follow the GUI instructions to select your project directory, scan files, validate paths, and apply fixes.

## Contributing
Pull requests and suggestions are welcome! Please open an issue for bugs or feature requests.

## License
MIT License (see LICENSE file)

## Contact
For support or questions, open an issue on GitHub or contact the repository owner.

---

*Screenshots and more detailed usage instructions coming soon.*