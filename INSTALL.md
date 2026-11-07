# Installation guide

Requires Python 3.10+ and Git. No third-party runtime dependencies. Use the repository URL below rather than `pip install skillcheck` (no PyPI publication is implied).

## Linux / macOS

```sh
python3 --version
python3 -m venv .venv
. .venv/bin/activate
python -m pip install git+https://github.com/masterxhackerx420-oss/skillcheck.git
skillcheck --version
skillcheck /path/to/skill
```

On Debian/Ubuntu, if venv is unavailable, install your distribution's `python3-venv` package. macOS users can install a current Python from python.org or their package manager.

## Windows (PowerShell)

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install git+https://github.com/masterxhackerx420-oss/skillcheck.git
.\.venv\Scripts\skillcheck.exe --version
.\.venv\Scripts\skillcheck.exe C:\path\to\skill
```

No PowerShell execution-policy change or activation is needed. Install Python from python.org and Git from git-scm.com if commands are missing; select a Python version at least 3.10.

## Local source and tests (all platforms)

Download the repository ZIP or clone it into a new directory, then open that directory in a terminal. Create a venv as above. With its Python (activated `python`, or `.\.venv\Scripts\python.exe` on Windows):

```sh
python -m pip install .
python -m unittest discover -s tests -v
python -m skillcheck examples/clean
python -m skillcheck examples/suspicious --json
```

The suspicious fixture is inert text for testing, not a script to execute. Scans are offline, but installation may download setuptools/build tooling. `python -m skillcheck` is interchangeable with the console command. Quote paths containing spaces.

## Reports and exit codes

`--json` writes a parseable JSON report to stdout, including scan errors. Exit 0: no findings in scanned content; exit 1: findings; exit 2: invalid path/input or a scan failure. Skipped entries are always listed and counted. No findings is not a safety guarantee; read the [limits and rules](README.md).

To uninstall, use the venv's `python -m pip uninstall skillcheck`. The app never modifies the files it scans.
