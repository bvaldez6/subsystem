## Setup
### back end
- install `uv`
- `cd backend`
- `uv venv` to create a venv
- activate the venv:
  - macos / linux: `source .venv/bin/activate`
  - windows: `.venv\Scripts\Activate.ps1` or `.venv\Scripts\activate.bat`
- run `uv sync` to install project's python packages
- start the backend: (TODO: add command)

#### other `uv` tips:
- to install additional packages: `uv add <package>`
  - will keep track of it for you! no need to dump dependencies to `requirements.txt` like in `pip`
- remove a package: `uv remove <package>`
