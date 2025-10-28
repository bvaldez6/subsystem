## Project Architecture
### back end
The back end is structured like so (credits to Ruben Martinez for the inspiration):

- `services/`: 
  - contains a python file containing all the classes / functions / etc. needed for each back-end module (e.g. tools hander)
  - can also contain subfolders when it makes sense. for example, we're putting all "tool" logic in a "tools" subfolder
  - `tools/`
    - `<superclass for all tools>.py`
    - `grype_interfacer.py`
    - `<other tool>_interfacer.py`
  - `database_hander.py`
  - ...
- `routes/`: contains a file for every back-end module linking each route for its respective functions
  - for example, you could have a `grype_routes.py` that links endpoints under `/tools/grype/*` to their respective functions under the `services/tools/` directory.

#### formatting
- ALL python files should `snake_case.py`
- try to use the "Black" formatter before committing code

### front end
TODO:

## Development Setup
### back end
- install `uv`
- `cd backend`
- `uv venv` to create a venv
- activate the venv:
  - macos / linux: `source .venv/bin/activate`
  - windows: `.venv\Scripts\Activate.ps1` or `.venv\Scripts\activate.bat`
- run `uv sync` to install project's python packages
- start the backend: `fastapi dev main.py`

#### other `uv` tips:
- to install additional packages: `uv add <package>`
  - will keep track of it for you! no need to dump dependencies to `requirements.txt` like in `pip`
- remove a package: `uv remove <package>`
