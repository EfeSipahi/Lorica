# Lorica

An HTTP intrusion detection model. The model examines each value in an HTTP request (query and
body values, path, some headers) and gives it a label: normal or attack.

## Status (22 November 2026)

Data preparation, step 1 of 8 is complete: the common format. The data is not converted yet.

- [Common format](docs/common-format.md): the two record types for all datasets.
- [Data preparation plan](docs/data-preparation-plan.md): the 8 steps and the notes for each dataset.

## Layout

```text
Lorica/
├── data/raw/        # Downloaded datasets (not in git, see below)
├── docs/            # Format and plan for the new work
├── reports/         # Dataset research report
├── research_notes/  # Dataset research notes
├── archive/         # First experiment: 1,000 CSIC requests, 4 models (complete)
└── requirements.txt # Python package versions
```

New scripts go in `scripts/` and their tests go in `tests/`.

## Setup

```bash
git clone https://github.com/EfeSipahi/Lorica.git
cd Lorica
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The project uses Python 3.14.7 and scikit-learn 1.9.1 on Linux. `requirements.txt` gives all package
versions. The saved models in `archive/models/` load only with scikit-learn 1.9.1.

## Data

`data/raw/` is not in git. [data/raw/DATASETS.md](data/raw/DATASETS.md) describes the 13 datasets
(2.2 GB). `data/raw/download_datasets.sh` downloads them and checks each file.

## Rules

- Do not change `data/raw/`. Write each output to a new folder.
- Do not change the scripts in `archive/scripts/`. The 4 saved models record their hashes.
- Load `.joblib` files only from this repository. A `.joblib` file can run code when it loads.
- Keep personal notes in `local/`. Git ignores this folder.
- Use paths relative to the project root, not full paths such as `/home/...`.
- When you add a package, update `requirements.txt` with `python -m pip freeze > requirements.txt`.

## First experiment (archive)

[archive/README.md](archive/README.md) describes the first experiment (in Turkish). The best model,
Random Forest v2, got F1 70.05% and a false alarm rate of 29.00% on 199 test requests. Run its
commands from the `archive/` folder.
