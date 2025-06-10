#!/bin/bash

# Get the directory of this script.
script_dir=$(dirname "$0")

# Make sure the virtual environment is activated.
. $script_dir/env/bin/activate

# Echo commands from now on.
set -x

# https://pycqa.github.io/isort/
isort $script_dir/fuzzers $script_dir/src $script_dir/analyze_logs.py $script_dir/cluster_fuzzer.py $script_dir/generate_bitstream.py $script_dir/main_fuzzer.py

# https://black.readthedocs.io/en/stable/
black --target-version py310 --target-version py311 --target-version py312 --target-version py313 $script_dir/fuzzers $script_dir/src $script_dir/analyze_logs.py $script_dir/cluster_fuzzer.py $script_dir/generate_bitstream.py $script_dir/main_fuzzer.py

# Update and build boofuzz from source.
cd $script_dir/boofuzz
git pull origin master
pip install .

# List all outdated packages.
pip list --outdated
