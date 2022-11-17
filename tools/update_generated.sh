#! /usr/bin/env bash
./tools/build_wrappers.py
jq . src/data/psbt.json >.foo && mv .foo src/data/psbt.json
./tools/build_psbt_ctests.py >src/ctest/psbts.h
