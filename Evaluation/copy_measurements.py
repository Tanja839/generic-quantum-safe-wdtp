# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ----------------------------------------------------------------------------
# Author:        Niels Korschinsky <niels.korschinsky@gmail.com>
# ****************************************************************************

import os
from pathlib import Path
from shutil import copy
from typing import Dict


mapping: Dict[str, Path] = {
    ### Classic ones
    "secp256r1": Path("classic"),
    "rsa2048": Path("classic"),
    "rsa4096": Path("classic"),

    ### Dilithium
    "Dilithium3": Path("NIST_Level_3"),
    "Dilithium5": Path("NIST_Level_5"),
    # "Dilithium2": # not supported,

    ### Falcon
    "Falcon-512": Path("NIST_Level_1"),
    "Falcon-1024": Path("NIST_Level_5"),

    # Sphincs
    # "SPHINCS+-Haraka-128f-robust": Path("NIST_Level_1"), # not included
    # "SPHINCS+-Haraka-128f-simple": Path("NIST_Level_1"), # not included
    # "SPHINCS+-Haraka-128s-robust": Path("NIST_Level_1"), # not included
    # "SPHINCS+-Haraka-128s-simple": Path("NIST_Level_1"), # not included
    # "SPHINCS+-Haraka-192f-robust": Path("NIST_Level_3"), # not included
    # "SPHINCS+-Haraka-192f-simple": Path("NIST_Level_3"), # not included
    # "SPHINCS+-Haraka-192s-robust": Path("NIST_Level_3"), # not included
    # "SPHINCS+-Haraka-192s-simple": Path("NIST_Level_3"), # not included
    # "SPHINCS+-Haraka-256f-robust": Path("NIST_Level_5"), # not included
    # "SPHINCS+-Haraka-256f-simple": Path("NIST_Level_5"), # not included
    # "SPHINCS+-Haraka-256s-robust": Path("NIST_Level_5"), # not included
    # "SPHINCS+-Haraka-256s-simple": Path("NIST_Level_5"), # not included
    "SPHINCS+-SHA256-128f-robust": Path("NIST_Level_1"),
    "SPHINCS+-SHA256-128f-simple": Path("NIST_Level_1"),
    "SPHINCS+-SHA256-128s-robust": Path("NIST_Level_1"),
    "SPHINCS+-SHA256-128s-simple": Path("NIST_Level_1"),
    "SPHINCS+-SHA256-192f-robust": Path("NIST_Level_3"),
    "SPHINCS+-SHA256-192f-simple": Path("NIST_Level_3"),
    "SPHINCS+-SHA256-192s-robust": Path("NIST_Level_3"),
    "SPHINCS+-SHA256-192s-simple": Path("NIST_Level_3"),
    "SPHINCS+-SHA256-256f-robust": Path("NIST_Level_5"),
    "SPHINCS+-SHA256-256f-simple": Path("NIST_Level_5"),
    "SPHINCS+-SHA256-256s-robust": Path("NIST_Level_5"),
    "SPHINCS+-SHA256-256s-simple": Path("NIST_Level_5"),
    "SPHINCS+-SHAKE256-128f-robust": Path("NIST_Level_1"),
    "SPHINCS+-SHAKE256-128f-simple": Path("NIST_Level_1"),
    "SPHINCS+-SHAKE256-128s-robust": Path("NIST_Level_1"),
    "SPHINCS+-SHAKE256-128s-simple": Path("NIST_Level_1"),
    "SPHINCS+-SHAKE256-192f-robust": Path("NIST_Level_3"),
    "SPHINCS+-SHAKE256-192f-simple": Path("NIST_Level_3"),
    "SPHINCS+-SHAKE256-192s-robust": Path("NIST_Level_3"),
    "SPHINCS+-SHAKE256-192s-simple": Path("NIST_Level_3"),
    "SPHINCS+-SHAKE256-256f-robust": Path("NIST_Level_5"),
    "SPHINCS+-SHAKE256-256f-simple": Path("NIST_Level_5"),
    "SPHINCS+-SHAKE256-256s-robust": Path("NIST_Level_5"),
    "SPHINCS+-SHAKE256-256s-simple": Path("NIST_Level_5"),

}


function_base_path = Path("..", "Proof-of-Concept", "benchmarking", "measurements","functions")
function_target_zone = Path("functions")

scenario_base_path = Path("..", "Proof-of-Concept", "benchmarking", "measurements","scenarios")
scenario_target_zone = Path("scenarios")

def copy_function_mappings(file_name: str):
     
    for algo_name, target_path in mapping.items():

        if algo_name in file_name:
            copy(
                function_base_path.joinpath(file_name), 
                function_target_zone.joinpath(target_path) \
                    .joinpath(file_name)
                )
            return
            #moved
    # error
    print(f"Function File {file_name} not found in the mapping and therefore not copied")

def copy_scenario_mappings(file_name: str):
    
    
    for algo_name, target_path in mapping.items():

        if algo_name in file_name:
            
            # naming: f"{unit}_{scenario}_{variant}_{hash_algo}"
            # we need the scenario there
            scenario_number = file_name.split("_")[1]

            if scenario_number in [4, 5]:
                print(f"Skipped {file_name} as it is not measureable due to randomness")
                return

            copy(
                scenario_base_path.joinpath(file_name), 
                scenario_target_zone.joinpath(target_path) \
                    .joinpath(scenario_number) \
                    .joinpath(file_name)
                )
            return
            #moved
    # error
    print(f"Scenario File {file_name} not found in the mapping and therefore not copied")

print("Starting Copy")


for file_name in os.listdir(function_base_path):
    if not file_name.endswith(".csv"):
        # skip
        print(f"Skipped file {file_name}")
        continue
    copy_function_mappings(file_name)

for file_name in os.listdir(scenario_base_path):
    if not file_name.endswith(".csv"):
        # skip
        print(f"Skipped file {file_name}")
        continue
    copy_scenario_mappings(file_name)
        
print("Finished")