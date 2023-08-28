# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

import os
import sys
# must be above the other imports so that the import can also import via the parent folder
currentdir: str = os.path.dirname(os.path.realpath(__file__))
parentdir: str = os.path.dirname(currentdir)
sys.path.append(parentdir)

from argparse import ArgumentParser
from psutil import WINDOWS, LINUX
from scenario_settings import ScenarioSettings
from pathlib import Path
import shutil

import settings
from modules.remove import RemoveFiles
from modules.filehandling import FolderHandling as foha
from modules.filehandling import DataHandling as dh
from modules.filehandling import FileHandling as fh
from settings import M_APP_BENCHMARKING_SCENARIO, HEADER_SCENARIOS, D_STORAGE, S_DATA_STORAGE, S_STORAGE, STAGING_AREA

if WINDOWS:
    python = "~/anaconda3/python.exe"
elif LINUX:
    python = "python3"
else:
    python = ""


parser = ArgumentParser(
    description=""" Benchmarking of the different scenarios. """)
# required options

parser.add_argument("--scenario", dest="scenario", type=int, help="", default=1)
parser.add_argument("--number", dest="number", type=int, help="", default=1)

parser.add_argument("--variant", dest="variant", help="", default="Falcon-512")
parser.add_argument("--hash", dest="hash_algo", help="", default="sha256")
parser.add_argument("--unit", dest="unit", help="", default="cycles")
parser.add_argument("--crypto", dest="crypto", help="", default="pqc", choices=["none", "pqc", "classic"])

ARGS = parser.parse_args()
print(f"ARGS: {ARGS}")
scenario = ARGS.scenario
number = ARGS.number

settings.unit = str(ARGS.unit)

variant = ARGS.variant
hash_algo = ARGS.hash_algo
crypto = ARGS.crypto

###############################################################################################################

if __name__ == "__main__":
    filepath = fh.gen_filepath(settings.unit, scenario, variant, hash_algo, M_APP_BENCHMARKING_SCENARIO)

    # Check if these folders exist, if not create them (for storing purposes)
    foha.createFolder(D_STORAGE)
    foha.createFolder(STAGING_AREA)
    foha.createFolder(S_STORAGE)
    foha.createFolder(S_DATA_STORAGE)

    ALGO = f"--scenario={scenario} --variant={variant} --hash={hash_algo} --unit={settings.unit} --crypto={crypto}"
    
    EXECUTE_SAVE_BOOT = f"{python} app.py --action=boot --saveb {ALGO}"
    EXECUTE_SAVE_UPDATE = f"{python} app.py --action=update --saveu {ALGO}"
    
    settings = ScenarioSettings()

    foha.createFolder(M_APP_BENCHMARKING_SCENARIO)
    # Set the header for benchmarking scenario measurements
    dh.set_header(filepath, HEADER_SCENARIOS)

    # Create a new folder for settings based on variant, crypto and hash_algo
    path: Path = settings.setting_starts(ALGO, variant, crypto, hash_algo)
    foha.createFolder(path)

    # Szenario 1: No bootticket available in Staging Area
    if scenario == 1:
        print(f"Scenario {scenario}: Taking measurements for requiring a new bootticket {number} times.")
        # Status 1: Staging area is empty: Require a new boot ticket
        settings.settings_scenario_1(path)

        for i in range(1, number+1):
            print(f"Measurement: {i}")

            # Execute app.py
            os.system(EXECUTE_SAVE_BOOT)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")

            # Remove all files to start the scenario with the correct start state
            RemoveFiles.remove_all_files()

            print("***** Start state for scenario 1 has been established. *****")

    # Szenario 2: Bootticket available in Staging Area, but not valid
    elif scenario == 2:
        print(f"Scenario {scenario}: Taking measurements for starting with an invalid bootticket {number} times.")
        
        settings.settings_scenario_2(path)
        for i in range(1, number+1):
            print(f"Measurement: {i}")

            # Execute app.py with a bootticket
            os.system(EXECUTE_SAVE_BOOT)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")

            # Remove the correct bootticket to start the scenario with the wrong bootticket
            RemoveFiles.remove_file(STAGING_AREA, "bootticket")
            RemoveFiles.remove_file(S_STORAGE, "bootticket")

            # Copy the right nonce to device
            shutil.copy(Path(path, "0_nonce.txt"), Path(D_STORAGE, "nonce.txt"))

            # Copy the wrong bootticket from temp to memory
            shutil.copy(Path(path, "1_bootticket"), Path(STAGING_AREA, "bootticket"))

            print("***** Start state for scenario 2 has been established. *****")
        
    # Szenario 3: Bootticket available in Staging Area and valid
    elif scenario == 3:

        settings.settings_scenario_3(path)

        print(f"Scenario {scenario}: Taking measurements for starting with a valid bootticket {number} times.")
        
        for i in range(1, number+1):
            print(f"Measurement: {i}")

            # Execute app.py with a valide bootticket
            os.system(EXECUTE_SAVE_BOOT)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")

            # Remove measured_data.txt and nonce.txt
            RemoveFiles.remove_file(S_DATA_STORAGE, "measured_data.txt")
            RemoveFiles.remove_file(D_STORAGE, "nonce.txt")

            # Copy the right nonce to device
            shutil.copy(Path(path, "0_nonce.txt"), Path(D_STORAGE, "nonce.txt"))

            # Copy the right bootticket from temp to memory
            shutil.copy(Path(path, "0_bootticket"), Path(STAGING_AREA, "bootticket"))

            print("***** Start state for scenario 3 has been established. *****")


    # Szenario 4: Business logic with deferralticket
    # Request a deferralticket as boot into business logic was successful
    elif scenario == 4:
        print(f"Scenario {scenario}: Taking measurements for requesting a deferralticket {number} times.")

        settings.settings_scenario_4(path)

        for i in range(1, number+1):
            print(f"Measurement: {i}")

            # Execute app.py with a valide bootticket
            os.system(EXECUTE_SAVE_BOOT)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")

            # Remove measured_data.txt and nonce.txt
            RemoveFiles.remove_file(S_DATA_STORAGE, "measured_data.txt")
            RemoveFiles.remove_file(D_STORAGE, "nonce.txt")

            # Copy the right nonce to device
            shutil.copy(Path(path, "0_nonce.txt"), Path(D_STORAGE, "nonce.txt"))

            # Copy the right bootticket from temp to memory
            shutil.copy(Path(path, "0_bootticket"), Path(STAGING_AREA, "bootticket"))
        
            print("***** Start state for scenario 4 has been established. *****")

    # Szenario 5: Business logic with compromised device
    elif scenario == 5:
        print(f"Scenario {scenario}: Taking measurements for sending data and requests from a compromised device {number} times.")
        
        settings.settings_scenario_5(path)

        for i in range(1, number+1):
            print(f"Measurement: {i}")
            
            # Execute app.py with an invalide bootticket
            os.system(EXECUTE_SAVE_BOOT)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")

            # Remove measured_data.txt and nonce.txt
            RemoveFiles.remove_file(S_DATA_STORAGE, "measured_data.txt")
            RemoveFiles.remove_file(D_STORAGE, "nonce.txt")
            RemoveFiles.remove_file(S_DATA_STORAGE, "compromised.device")

            # Copy the right nonce to device
            shutil.copy(Path(path, "0_nonce.txt"), Path(D_STORAGE, "nonce.txt"))

            # copy right bootticket from temp to memory
            shutil.copy(Path(path, "0_bootticket"), Path(STAGING_AREA, "bootticket"))

            # Put an empty file into the server memory to mark that the server knows the device has been compromised so that the server does not send any deferraltickets or stores the data that the server receives from the device's sensor
            Path(S_DATA_STORAGE, "compromised.device").touch()

            print("***** Start state for scenario 5 has been established. *****")
 
    # Szenario 6: Update available in Staging Area, but not valid
    # Update available but not valid -> try to verify and request a new update
    elif scenario == 6:
        print(f"Scenario {scenario}: Taking measurements for requesting a new update {number} times.")
        for i in range(1, number+1):
            print(f"Measurement: {i}")
            settings.settings_scenario_6(path)

            # Booting -> staging area -> verifying update not possible because public key is wrong-> requesting a new update
            os.system(EXECUTE_SAVE_BOOT)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")
                        
            # Remove the correct update to start the scenario with the correct start state
            RemoveFiles.remove_file(STAGING_AREA, "update")
            RemoveFiles.remove_file(S_STORAGE, "update")

            # Copy the wrong update into the staging area again
            shutil.copy(Path(path, "1_update"), Path(STAGING_AREA, "update"))

            print("***** Start state for scenario 6 has been established. *****")

    # Szenario 7: Update available in Staging Area and valid
    elif scenario == 7:

        print(f"Scenario {scenario}: Taking measurements for installing a new update {number} times.")

        settings.settings_scenario_7(path)

        for i in range(1, number+1):
            print(f"Measurement: {i}")
        
            # Booting -> staging area -> verifying update -> installing a new update -> reset
            os.system(EXECUTE_SAVE_BOOT)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")
                        
            # Remove the correct update to start the scenario with the correct start state
            RemoveFiles.remove_file(STAGING_AREA, "update")
            RemoveFiles.remove_file(S_STORAGE, "update")

            # Copy the right update into the staging area again
            shutil.copy(Path(path, "0_version.txt"), Path(D_STORAGE, "version.txt"))
            shutil.copy(Path(path, "0_update"), Path(STAGING_AREA, "update"))

            print("***** Start state for scenario 7 has been established. *****") 

    # Szenario 8: Server sends update
    elif scenario == 8:
        print(f"Scenario {scenario}: Taking measurements for external call to server to send an update to the device {number} times.")
        
        settings.settings_scenario_8(path)

        for i in range(1, number+1):
            print(f"Measurement: {i}")

            os.system(EXECUTE_SAVE_UPDATE)
            with open(f"{filepath}.csv", 'at') as file:
                file.write("\n")
                        
            # Remove the correct update to start the scenario with the correct start state
            RemoveFiles.remove_file(STAGING_AREA, "update")
            RemoveFiles.remove_file(S_STORAGE, "update")

            print("***** Start state for scenario 8 has been established. *****") 
