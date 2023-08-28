# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

# Add the parent directory to the paths to be searched for modules
import os
import sys
currentdir: str = os.path.dirname(os.path.realpath(__file__))
parentdir: str = os.path.dirname(currentdir)
sys.path.append(parentdir)

from psutil import LINUX, WINDOWS
import shutil
from pathlib import Path
from modules.remove import RemoveFiles
from settings import D_PRIV_KEY, D_PUB_KEY, D_STORAGE, S_PRIV_KEY, S_PUB_KEY, S_STORAGE, STAGING_AREA, S_DATA_STORAGE


if WINDOWS:
    python = "~/anaconda3/python.exe"
elif LINUX:
    python= "python3"
else:
    python = ""

# settings.py: set CRYPTO and VARIANT
# Example: CRYPTO = "classic" and VARIANT = "secp256r1"

class ScenarioSettings:
    def setting_starts(self, algo: str, variant: str, crypto: str, hash_algo: str):
        # To create to sets of starting points and keys with files
        n = 2

        path: Path = Path("temp", variant, hash_algo)

        ## Check if directory temp/variante/hash_algo exists
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)

            for i in range (n):

                # Remove all files
                RemoveFiles.remove_all_files()

                # Remove all key pairs
                RemoveFiles.remove_all_keys()
            
                # Generate new key pairs
                if crypto != "none" and variant != "none":
                    os.system(f"{python} key_generation.py --variant={variant} --crypto={crypto}")

                    # Save keys from memory to temp
                    shutil.copy(Path(D_STORAGE, f"{D_PUB_KEY}.der"), Path(path, f"{i}_{D_PUB_KEY}.der"))
                    shutil.copy(Path(D_STORAGE, f"{D_PRIV_KEY}.der"), Path(path, f"{i}_{D_PRIV_KEY}.der"))
                    shutil.copy(Path(S_STORAGE, f"{S_PUB_KEY}.der"), Path(path, f"{i}_{S_PUB_KEY}.der"))
                    shutil.copy(Path(S_STORAGE, f"{S_PRIV_KEY}.der"), Path(path, f"{i}_{S_PRIV_KEY}.der"))

                # Generate a new boot ticket
                os.system(f"{python} app.py --action=boot {algo}")

                # Copy bootticket from memory to temp
                shutil.copy(Path(STAGING_AREA, "bootticket"), Path(path, f"{i}_bootticket"))

                # Copy nonce.txt from memory to temp
                shutil.copy(Path(D_STORAGE, "nonce.txt"), Path(path, f"{i}_nonce.txt"))

                # Generate a new update
                os.system(f"{python} app.py --action=update {algo}")

                # Copy update from memory to temp
                shutil.copy(Path(STAGING_AREA, "update"), Path(path, f"{i}_update"))

                # Copy version number from memory to temp
                shutil.copy(Path(S_STORAGE, "version.txt"), Path(path, f"{i}_version.txt"))

        return path


    def settings_scenario_1(self, path: Path) -> None: 
        """
        Scenario 1: No bootticket available in Staging Area
        """

        # Remove all key pairs
        RemoveFiles.remove_all_keys()

        # Remove all files
        RemoveFiles.remove_all_files()
        
        # Copy keys from temp to memory
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(D_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(S_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PRIV_KEY}.der"), Path(D_STORAGE, f"{D_PRIV_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(S_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(D_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PRIV_KEY}.der"), Path(S_STORAGE, f"{S_PRIV_KEY}.der"))

        # Copy the right nonce to device memory
        shutil.copy(Path(path, "0_nonce.txt"), Path(D_STORAGE, "nonce.txt"))

        print("***** Initial state for scenario 1 has been established. *****")

    def settings_scenario_2(self, path: Path) -> None:
        """
        Scenario 2: Bootticket available in Staging Area, but not valid (because nonce of bootticket is invalid/wrong)
        Device requests new bootticket from the server.
        Server sends new bootticket to the Staging Area of the device.
        """

        # Remove all key pairs
        RemoveFiles.remove_all_keys()

        # Remove all files
        RemoveFiles.remove_all_files()

        # Copy keys from temp to memory
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(D_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(S_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PRIV_KEY}.der"), Path(D_STORAGE, f"{D_PRIV_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(S_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(D_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PRIV_KEY}.der"), Path(S_STORAGE, f"{S_PRIV_KEY}.der"))

        # Copy the right nonce to device
        shutil.copy(Path(path, "0_nonce.txt"), Path(D_STORAGE, "nonce.txt"))

        # Copy the wrong bootticket from temp to memory
        shutil.copy(Path(path, "1_bootticket"), Path(STAGING_AREA, "bootticket"))

        print("***** Initial state for scenario 2 has been established. *****")
    
    def settings_scenario_3(self, path: Path) -> None:
        """
        Scenario 3: Bootticket available in Staging Area and valid

        It is started in the business logic and measured how long it takes until the first measurement is saved and until the timer is initialised. After that, it is aborted so that further measurements can be carried out."""

        # Remove all key pairs
        RemoveFiles.remove_all_keys()

        # Remove all files
        RemoveFiles.remove_all_files()

        # Copy keys from temp to memory
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(D_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(S_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PRIV_KEY}.der"), Path(D_STORAGE, f"{D_PRIV_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(S_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(D_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PRIV_KEY}.der"), Path(S_STORAGE, f"{S_PRIV_KEY}.der"))

        # Copy the right nonce to device
        shutil.copy(Path(path, "0_nonce.txt"), Path(D_STORAGE, "nonce.txt"))

        # Copy the right bootticket from temp to memory
        shutil.copy(Path(path, "0_bootticket"), Path(STAGING_AREA, "bootticket"))

        print("***** Initial state for scenario 3 has been established. *****")

    def settings_scenario_4(self, path: Path) -> None:
        """
        Scenario 4: Business logic with deferralticket
        Request a deferralticket as boot into business logic was successful
        """

        # Create scenario 3
        ScenarioSettings.settings_scenario_3(self, path)

        print("***** Initial state for scenario 4 has been established. *****")

    def settings_scenario_5(self, path: Path) -> None:
        """
        Scenario 5: Business logic with compromised device. 
        Server does not save received sensor data from the unit nor does it respond to the DefTicket request.
        """

        # Create scenario 3
        ScenarioSettings.settings_scenario_3(self, path)

        # Put an empty file into the server memory to mark that the server knows the device has been compromised so that the server does not send any deferraltickets or stores the data that the server receives from the device's sensor
        Path(S_DATA_STORAGE, "compromised.device").touch()

        print("***** Initial state for scenario 5 has been established. *****")

    def settings_scenario_6(self, path: Path) -> None:
        """
        Scenario 6: Update available in Staging Area, but not valid
        Update available but not valid -> try to verify and request a new update
        Public key should not be able to verify the update -> because the public key of the server is not accurate
        Another possibility is a wrong version number but this will not be tested.
        """

        # Remove all key pairs
        RemoveFiles.remove_all_keys()

        # Remove all files
        RemoveFiles.remove_all_files()

        # Copy keys from temp to memory
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(D_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(S_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PRIV_KEY}.der"), Path(D_STORAGE, f"{D_PRIV_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(S_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(D_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PRIV_KEY}.der"), Path(S_STORAGE, f"{S_PRIV_KEY}.der"))

        # Copy bootticket from temp to memory
        shutil.copy(Path(path, "1_update"), Path(STAGING_AREA, "update"))

        print("***** Initial state for scenario 6 has been established. *****") 


    def settings_scenario_7(self, path: Path) -> None:
        """
        Scenario 7: Update available in Staging Area and valid
        Update is verified and installed, then the device is restarted.
        """

        # Remove all key pairs
        RemoveFiles.remove_all_keys()

        # Remove all files
        RemoveFiles.remove_all_files()

        # Copy keys from temp to memory
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(D_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(S_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PRIV_KEY}.der"), Path(D_STORAGE, f"{D_PRIV_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(S_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(D_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PRIV_KEY}.der"), Path(S_STORAGE, f"{S_PRIV_KEY}.der"))

        # Copy the right version to device
        shutil.copy(Path(path, "0_version.txt"), Path(D_STORAGE, "version.txt"))

        # Copy bootticket from temp to memory
        shutil.copy(Path(path, "0_update"), Path(STAGING_AREA, "update"))

        print("***** Initial state for scenario 7 has been established. *****") 


    def settings_scenario_8(self, path: Path) -> None:
        """
        Scenario 8: Server sends Update to the Staging Area of the device
        """
        
        # Remove all key pairs
        RemoveFiles.remove_all_keys()

        # Remove all files
        RemoveFiles.remove_all_files()

        # Copy keys from temp to memory
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(D_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PUB_KEY}.der"), Path(S_STORAGE, f"{D_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{D_PRIV_KEY}.der"), Path(D_STORAGE, f"{D_PRIV_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(S_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PUB_KEY}.der"), Path(D_STORAGE, f"{S_PUB_KEY}.der"))
        shutil.copy(Path(path, f"0_{S_PRIV_KEY}.der"), Path(S_STORAGE, f"{S_PRIV_KEY}.der"))

        print("***** Initial state for scenario 8 has been established. *****") 
