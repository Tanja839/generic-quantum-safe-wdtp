# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from settings import D_STORAGE, S_STORAGE, STAGING_AREA, S_DATA_STORAGE
import os
from pathlib import Path

class RemoveFiles():
    @staticmethod
    def remove_keys(name: str, priv_storage: Path, pub_storage: Path):
        try:
            os.remove(Path(priv_storage, f"{name}_priv_key.der"))
            os.remove(Path(priv_storage, f"{name}_pub_key.der"))
            os.remove(Path(pub_storage, f"{name}_pub_key.der"))
            print(f"Removed the key files of {name}.")
        except:
            print("File does not exist, so it cannot be removed.")
    
    @staticmethod
    def remove_all_keys():
        # Remove device key pair 
        RemoveFiles.remove_keys(name="device", priv_storage=D_STORAGE, pub_storage=S_STORAGE)
        # Remove server key pair
        RemoveFiles.remove_keys(name="server", priv_storage=S_STORAGE, pub_storage=D_STORAGE)
        
    @staticmethod
    def remove_file(storage: Path, filename: str):
        try:
            os.remove(Path(storage, filename))
        except:
            print("File does not exist, so it cannot be removed.")

    @staticmethod
    def remove_all_files():
        try:
            # Remove nonce.txt
            RemoveFiles.remove_file(D_STORAGE, "nonce.txt")

            # Remove bootticket
            RemoveFiles.remove_file(STAGING_AREA, "bootticket")

            # Remove update
            RemoveFiles.remove_file(STAGING_AREA, "update")

            # Remove measured_data.txt
            RemoveFiles.remove_file(S_DATA_STORAGE, "measured_data.txt")

            # Remove bootticket from server
            RemoveFiles.remove_file(S_STORAGE, "bootticket")

            # Remove update from server
            RemoveFiles.remove_file(S_STORAGE, "update")

            # Remove compromised.device from server
            RemoveFiles.remove_file(S_DATA_STORAGE, "compromised.device")
            
            print("Removed all files.")
        except:
            print("File does not exist, so it cannot be removed.")


if __name__ == "__main__":
    # Remove all key pairs
    RemoveFiles.remove_all_keys()

    # Remove all files
    RemoveFiles.remove_all_files()


