# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from argparse import ArgumentParser

from modules.crypto import KeyGen
from modules.filehandling import FileHandling as fh
from modules.filehandling import FolderHandling as foha
from settings import D_STORAGE, S_STORAGE, STAGING_AREA, S_DATA_STORAGE

parser = ArgumentParser(
    description=""" Key generation (classic and pqc algorithms). """)

parser.add_argument("--crypto", dest="crypto", help="", default="classic", choices=["none", "pqc", "classic"])
parser.add_argument("--variant", dest="variant", help="", default="secp256r1")

ARGS = parser.parse_args()

# Variant of the algorithm to use for key generation
variant = ARGS.variant
crypto = ARGS.crypto

###################################################################################################

if __name__ == "__main__":
    # Check if these folders exist, if not create them (for storing purposes)
    foha.createFolder(D_STORAGE)
    foha.createFolder(STAGING_AREA)
    foha.createFolder(S_STORAGE)
    foha.createFolder(S_DATA_STORAGE)

    if variant != "none":
        if crypto == "classic":
            # Generate device key pair
            pub_key, priv_key, data, unit = KeyGen.gen_keypair_classic(name="device", priv_storage=D_STORAGE, pub_storage=S_STORAGE, variant=variant)
            
            # Generate server key pair
            pub_key, priv_key, data, unit = KeyGen.gen_keypair_classic(name="server", priv_storage=S_STORAGE, pub_storage=D_STORAGE, variant=variant)

        elif crypto == "pqc": 
            # Generate device key pair
            pub_key, priv_key, data, unit = KeyGen.gen_keypair_pqc(sigalg=variant, name="device", priv_storage=D_STORAGE, pub_storage=S_STORAGE)
            # Generate server key pair
            pub_key, priv_key, data, unit = KeyGen.gen_keypair_pqc(sigalg=variant, name="server", priv_storage=S_STORAGE, pub_storage=D_STORAGE)

        # Save update versionnr = 0 to a txtfile
        try: 
            fh.save_to_txtfile("0", "version", D_STORAGE)
        except:
            print("Could not save the update version nr = 0 to storage.")


###################################################################################################