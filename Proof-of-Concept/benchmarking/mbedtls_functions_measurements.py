# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

import os
import sys
currentdir: str = os.path.dirname(os.path.realpath(__file__))
parentdir: str = os.path.dirname(currentdir)
sys.path.append(parentdir)

from argparse import ArgumentParser
from pathlib import Path
from modules.crypto import KeyGen, KeyUsage
from modules.filehandling import DataHandling as dh
from settings import UNIT, S_STORAGE, D_STORAGE, HEADER_FUNCTIONS, START_MEASUREMENT, END_MEASUREMENT, M_APP_BENCHMARKING_FUNCTIONS

parser_bedtls = ArgumentParser(
    description=""" Mbedtls test script for function benchmarking. """)

parser_bedtls.add_argument("--number", dest="number", type=int, help="", default=1)
parser_bedtls.add_argument("--hash", dest="hash_algo", help="", default="sha256", choices=["sha256", "sha384", "sha512"]) # msg_len 64, 96 or 128 for Hashalgo 256, 384 or 512 
parser_bedtls.add_argument("--variant", dest="variant", help="", default="secp256r1") 

ARGS = parser_bedtls.parse_args()
number = ARGS.number
hash_algo = ARGS.hash_algo
variant = ARGS.variant

if hash_algo == "sha512":
    msg_len = 128
elif hash_algo == "sha384":
    msg_len = 96
else:
    msg_len = 64

## Crypto imports ##
from mbedtls.pk import ECC, RSA

filename: str = f"{UNIT}_{variant}_{hash_algo}"
filepath: Path = Path("..", M_APP_BENCHMARKING_FUNCTIONS, filename)

if __name__ == "__main__":

    if variant is not None:
        message: bytes = os.urandom(msg_len)
        name = "test"
        
        dh.set_header(filepath, HEADER_FUNCTIONS)
        print(f"***** Measuring the runtime of a classic algorithm *****")

        for i in range (1,number+1):
            print(f"Measurement number: {i} Variant: {variant}")
            if "rsa" not in variant:
                # Generate and save a key_pair
                pub_key, priv_key, data_gen, unit = KeyGen.gen_keypair_classic(name=name, priv_storage=D_STORAGE, pub_storage=S_STORAGE, variant=variant)

                # Read private key from file
                priv_key_ECC: ECC = KeyUsage.open_and_save_key_ECC(D_STORAGE, f"{name}_priv_key","der")

                # Sign the message (bytes)
                t1 = START_MEASUREMENT()
                signature: bytes = priv_key_ECC.sign(message, hash_algo) 
                t2 = END_MEASUREMENT()
                
                data_sign: float = t2 - t1
                print(f"sign took {data_sign} {UNIT}.")

                # Read pub_key from file
                d_pub_key_ECC: ECC = KeyUsage.open_and_save_key_ECC(S_STORAGE, f"{name}_pub_key","der")

                # Verify the signature
                t1 = START_MEASUREMENT()
                valid = d_pub_key_ECC.verify(message, signature, hash_algo) 
                t2 = END_MEASUREMENT()

                data_verify: float = t2 - t1
                print(f"verify took {data_verify} {UNIT}.")
                print(f"Valid signature? {valid}")
        
            elif "rsa" in variant:
                # Generate and save a key_pair
                pub_key, priv_key, data_gen, unit = KeyGen.gen_keypair_classic(name=name, priv_storage=D_STORAGE, pub_storage=S_STORAGE, variant=variant)

                # Read private key from file (device)
                priv_key_RSA: RSA = KeyUsage.open_and_save_key_RSA(D_STORAGE, f"{name}_priv_key","der")

                # Sign the message (bytes)
                t1 = START_MEASUREMENT()
                signature: bytes = priv_key_RSA.sign(message, hash_algo) 
                t2 = END_MEASUREMENT()

                sig_str: str = signature.hex()  # Converting bytes to string

                b_sig: bytes = bytes(bytearray.fromhex(sig_str)) # Converting string to bytes

                data_sign: float = t2 - t1
                print(f"sign took {data_sign} {UNIT}.")

                # Read pub_key from file
                d_pub_key_RSA: RSA = KeyUsage.open_and_save_key_RSA(S_STORAGE, f"{name}_pub_key","der")

                # Verify the signature
                t1 = START_MEASUREMENT()
                valid = d_pub_key_RSA.verify(message, b_sig, hash_algo) 
                t2 = END_MEASUREMENT()

                data_verify: float = t2 - t1
                print(f"verify took {data_verify} {UNIT}.")
                print(f"Valid signature? {valid}")
    
            dh.save_to_csv_functions(Path("..", M_APP_BENCHMARKING_FUNCTIONS), i, filename, data_gen, data_sign, data_verify, str(valid))
