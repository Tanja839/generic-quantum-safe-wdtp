# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

"""
This file contains a test scenario for using the liboqs wrapper library for python (generating a key pair, signing a message and verifying the message) where these three function calls can be measured (e.g. cpu cycles, runtime or ram usage).
"""
# Go one level up in the directory to use modules from the parent directory 
import os
import sys
currentdir: str = os.path.dirname(os.path.realpath(__file__))
parentdir: str = os.path.dirname(currentdir)
sys.path.append(parentdir)


sys.path.append("../../liboqs-python/liboqs")
import oqs # liboqs library

from pathlib import Path
from argparse import ArgumentParser
from typing import List
from settings import S_STORAGE, D_STORAGE, HEADER_FUNCTIONS, M_APP_BENCHMARKING_FUNCTIONS, UNIT

# Imports of own classes and modules
from modules.filehandling import DataHandling as dh
from modules.crypto import KeyGen, KeyUsage, SignMessage, VerifyMessage

parser = ArgumentParser(
    description=""" Liboqs test script for liboqs library. """)

parser.add_argument("--number", dest="number", type=int, help="", default=1)
parser.add_argument("--hash", dest="hash_algo", help="", default="sha256", choices=["sha256", "sha384", "sha512"]) # msg_len 64, 96 or 128 for Hashalgo 256, 384 or 512 
parser.add_argument("--variant", dest="variant", help="", default="Falcon-512")

ARGS = parser.parse_args()
# How often the measurement will be taken
number = ARGS.number
hash_algo = ARGS.hash_algo
# Variant of the pqc algorithm to use for key generation
variant = ARGS.variant

if hash_algo == "sha512":
    msg_len = 128
elif hash_algo == "sha384":
    msg_len = 96
else:
    msg_len = 64

# Algorithms
dilithium_algos: List[str] = ["Dilithium3", "Dilithium5"]

falcon_algos: List[str] = ["Falcon-512", "Falcon-1024"]

sphincsp_sha256_algos: List[str] = ["SPHINCS+-SHA256-128f-robust", "SPHINCS+-SHA256-128f-simple", "SPHINCS+-SHA256-128s-robust", "SPHINCS+-SHA256-128s-simple", "SPHINCS+-SHA256-192f-robust", "SPHINCS+-SHA256-192f-simple", "SPHINCS+-SHA256-192s-robust", "SPHINCS+-SHA256-192s-simple", "SPHINCS+-SHA256-256f-robust", "SPHINCS+-SHA256-256f-simple", "SPHINCS+-SHA256-256s-robust", "SPHINCS+-SHA256-256s-simple"]
sphincsp_shake256_algos: List[str] = ["SPHINCS+-SHAKE256-128f-robust", "SPHINCS+-SHAKE256-128f-simple", "SPHINCS+-SHAKE256-128s-robust", "SPHINCS+-SHAKE256-128s-simple", "SPHINCS+-SHAKE256-192f-robust"," SPHINCS+-SHAKE256-192f-simple", "SPHINCS+-SHAKE256-192s-robust", "SPHINCS+-SHAKE256-192s-simple", "SPHINCS+-SHAKE256-256f-robust", "SPHINCS+-SHAKE256-256f-simple", "SPHINCS+-SHAKE256-256s-robust", "SPHINCS+-SHAKE256-256s-simple"]

# Variables
filename: str = f"{UNIT}_liboqs_{variant}_{hash_algo}"
filepath: Path = Path("..", M_APP_BENCHMARKING_FUNCTIONS, filename)

#######################################################################
# Signature Algorithm 
#######################################################################

if __name__ == "__main__":

    if variant is not None:
        print(ARGS)
        sigalg: str = variant

        print(f"liboqs version: {oqs.oqs_version()}")
        print(f"liboqs-python version: {oqs.oqs_python_version()}")

        # Cast a message to a bytes type
        b_msg: bytes = os.urandom(msg_len)

        name = "test"
        dh.set_header(filepath, HEADER_FUNCTIONS)
        print(f"***** Measuring the runtime of algorithm {sigalg} *****")

        for i in range (1,number+1):
            print(f"Measurement number: {i} Variant: {variant}")
            # Generate a keypair for device
            priv_key, pub_key, data_gen, unit = KeyGen.gen_keypair_pqc(sigalg, name, D_STORAGE, S_STORAGE)
            print(f"time_taken keygen: {data_gen} {unit}.")

            # Read private key from file (device)
            priv_key_new: bytes = KeyUsage.open_and_save_key_bytes(D_STORAGE, f"{name}_priv_key", "der")

            # Sign the message
            signature, data_sign, unit = SignMessage.liboqs_sign(sigalg, priv_key_new, b_msg)
            print(f"time_taken sign: {data_sign} {unit}.")

            # Read pub_key from file (server)
            pub_key_new: bytes = KeyUsage.open_and_save_key_bytes(S_STORAGE, f"{name}_pub_key", "der")

            # Verify the signature
            is_valid, data_verify, unit = VerifyMessage.liboqs_verify(sigalg, pub_key_new, b_msg, signature)
            print(f"time_taken verify: {data_verify} {unit}.")

            # Save the runtime benchmarking to csv file for future reference
            dh.save_to_csv_functions(Path("..", M_APP_BENCHMARKING_FUNCTIONS), i, filename, data_gen, data_sign, data_verify, str(is_valid))

            print("Valid signature?", is_valid)
