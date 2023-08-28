# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from pathlib import Path

## Crypto imports ##
from mbedtls.pk import ECC, RSA

class KeyUsage:

    @staticmethod
    def open_and_save_key_ECC(path: Path, name: str, format: str) -> ECC:
        with open(Path(path, f"{name}.{format}"), "rb") as file:
            b_key: bytes = file.read()
        key: ECC = ECC.from_buffer(b_key)
        return key

    @staticmethod
    def open_and_save_key_RSA(path: Path, name: str, format: str) -> RSA:
        with open(Path(path, f"{name}.{format}"), "rb") as file:
            b_key: bytes = file.read()
        key: RSA = RSA.from_buffer(b_key)
        return key

    @staticmethod
    def open_and_save_key_bytes(path: Path, name: str, format: str) -> bytes:
        with open(Path(path, f"{name}.{format}"), "rb") as file:
            b_key: bytes = file.read()
        return b_key
        