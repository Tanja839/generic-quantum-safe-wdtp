# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from typing import Any, Dict, Tuple, Union
from json import dumps
import pprint

from settings import *
from modules.messagetypes import *
from modules.keys import KeyUsage
from modules.utils import Utils
from modules.filehandling import FileHandling as fh

## Classic crypto imports
from mbedtls.pk import ECC, RSA
## PQC crypto imports
import oqs

MBEDTLS_CURVES_DICT: Dict[str, Any] = {
    "secp192r1": pk.Curve.SECP192R1,
    "secp192k1": pk.Curve.SECP192K1,
    "secp224r1": pk.Curve.SECP224R1,
    "secp224k1": pk.Curve.SECP224K1,
    "secp256r1": pk.Curve.SECP256R1,
    "secp256k1": pk.Curve.SECP256K1,
    "secp384r1": pk.Curve.SECP384R1,
    "secp521r1": pk.Curve.SECP521R1,
    "x25519": pk.Curve.CURVE25519,
    "x448": pk.Curve.CURVE448,
    "brainpoolP256r1": pk.Curve.BRAINPOOLP256R1,
    "brainpoolP384r1": pk.Curve.BRAINPOOLP384R1,
    "brainpoolP512r1": pk.Curve.BRAINPOOLP512R1
}

class SignMessage():
    # Signs the message.mdata and returns signature and the measurement data
    @staticmethod
    def classic_sign(priv_key: Union[ECC, RSA], b_message: bytes, hashtype: str) -> Tuple[bytes, float, str]:
        t1: float = START_MEASUREMENT()
        b_signature: bytes = priv_key.sign(b_message, hashtype) 
        t2: float = END_MEASUREMENT()
        data: float = t2 - t1 

        return b_signature, data, UNIT
    
    @staticmethod
    def sign(host: str, message: Message, storage: Path, priv_key_from: str, variant: str, crypto: str, hashtype: str):
        # Create message to sign 
        m_dict: Dict[str, Any] = Utils.pack_json(message.mdata)
        b_message: bytes = dumps(m_dict, indent=2).encode('utf-8')

        data = None
        unit = "unknown"
        b_signature = b""

        if crypto == "classic" or crypto == "pqc":

            if (crypto == "classic") and ("rsa" not in variant):
                # Load own private key from own secure storage into variable
                priv_key_ECC: ECC = KeyUsage.open_and_save_key_ECC(storage, priv_key_from, "der")  

                # Sign the message with the own private key
                b_signature, data, unit = SignMessage.classic_sign(priv_key_ECC, b_message, hashtype)

            elif (crypto == "classic") and ("rsa" in variant):
                # Load own private key from own secure storage into variable
                priv_key_RSA: RSA = KeyUsage.open_and_save_key_RSA(storage, priv_key_from, "der")  

                # Sign the message with the own private key
                b_signature, data, unit = SignMessage.classic_sign(priv_key_RSA, b_message, hashtype)

            elif crypto == "pqc":
                # Read private key from file (device)
                priv_key_new: bytes = KeyUsage.open_and_save_key_bytes(storage, priv_key_from, "der")

                # Sign the message
                b_signature, data, unit = SignMessage.liboqs_sign(variant, priv_key_new, b_message)

        else:
            print(f"[{host}] Dummy: No signing needed.")

        # Convert signature from bytes to string
        signature: str = b_signature.hex()

        if signature != "":
            if message.mdata is None:
                file_type: str = message.name
            else: 
                file_type: str = message.mdata.name

            print(f"[{host}] Signed the {file_type} in {data} {unit}.")

        message.signature = signature

        return message

    @staticmethod
    def liboqs_sign(sigalg: str, priv_key: bytes, b_msg: bytes) -> Tuple[bytes, float, str]:
        with oqs.Signature(sigalg) as signer:
            signer = oqs.Signature(sigalg, priv_key)

            t1: float = START_MEASUREMENT()
            # signer signs the message
            b_signature: bytes = signer.sign(b_msg)
            t2: float = END_MEASUREMENT()

            data: float = t2 - t1

        return b_signature, data, UNIT


class VerifyMessage():
    # Verifies the message.mdata with the signature and returns True or False and the measurement data
    @staticmethod
    def classic_verify(b_message: bytes, pub_key: Union[ECC, RSA], sig: bytes, hashtype: str) -> Tuple[bool, float, str]:

        t1: float = START_MEASUREMENT()
        valid = pub_key.verify(b_message, sig, hashtype)
        t2: float = END_MEASUREMENT()

        data: float = t2 - t1

        return valid, data, UNIT

    @staticmethod
    def verify(host: str, message: Message, storage: Path, pub_key_from: str, variant: str, crypto: str, hashtype: str):
        valid: bool = False 
        data = None
        unit: str = "unknown"
        file_type: str = "unknown"
        if message.signature is not None:
            # Converting string to bytes
            b_signature: bytes = bytes(bytearray.fromhex(message.signature))
            try:
                # Create message to verify
                m_dict: Dict[str, Any] = Utils.pack_json(message.mdata)
                b_message: bytes = dumps(m_dict, indent=2).encode('utf-8')

                if (crypto == "classic") or (crypto == "pqc"):

                    if (crypto == "classic") and (variant == "secp256r1"):
                        # Load own public key from own secure storage into variable
                        pub_key_ECC: ECC = KeyUsage.open_and_save_key_ECC(storage, pub_key_from, "der") 

                        # Sign the message with the own private key
                        valid, data, unit = VerifyMessage.classic_verify(b_message, pub_key_ECC, b_signature, hashtype)
                    
                    elif (crypto == "classic") and (variant == "rsa2048" or variant == "rsa4096"):

                        # Load own private key from own secure storage into variable
                        pub_key_RSA: RSA = KeyUsage.open_and_save_key_RSA(storage, pub_key_from, "der")  

                        # Sign the message with the own private key
                        valid, data, unit = VerifyMessage.classic_verify(b_message, pub_key_RSA, b_signature, hashtype)
                    
                    elif crypto == "pqc":
                        # Read pub_key from file
                        pub_key_new: bytes = KeyUsage.open_and_save_key_bytes(storage, pub_key_from, "der")

                        # Verify the signature
                        valid, data, unit = VerifyMessage.liboqs_verify(variant, pub_key_new, b_message, b_signature)

                else:
                    print(f"[{host}] Dummy: No verification needed.")
                    valid = True
                
            except:
                print(f"[{host}] Message could not be verified")

        else:
            print(f"[{host}] Do not verify the message. (sig = None) because CRYPTO = None")
            valid = True

        if message.signature != "":
            if message.mdata is None:
                file_type: str = message.name
            else: 
                file_type: str = message.mdata.name

            print(f"[{host}] Verification of {file_type} proven valid: {valid} in {data} {unit}.")

        return valid

    @staticmethod
    def liboqs_verify(sigalg: str, b_pub_key: bytes, b_msg: bytes, b_signature: bytes) -> Tuple[bool, float, str]:
        with oqs.Signature(sigalg) as verifier:

            t1: float = START_MEASUREMENT()
            # verifier verifies the signature
            is_valid: bool = verifier.verify(b_msg, b_signature, b_pub_key)
            t2: float = END_MEASUREMENT()

            data: float = t2 - t1 

        return is_valid, data, UNIT


class KeyGen():
    @staticmethod
    def gen_keypair_classic(name: str, priv_storage: Path, pub_storage: Path, variant: str):
        
        data: float = 0.0
        if variant in MBEDTLS_CURVES_DICT:
            # Initialize context
            ecdsa: ECC = pk.ECC(curve=MBEDTLS_CURVES_DICT[variant])

            # Start time of key generation
            t1: float = START_MEASUREMENT()
            # Generate key pair 
            key_bytes: bytes = ecdsa.generate()
            # End time of key generation
            t2: float = END_MEASUREMENT()

            priv_key = ecdsa.export_key("DER") 
            pub_key = ecdsa.export_public_key("DER")
        
        elif "rsa" in variant:  
            # Initialize context   
            rsa: RSA = pk.RSA()

            # Choose rsa key size; default: 2048
            if variant == "rsa4096":
                key_size=4096
            else:
                key_size=2048

            # Start time of key generation
            t1: float = START_MEASUREMENT()
            # Generate key pair 
            key_bytes = rsa.generate(key_size=key_size)
            # End time of key generation
            t2: float = END_MEASUREMENT()

            priv_key = rsa.export_key("DER") 
            pub_key = rsa.export_public_key("DER")

        else:
            raise ValueError("Unsupported encryption type")
        
        data: float = t2 - t1

        # Save the keys to the designated storage spaces
        fh.save_to_format(priv_key, priv_storage, f"{name}_priv_key", "der")
        fh.save_to_format(pub_key, priv_storage, f"{name}_pub_key", "der")

        fh.save_to_format(pub_key, pub_storage, f"{name}_pub_key", "der")

        print(f"Generated and saved {name} key pair")

        # Calculate the time taken for key generation in seconds

        print(f"{name}: Classical key generation took {data} {UNIT}.")

        return pub_key, priv_key, data, UNIT

    @staticmethod
    def gen_keypair_pqc(sigalg: str, name: str, priv_storage: Path, pub_storage: Path) -> Tuple[bytes, bytes, float, str]:
        with oqs.Signature(sigalg) as signer:
            print("\nSignature details:")
            print(signer.details) 

            # Write signer details to a file for future reference 
            fh.save_to_json(signer.details, Path("measurements", "functions"), f"signer_details_{sigalg}")

            # Start time of key generation
            t1: float = START_MEASUREMENT()

            # Generate a public key
            pub_key: bytes = signer.generate_keypair()

            # End time of key generation
            t2: float = END_MEASUREMENT()

            # Extract the private key
            priv_key: bytes = signer.export_secret_key()

            # Save the keys to the designated storage spaces
            fh.save_to_format(priv_key, priv_storage, f"{name}_priv_key", "der")
            fh.save_to_format(pub_key, priv_storage, f"{name}_pub_key", "der")

            fh.save_to_format(pub_key, pub_storage, f"{name}_pub_key", "der")

            # Calculate the difference of the taken measurements
            data: float = t2 - t1

            print(f"{name}: Quantumsafe key generation took {data} {UNIT}.")

        return pub_key, priv_key, data, UNIT