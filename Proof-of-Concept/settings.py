# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from pathlib import Path
from typing import List, Callable, Optional
from hwcounter import count, count_end
from mbedtls import pk

#######################################################################
# TO SET MANUALLY
#######################################################################

UNIT: str = "cycles" # or "Bytes"

# count und count_end for starting and ending Cycle-Measurements
# TODO: adding functions for starting and ending RAM-Usage-Measurement (which unit?)

#tracemalloc.start()
#memory = tracemalloc.get_traced_memory()
#tracemalloc.stop()
START_MEASUREMENT: Callable[[], float] = count
END_MEASUREMENT:Callable[[], float] = count_end

#######################################################################
# HOW OFTEN SHOULD A WAKEUP MESSAGE BE SENT (IN DEVICE ACTOR)
#######################################################################

WAKEUP_DEF_REQUEST: int = 10     # Wake up to request a deferral ticket every x seconds
WAKEUP_SENSOR: int = 10          # Wake up sensor to measure every x seconds
START_TIME_WDT: int = 25

#######################################################################
## FILENAMES ##
#######################################################################

D_PUB_KEY:  str = "device_pub_key"
D_PRIV_KEY: str = "device_priv_key"
S_PUB_KEY:  str = "server_pub_key"
S_PRIV_KEY: str = "server_priv_key"

#######################################################################
# LIBOQS ALGORITHMS
#######################################################################

dilithium_algos: List[str] = ["Dilithium2", "Dilithium3", "Dilithium5", "Dilithium2-AES", "Dilithium3-AES", "Dilithium5-AES"]

falcon_algos: List[str] = ["Falcon-512", "Falcon-1024"]

sphincsp_haraka_algos: List[str] = ["SPHINCS+-Haraka-128f-robust", "SPHINCS+-Haraka-128f-simple", "SPHINCS+-Haraka-128s-robust", "SPHINCS+-Haraka-128s-simple", "SPHINCS+-Haraka-192f-robust", "SPHINCS+-Haraka-192f-simple", "SPHINCS+-Haraka-192s-robust", "SPHINCS+-Haraka-192s-simple", "SPHINCS+-Haraka-256f-robust", "SPHINCS+-Haraka-256f-simple", "SPHINCS+-Haraka-256s-robust", "SPHINCS+-Haraka-256s-simple"]
sphincsp_sha256_algos: List[str] = ["SPHINCS+-SHA256-128f-robust", "SPHINCS+-SHA256-128f-simple", "SPHINCS+-SHA256-128s-robust", "SPHINCS+-SHA256-128s-simple", "SPHINCS+-SHA256-192f-robust", "SPHINCS+-SHA256-192f-simple", "SPHINCS+-SHA256-192s-robust", "SPHINCS+-SHA256-192s-simple", "SPHINCS+-SHA256-256f-robust", "SPHINCS+-SHA256-256f-simple", "SPHINCS+-SHA256-256s-robust", "SPHINCS+-SHA256-256s-simple"]
sphincsp_shake256_algos: List[str] = ["SPHINCS+-SHAKE256-128f-robust", "SPHINCS+-SHAKE256-128f-simple", "SPHINCS+-SHAKE256-128s-robust", "SPHINCS+-SHAKE256-128s-simple", "SPHINCS+-SHAKE256-192f-robust", "SPHINCS+-SHAKE256-192f-simple", "SPHINCS+-SHAKE256-192s-robust", "SPHINCS+-SHAKE256-192s-simple", "SPHINCS+-SHAKE256-256f-robust", "SPHINCS+-SHAKE256-256f-simple", "SPHINCS+-SHAKE256-256s-robust", "SPHINCS+-SHAKE256-256s-simple"]

#######################################################################

liboqs_algos: List[str] = dilithium_algos + falcon_algos + sphincsp_sha256_algos

#######################################################################
# STORAGE SPACES
#######################################################################

S_STORAGE:      Path = Path("memory", "server_secure_storage")
D_STORAGE:      Path = Path("memory", "device_secure_storage")
STAGING_AREA:   Path = Path("memory", "device_staging_area") 
S_DATA_STORAGE: Path = Path("memory", "server_data_storage")
MEASURED_DATA:   str = "measured_data"

#######################################################################
# MEASUREMENT SPACES
#######################################################################

HEADER_FUNCTIONS: List[str] = ["no", "algo_name", f"gen_keypair ({UNIT})", f"sign ({UNIT})", f"verify ({UNIT})", "valid"]
HEADER_SCENARIOS: List[str] = ["pre1", "counter1", "pre2", "counter2", "pre3", "counter3", "pre4", "counter4"]
HEADER_EVALUATION: List[str] = ["algo_name", f"mean ({UNIT})", f"median ({UNIT})", f"std ({UNIT})", f"min ({UNIT})", f"max ({UNIT})"]

BENCHMARKING: Path = Path("benchmarking", "measurements") 
M_APP_BENCHMARKING_FUNCTIONS: Path = Path(BENCHMARKING, "functions")
M_APP_BENCHMARKING_SCENARIO: Path = Path(BENCHMARKING, "scenarios")
EVALUATION: Path = Path("evaluation")

DEVICE = "DEVICE"
SERVER = "SERVER"

# argparse

scenario: Optional[int] = None
save_measurements: bool = False
save_update_measurements: bool = False