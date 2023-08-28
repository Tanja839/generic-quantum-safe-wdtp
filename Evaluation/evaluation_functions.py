# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from pathlib import Path
from typing import List
import csv 
from pandas import read_csv
import os
import numpy as np

filepaths: List[str] = ["evaluation_genkeypair.csv", "evaluation_sign.csv", "evaluation_verify.csv"]

HEADER: List[str] = ["algo_name", "mean", "median", "std", "min", "max"]

level_list: List[str] = os.listdir(Path("functions"))
level_list.remove("Signer_Details")
print(level_list)
for each in level_list:
    print(each)
    for x in filepaths:
        # Create evaluation file with header
        with open(Path("functions", each, x), "w") as f1:
            writer = csv.writer(f1)
            writer.writerow(HEADER)

    algo_list: List[str] = os.listdir(Path("functions", each))
    algo_list.remove("evaluation_genkeypair.csv")
    algo_list.remove("evaluation_sign.csv")
    algo_list.remove("evaluation_verify.csv")

    for algo in algo_list:
        if algo == ".gitkeep":
            continue
        try:
            data = read_csv(Path("functions", each, algo))
            algo_name = algo.replace(".csv", "")


            # evaluation for gen_keypair (cycles)
            key_gen = np.array(data["gen_keypair (cycles)"].tolist())
            key_gen_median = np.round(np.median(key_gen, axis=0)).astype("int64")
            key_gen_mean = np.round(np.mean(key_gen, axis=0)).astype("int64")
            key_gen_std = np.round(np.std(key_gen, axis=0)).astype("int64")
            key_gen_min = np.round(key_gen.min()).astype("int64")
            key_gen_max = np.round(key_gen.max()).astype("int64")

            with open(Path("functions", each, "evaluation_genkeypair.csv"), "a") as f2:
                writer = csv.writer(f2)
                writer.writerow([algo_name, key_gen_mean, key_gen_median, key_gen_std, key_gen_min, key_gen_max])


            # evaluation for sign (cycles)
            sign = np.array(data["sign (cycles)"].tolist())
            sign_median = np.round(np.median(sign, axis=0)).astype("int64")
            sign_mean = np.round(np.mean(sign, axis=0)).astype("int64")
            sign_std = np.round(np.std(sign, axis=0)).astype("int64")
            sign_min = np.round(sign.min()).astype("int64")
            sign_max = np.round(sign.max()).astype("int64")

            with open(Path("functions", each, "evaluation_sign.csv"), "a") as f3:
                writer = csv.writer(f3)
                writer.writerow([algo_name, sign_mean, sign_median, sign_std, sign_min, sign_max])

            # evaluation for verify (cycles)
            verify = np.array(data["verify (cycles)"].tolist())
            verify_median = np.round(np.median(verify, axis=0)).astype("int64")
            verify_mean = np.round(np.mean(verify, axis=0)).astype("int64")
            verify_std = np.round(np.std(verify, axis=0)).astype("int64")
            verify_min = np.round(verify.min()).astype("int64")
            verify_max = np.round(verify.max()).astype("int64")

            with open(Path("functions", each, "evaluation_verify.csv"), "a") as f4:
                writer = csv.writer(f4)
                writer.writerow([algo_name, verify_mean, verify_median, verify_std, verify_min, verify_max])
        except Exception as ex:
            print(f"file is empty or other error for algorithmus {algo}, exeption: {ex}")
