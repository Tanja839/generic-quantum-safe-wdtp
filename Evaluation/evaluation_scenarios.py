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

HEADER: List[str] = ["algo_name", "mean", "median", "std", "min", "max"]

level_list: List[str] = os.listdir(Path("scenarios"))
print(level_list)
for level in level_list:
    scenario_list: List[str] = os.listdir(Path("scenarios", f"{level}"))
    for scenario in scenario_list:
        # Create evaluation file with header
        if scenario != "3":
            with open(Path("scenarios", level, scenario, f"evaluation_scenario_{scenario}.csv"), "w") as f1:
                writer = csv.writer(f1)
                writer.writerow(HEADER)
        if scenario == "3":
            with open(Path("scenarios", level, scenario, f"evaluation_scenario_3_timer_init.csv"), "w") as ft:
                writer = csv.writer(ft)
                writer.writerow(HEADER)
            with open(Path("scenarios", level, scenario, f"evaluation_scenario_3_storage.csv"), "w") as fs:
                writer = csv.writer(fs)
                writer.writerow(HEADER)

        algo_list: List[str] = os.listdir(Path("scenarios", level, scenario))
        if scenario != "3":
            algo_list.remove(f"evaluation_scenario_{scenario}.csv")
        elif scenario == "3":
            algo_list.remove(f"evaluation_scenario_3_timer_init.csv")
            algo_list.remove(f"evaluation_scenario_3_storage.csv")
        else:
            pass

        for algo in algo_list:
            if algo == ".gitkeep":
                continue
            start_list: List[int] = []
            end_list: List[int] = []
            e_timer_init_list: List[int] = []
            e_storage_list: List[int] = []
            diff_list: List[int] = []
            diff_timer_init_list: List[int] = []
            diff_storage_list: List[int] = []

            data = read_csv(Path("scenarios", level, scenario, algo))
            data_dict = data.to_dict()
            algo_name = algo.replace(".csv", "")
            data_len = len(data)
            for i in range(data_len):
                if ("sb" in data_dict["pre1"][i]) or ("su" in data_dict["pre1"][i]) or ("s_" in data_dict["pre1"][i]):
                    start_list.append(data_dict["counter1"][i])      
                if ("eb" in data_dict["pre2"][i]) or ("eu" in data_dict["pre2"][i]):
                    end_list.append(data_dict["counter2"][i])
                elif "e_timer_init" in data_dict["pre2"][i]:
                    e_timer_init_list.append(data_dict["counter2"][i])
                elif "e_storage" in data_dict["pre2"][i]:
                    e_storage_list.append(data_dict["counter2"][i])
                if not isinstance(data_dict["pre3"][i], float):
                    if "e_timer_init" in data_dict["pre3"][i]:
                        e_timer_init_list.append(data_dict["counter3"][i])
                    elif "e_storage" in data_dict["pre3"][i]:
                        e_storage_list.append(data_dict["counter3"][i])

                else:
                    continue

            for j in range(data_len):
                if len(end_list) > 1:
                    diff_list.append(end_list[j]-start_list[j])
                if len(e_timer_init_list) > 1:
                    diff_timer_init_list.append(e_timer_init_list[j]-start_list[j])
                if len(e_storage_list) > 1:
                    diff_storage_list.append(e_storage_list[j]-start_list[j])
            

            if len(diff_list) > 1  and scenario != "3":
                # evaluation for diff_list (cycles)
                median = np.round(np.median(diff_list, axis=0)).astype("int64")
                mean = np.round(np.mean(diff_list, axis=0)).astype("int64")
                std = np.round(np.std(diff_list, axis=0)).astype("int64")
                min = np.round(np.min(diff_list, axis=0)).astype("int64")
                max = np.round(np.max(diff_list, axis=0)).astype("int64")

                with open(Path("scenarios", level, scenario, f"evaluation_scenario_{scenario}.csv"), "a") as f2:
                    writer = csv.writer(f2)
                    writer.writerow([algo_name, mean, median, std, min, max])
            
            if len(diff_storage_list) > 1 and scenario == "3":
                # evaluation for diff_storage_list (cycles)
                median_storage = np.round(np.median(diff_storage_list, axis=0)).astype("int64")
                mean_storage = np.round(np.mean(diff_storage_list, axis=0)).astype("int64")
                std_storage = np.round(np.std(diff_storage_list, axis=0)).astype("int64")
                min_storage = np.round(np.min(diff_storage_list, axis=0)).astype("int64")
                max_storage = np.round(np.max(diff_storage_list, axis=0)).astype("int64")

                with open(Path("scenarios", level, scenario, f"evaluation_scenario_{scenario}_storage.csv"), "a") as f3:
                    writer = csv.writer(f3)
                    writer.writerow([algo_name, mean_storage, median_storage, std_storage, min_storage, max_storage])

            if len(diff_timer_init_list) > 1 and scenario == "3":
                # evaluation for diff_timer_init_list (cycles)
                median_timer_init = np.round(np.median(diff_timer_init_list, axis=0)).astype("int64")
                mean_timer_init = np.round(np.mean(diff_timer_init_list, axis=0)).astype("int64")
                std_timer_init = np.round(np.std(diff_timer_init_list, axis=0)).astype("int64")
                min_timer_init = np.round(np.min(diff_timer_init_list, axis=0)).astype("int64")
                max_timer_init = np.round(np.max(diff_timer_init_list, axis=0)).astype("int64")

                with open(Path("scenarios", level, scenario, f"evaluation_scenario_{scenario}_timer_init.csv"), "a") as f4:
                    writer = csv.writer(f4)
                    writer.writerow([algo_name, mean_timer_init, median_timer_init, std_timer_init, min_timer_init, max_timer_init])
