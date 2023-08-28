# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from pathlib import Path
import pickle
from typing import List, Dict, Any, Union
import csv
import os
import json
from pandas import read_csv

from modules.messagetypes import Message

class FileHandling():
    @staticmethod
    def save_object(obj_to_save: Message, path: Path) -> bool:
        """
        Save a message with pickle to store and restore it later.
        
        Parameters:
        -----------
        obj_to_save:
            Object which can be dumped to a pickle file. Can be of type Message.
        path: str
            Path were the object should be saved to.
        """
        if obj_to_save.mdata is None:
            filename: str = obj_to_save.name
        else: 
            filename: str = obj_to_save.mdata.name

        try:
            with open(Path(path, filename), "wb") as file:
                pickle.dump(obj_to_save, file, protocol=pickle.HIGHEST_PROTOCOL)

            return True

        except Exception as ex:
            print("Error during pickling object (Possibly unsupported): ", ex)
            return False

    @staticmethod
    def pickle_file_to_object(filename_pickle: str, path: Path): # return Any?
        """
        Checks what type of message is stored in the pickle file and loads it into an object variable
        
        Parameters:
        -----------
        filename_pickle: str
            Name of the file the content should be upacked and passed to a object than can be saved as a variable.
        path: str
            Contains the path where the file is located.
        """
        try:
            with open(Path(path, filename_pickle), "rb") as file:
                data = pickle.load(file, encoding="bytes")
                return data
        except Exception as ex:
            print("Error during unpickling object (Possibly unsupported): ", ex)
            return False

    @staticmethod
    def save_to_txtfile(data: str, filename: str, path: Path) -> bool:
        """
        Saves data to a textfile in the given path and with the given filename.
        Parameters:
        data: 
            Data which will be written to the file.
        filename: str
            Name of the file in which the data will be written.
        path: str
            Path were the textfile with the data should be saved to.
        """
        try:
            with open(Path(path, f"{filename}.txt"), "wt") as file:
                file.write(data)
            return True
            
        except Exception as ex:
            print("Error during writing file: ", ex)
            return False

    @staticmethod
    def read_from_file(filename: str, path: Path) -> str:
        """
        Reads data to a variable from a textfile from the given path and with the given filename.
        filename: str
            Name of the file from which the data will be read.
        path: str
            Contains the path where the file is located.

        Returns a str with data.
        If reading from the file is not possible then write "0" to the file and return "0".
        """
        try:
            with open(Path(path, f"{filename}"), "rt") as file:
                data: str = file.read()
            return data

        except Exception as ex:
            with open(Path(path, f"{filename}"), "wt") as file:
                file.write("0")
            # print("Error during writing file: ", ex)
            return "0"
    
    @staticmethod
    def save_to_json(data: Dict[str, Any], path: Path, filename: str) -> None:
        dir: Path = Path(path)
        if not os.path.exists(dir):
            os.makedirs(dir)

        with open(Path(path, f"{filename}.json"), "w") as file:
            json.dump(data, file)

    @staticmethod
    def save_to_format(data: Any, path: Path, filename: str, format: str) -> None:
        if not os.path.exists(path):
            os.mkdir(path)
        with open(Path(path, f"{filename}.{format}"), "wb") as file:
            file.write(data)

    @staticmethod
    def gen_filepath(unit: str, scenario: int, variant: str, hash_algo: str, path: Path):
        filename: str = f"{unit}_{scenario}_{variant}_{hash_algo}"
        filepath: Path = Path(path, filename)
        return filepath

class DataHandling():
    @staticmethod
    def set_header(file_path: Path, header: List[str]) -> None:
        # Open the file in the write mode
            
        with open(f"{file_path}.csv", 'w') as f:
            # Create the csv writer
            writer = csv.writer(f)

            # Write a header row to the csv file
            writer.writerow(header)

    @staticmethod
    def save_to_csv_functions(path: Path, no: int, algo_name: str, gen_keypair_s: float, sign_s: float, verify_s: float, valid: str) -> None:
        # Open the file in the write mode
        with open(f'{path}/{algo_name}.csv', 'a', encoding='UTF8', newline='') as f:
            # create the csv writer
            writer = csv.writer(f)

            # Write a header row to the csv file
            writer.writerow([no, algo_name, gen_keypair_s, sign_s, verify_s, valid])

    @staticmethod
    def save_to_csv_evaluation(path: Path, algo_name: str, mean: int, median: int, std: int, min: int, max: int) -> None:
        # Open the file in the write mode
        with open(f'{path}/{algo_name}.csv', 'a', encoding='UTF8', newline='') as f:
            # Create the csv writer
            writer = csv.writer(f)

            # Write a header row to the csv file
            writer.writerow([algo_name, mean, median, std, min, max])

class FolderHandling():
    @staticmethod
    def createFolder(path: Path) -> None:
        if not os.path.exists(path):
            os.makedirs(path)

class SaveTimes2File():
    @staticmethod
    def save_counter(file_path: Path, start_counter: float, type: str) -> None:
        if not os.path.exists(f"{file_path}.csv"):
            with open(f"{file_path}.csv", 'wt') as file:
                file.write(f"{type},{start_counter},")
        with open(f"{file_path}.csv", 'at') as file:
            file.write(f"{type},{start_counter},")
