# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from datetime import datetime
from secrets import token_urlsafe
from random import randint, choice
from pathlib import Path
from typing import Tuple, List

from settings import D_STORAGE, START_TIME_WDT, S_STORAGE
from modules.filehandling import FileHandling as fh
from modules.messagetypes import *

#################################################################################################
###                Generate Messagetypes python message object                       ###
#################################################################################################
# Standard update types (except LZ_core_update)
update_types: List[str] = ["LZ_updatedownloader_update", "LZ_cpatcher_update", "business_logic_update", "config_update", "LZ_core_update"]

class GenerateDeviceObjects():
    """
    These methods should only work on the device.
    
    """
    
    @staticmethod
    def gen_nonce(path: Path) -> Tuple[int, str]:
        """
        Generates, saves to file and returns a nonce.

        Parameters:
        -----------
        path: Path

        return:
        timestamp: int
        nonce: str

        """
        print("[DEVICE] NONCE GENERATOR")
        timestamp: int = int(datetime.now().timestamp())
        nonce: str = token_urlsafe(32) # Are 32 bytes sufficient for a random number?
        # Try to save the generated nonce to the secure device storage
        try: 
            fh.save_to_txtfile(nonce, "nonce", path)
        except:
            print("[DEVICE] Could not save the nonce to storage.")
        return timestamp, nonce

    @staticmethod
    def gen_request(msg_obj: Message, request_type: str) -> Message:        
        """
        Generates a message of type Message with the information for a new Request object.
        Request contains the type of the request object and a nonce.

        Parameters:
        -----------
        msg_obj: Message
        request_type: str ("update", "bootticket", "defticket")

        return:
        msg_obj: Message

        """
        print("[DEVICE] REQUEST GENERATOR")
        timestamp, nonce = GenerateDeviceObjects.gen_nonce(D_STORAGE)
        msg_obj.mdata = Request(request_type, timestamp, nonce)
        print(f"[DEVICE] Request {request_type} from the server.")
        return msg_obj

    @staticmethod
    def gen_measured_data(msg_obj: Message) -> Message:
        """
        Generates a message of type Message with the information for a new MeasuredData object.
        MeasuredData contains data from the measurements in units that are not defined because it is for prototyping purposes only.
        MeasuredData also contains the timestamp of when the specific measurement has been taken.

        Parameters:
        -----------
        msg_obj: Message

        return:
        msg_obj: Message

        """
        print("[DEVICE] MEASURED DATA")
        data: int = randint(4,14)
        timestamp: int = int(datetime.now().timestamp())
        msg_obj.mdata = MeasuredData(data, timestamp)
        return msg_obj

###########################################################################################
class GenerateServerObjects():
    """
    These methods should only work on the server.
    
    """

    @staticmethod
    def gen_update(msg_obj: Message) -> Message:
        """
        Generates a message of type Message with the information for a new Update object.
        Update contains the actual update - for the prototype it is just represented by a string -, the update_type, a version_nr and the timestamp of the time the update has been generated.

        Parameters:
        -----------
        msg_obj: Message

        return:
        msg_obj: Message

        """
        print("[SERVER] UPDATE GENERATOR")
        timestamp: int = int(datetime.now().timestamp())
        update: str = f"update_{str(timestamp)}"
        update_type: str = choice(update_types)
        # read from version and add a 1 for new version nr.
        stored_version_nr: str = fh.read_from_file("version.txt", D_STORAGE)
        stored_version_nr: str = fh.read_from_file("version.txt", S_STORAGE)
        version_nr: int = int(stored_version_nr) + 1
        msg_obj.mdata = Update(update, update_type, version_nr, timestamp)
        return msg_obj

    @staticmethod
    def gen_bootticket(msg_obj: Message) -> Message:
        """
        Generates a message of type Message with the information for a new BootTicket object.
        BootTicket contains the actual bootticket - for the prototype it is just represented by a string -, a nonce and the timestamp of the time the BootTicket has been generated.

        Parameters:
        -----------
        msg_obj: Message

        return:
        msg_obj: Message

        """
        if isinstance(msg_obj.mdata, Request):
            print("[SERVER] BOOT TICKET GENERATOR")
            timestamp: int = int(datetime.now().timestamp())
            bootticket: str = f"bootticket_{str(timestamp)}"
            nonce: str = msg_obj.mdata.nonce # contains only the nonce and not the time stamp
            start_time: int = START_TIME_WDT
            msg_obj.mdata = BootTicket(bootticket, nonce, timestamp, start_time)
        return msg_obj

    @staticmethod
    def gen_defticket(msg_obj: Message) -> Message:
        """
        Generates a message of type Message with the information for a new DefTicket object.
        DefTicket contains a nonce, the time the counter has be to deferred in seconds and the timestamp of the generation of the DefTicket.

        Parameters:
        -----------
        msg_obj: Message

        return:
        msg_obj: Message

        """
        if isinstance(msg_obj.mdata, Request):
            print("[SERVER] DEFERRAL TICKET GENERATOR")
            nonce: str = msg_obj.mdata.nonce # contains only the nonce and not the time stamp
            def_time: int = 25
            timestamp: int = int(datetime.now().timestamp())
            msg_obj.mdata = DefTicket(nonce, def_time, timestamp)
        return msg_obj