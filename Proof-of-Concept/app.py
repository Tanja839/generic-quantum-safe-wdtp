# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from argparse import ArgumentParser
from thespian.actors import Actor, ActorAddress, ActorSystem, ChildActorExited
from server import *
from device import *

import time
from typing import List, Dict, Tuple

import settings
from settings import S_STORAGE, D_STORAGE, STAGING_AREA, S_DATA_STORAGE, HEADER_SCENARIOS, START_MEASUREMENT, END_MEASUREMENT, M_APP_BENCHMARKING_SCENARIO
from modules.messagetypes import *
from modules.filehandling import FolderHandling as foha
from modules.filehandling import SaveTimes2File as save
from modules.filehandling import DataHandling as dh

parser_app = ArgumentParser(
    description=""" Starting the watchdog timer protocol with different crypto algorithms """)

parser_app.add_argument("--action", dest="action", default="boot", help="", choices=["boot", "update"])
parser_app.add_argument("--saveb", dest="save_boot", action="store_true", default=False, help="")
parser_app.add_argument("--saveu", dest="save_update", action="store_true", default=False, help="")
parser_app.add_argument("--crypto", dest="crypto", default="classic", help="", choices=["none", "pqc", "classic"])
parser_app.add_argument("--variant", dest="variant", default="secp256r1", help="")
parser_app.add_argument("--scenario", dest="scenario", type=int, help="", choices=[1, 2, 3, 4, 5, 6, 7, 8])
parser_app.add_argument("--hash", dest="hash_algo", default="sha256", help="", choices=["none","sha256", "sha384", "sha512"])
parser_app.add_argument("--unit", dest="unit", default="cycles", help="")

ARGS = parser_app.parse_args()
start_str = ARGS.action
crypto = ARGS.crypto
variant = ARGS.variant
settings.scenario = ARGS.scenario
hash_algo = ARGS.hash_algo
unit = ARGS.unit

settings.save_measurements = bool(ARGS.save_boot)
settings.save_update_measurements = bool(ARGS.save_update)
# app.py --action=boot --saveb

FILEPATH = fh.gen_filepath(unit, settings.scenario, variant, hash_algo, M_APP_BENCHMARKING_SCENARIO)

class TopLevelActor(Actor):

    def __init__(self) -> None:
        self.actor_name: str = "top_level_actor"

    def receiveMessage(self, message: Union[Dict[str, Any], ActorExitRequest, ChildActorExited], sender: ActorAddress) -> None:
        if isinstance(message, dict):
            print("[TopLevelActor] Instantiated")
            server_addr: ActorAddress = self.createActor('server.Server', globalName='Server')
            device_addr: ActorAddress = self.createActor('device.Device', globalName='Device')

            addresses: Addresses = Addresses(server_addr, device_addr)
        
            if message["start_str"] == "update":
                sequence_list: List = ["send_update"]
            else:
                sequence_list: List = ["boot"]

            print(f"[TopLevelActor] Sequence list: {sequence_list}")

            msg_obj: Message = Message(
                addresses=addresses,
                sequence_list=[sequence_list[0]],
                state = 0,
                signature = "",
                crypto = message["crypto"],
                variant = message["variant"],
                scenario = message["scenario"],
                hash_algo = message["hash_algo"],
                mdata = None)

            message_dict: Dict[str, Any] = Utils.pack_json(msg_obj)

            # Send message_dict for JSON (for communication without the Thespian framework)
            # and addresses for using the ActorAddress variables in the framework
            msg: Tuple[Dict, Addresses] = (message_dict, addresses)

            scenario_type: str = message_dict["sequence_list"][0]
            print(f"[TopLevelActor] Scenario {scenario_type} has been initialized.")

            if scenario_type == "send_update":
                send_to: ActorAddress = server_addr
                if settings.save_update_measurements:
                    Utils.start_counter: float = START_MEASUREMENT()
                    save.save_counter(FILEPATH, Utils.start_counter, "su")
                    print(f"[TopLevelActor] start update counter at: {Utils.start_counter}")
                print("[TopLevelActor] Send message to server ... ")
            else:
                send_to: ActorAddress = device_addr
                if settings.save_measurements and not (settings.scenario == 4 or settings.scenario == 5):
                    Utils.start_counter: float = START_MEASUREMENT()
                    save.save_counter(FILEPATH, Utils.start_counter, "sb")
                    print(f"[TopLevelActor] start boot counter at: {Utils.start_counter}")
                print("[TopLevelActor] Send message to device ... ")
            
            self.send(send_to, msg)

        
        if isinstance(message, ActorExitRequest):
            print("[TopLevelActor] Received ActorExitRequest.")
            if settings.save_measurements and not (settings.scenario == 3 or settings.scenario == 4):
                end_counter: float = END_MEASUREMENT()
                print(f"[TopLevelActor] end counter at: {end_counter}")
                save.save_counter(FILEPATH, end_counter, "eb")

            elif settings.save_update_measurements:
                end_counter: float = END_MEASUREMENT()
                print(f"[TopLevelActor] end counter at: {end_counter}")
                save.save_counter(FILEPATH, end_counter, "eu")

            if os.path.exists(alive_file):
                os.remove(alive_file)

            ActorSystem('multiprocTCPBase', {'Admin Port':1900}).shutdown()
        
        if isinstance(message, ChildActorExited):
            print(f"[TopLevelActor] Received ChildActorExited from {sender}")
            try: 
                self.send(self.myAddress, ActorExitRequest())
            except Exception as ex:
                print(f"[TopLevelActor] ActorSystem has not been shutdown. Exception: {ex}")
            

if __name__ == "__main__":
    # Create an empty file for a workaround
    alive_file = f"{os.getpid()}_still.alive"
    with open(alive_file, "wt") as file:
        file.write("")

    start_dict: Dict[str, Any] = {
        "start_str": start_str,
        "crypto": crypto,
        "variant": variant,
        "hash_algo": hash_algo,
        "scenario": settings.scenario
    }

    # Check if these folders exist, if not create them (for storing purposes)
    foha.createFolder(D_STORAGE)
    foha.createFolder(STAGING_AREA)
    foha.createFolder(S_STORAGE)
    foha.createFolder(S_DATA_STORAGE)
    
    print("[APP] Starting the ActorSystem without capabilities.")

    # Creating an actor system
    asys: ActorSystem = ActorSystem('multiprocTCPBase')

    # Create and tell top level actor as starting point for the device and server actors
    top_level_actor_addr: ActorAddress = asys.createActor(TopLevelActor, globalName='TopLevel')
    r = asys.tell(top_level_actor_addr, start_dict)
        
    # As long as the file exists, the app.py-Skript will not be ended.
    # To be sure that all child processes have been finished.
    while(os.path.exists(alive_file)):
        time.sleep(2)

    ActorSystem('multiprocTCPBase', {'Admin Port':1900}).shutdown()
    print("[APP] ActorSystem is shut down.")
    