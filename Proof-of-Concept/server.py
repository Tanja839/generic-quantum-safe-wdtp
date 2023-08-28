# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from thespian.actors import ActorExitRequest, Actor, ChildActorExited, ActorAddress
from typing import Any, Dict, Tuple, Union
import os

from settings import UNIT, SERVER, MEASURED_DATA, S_STORAGE, S_PRIV_KEY, D_PUB_KEY, S_DATA_STORAGE, END_MEASUREMENT, M_APP_BENCHMARKING_SCENARIO
from modules.crypto import SignMessage, VerifyMessage
from modules.generate_objects import GenerateServerObjects as gen_obj
from modules.filehandling import FileHandling as fh
from modules.filehandling import SaveTimes2File as save
from modules.common import *
from modules.utils import Utils
from modules.messagetypes import *

class Server(Actor):
    def __init__(self) -> None:
        self.actor_name: str = "server"
    
    def receiveMessage(self, message: Union[Tuple[Dict[str, Any], Addresses], Message, ChildActorExited, str], sender: ActorAddress) -> None:
        
        if isinstance(message, str):
            print(f"[{__name__}] {message}")

        if isinstance(message, tuple):
            message: Message = Utils.open_tuple(SERVER, message) 

        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "send_update":
                Utils.create_and_send(self, SERVER, UpdateGenerator, updated_message)

            elif former == "signer":
                # Pack tuple to send message and addresses to device
                Utils.create_and_send_tuple(self, SERVER, message, updated_message, sender)

            elif former == "device":
                Utils.create_and_send(self, SERVER, Verifier, updated_message)

        #if isinstance(message, ChildActorExited): 
            # Do not kill yourself if ChildActorExited


class BootTicketGenerator(Server):
    def __init__(self) -> None:
        self.actor_name: str = "gen_bootticket"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            
            if former == "verifier":
                new_message: Message = gen_obj.gen_bootticket(updated_message)
                # Save bootticket for future reference
                fh.save_object(updated_message, S_STORAGE)
                Utils.create_and_send(self, SERVER, Signer, new_message)

            else:
                print("[SERVER] BootTicketGenerator Error")
                self.send(self.myAddress, ActorExitRequest())

        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, SERVER, self.actor_name, self.myAddress)

class UpdateGenerator(Server):
    def __init__(self) -> None:
        self.actor_name: str = "gen_update"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if former == "verifier" or former == "server":
                new_message: Message = gen_obj.gen_update(updated_message)
                # Save update for future reference
                fh.save_object(updated_message, S_STORAGE)
                Utils.create_and_send(self, SERVER, Signer, new_message)

            else:
                print("[SERVER] UpdateGen Error")
                self.send(self.myAddress, ActorExitRequest())

        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, SERVER, self.actor_name, self.myAddress)

class Storage(Server):
    def __init__(self) -> None:
        self.actor_name: str = "storage"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "verifier":
                if isinstance(updated_message.mdata, MeasuredData):
                    data_processing(updated_message, S_DATA_STORAGE, MEASURED_DATA)
                    if updated_message.scenario == 3:
                        filepath = fh.gen_filepath(UNIT, updated_message.scenario, updated_message.variant, updated_message.hash_algo, M_APP_BENCHMARKING_SCENARIO)
                        end_counter: float = END_MEASUREMENT()
                        print(f"[SERVER] In storage end counter at: {end_counter}")
                        save.save_counter(filepath, end_counter, "e_storage")

                    if (updated_message.scenario == 4) or (updated_message.scenario == 5):
                        self.send(sender, ActorExitRequest())
                        self.send(self.myAddress, ActorExitRequest())
                    else:
                        # To end the actorsystem after one measurement: (but thats not good for scenario 4 and 5)
                        self.send(updated_message.addresses.device_addr, ActorExitRequest())

                else:
                    print("[SERVER] Storage Error")
                    self.send(self.myAddress, ActorExitRequest())
               
class DeferralTicketGenerator(Server):
    def __init__(self) -> None:
        self.actor_name: str = "gen_defticket"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            
            if former == "verifier":
                new_message: Message = gen_obj.gen_defticket(updated_message)
                Utils.create_and_send(self, SERVER, Signer, new_message)
            else:
                print("[SERVER] DefTicketGen Error")
                self.send(self.myAddress, ActorExitRequest())

        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, SERVER, self.actor_name, self.myAddress)

class Verifier(Server):
    def __init__(self) -> None:
        self.actor_name: str = "verifier"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance(message, Message):
            if (message.variant != "none") and (message.crypto != "none"):
                valid = VerifyMessage.verify(SERVER, message, S_STORAGE, D_PUB_KEY, message.variant, message.crypto, message.hash_algo)

            else:
                print("[SERVER] Dummy function: No verification needed.")
                valid = True

            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if (not valid) or (former != "server"):
                print("[SERVER] Verifier Error or verification not successful.")
                self.send(self.myAddress, ActorExitRequest())
                return # Ends the method

            if former == "server":
                if isinstance(updated_message.mdata, Request):
                    request_type: str = updated_message.mdata.requesttype
                    if valid and not os.path.exists(Path(S_DATA_STORAGE, "compromised.device")):
                        print(f"[SERVER] {request_type.capitalize()} request has been verified: {valid}")
                        if request_type == "update":
                            Utils.create_and_send(self, SERVER, UpdateGenerator, updated_message)

                        elif request_type == "bootticket":
                            Utils.create_and_send(self, SERVER, BootTicketGenerator, updated_message)

                        elif request_type == "defticket":
                            Utils.create_and_send(self, SERVER, DeferralTicketGenerator, updated_message)
                    else:
                        print(f"[SERVER] {request_type.capitalize()} request has NOT been verified: Device might be compromised.")
                        # End the measurement here for scenario 5
                        if updated_message.scenario == 5:
                            filepath = fh.gen_filepath(UNIT, updated_message.scenario, updated_message.variant, updated_message.hash_algo, M_APP_BENCHMARKING_SCENARIO)
                            end_counter: float = END_MEASUREMENT()
                            print(f"[SERVER] In verifier (request defticket) end counter at: {end_counter}")
                            save.save_counter(filepath, end_counter, "e_device_compromised")

                            self.send(updated_message.addresses.device_addr, ActorExitRequest())
                        # End scenario 5 and the measurement

                elif isinstance(updated_message.mdata, MeasuredData):
                    if valid and not os.path.exists(Path(S_DATA_STORAGE, "compromised.device")):
                        print(f"[SERVER] MeasuredData has been verified: {valid}")
                        Utils.create_and_send(self, SERVER, Storage, updated_message)
                    else:
                        print(f"[SERVER] MeasuredData has NOT been verified: Device might be compromised.")

            
        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, SERVER, self.actor_name, self.myAddress)

class Signer(Server):
    def __init__(self) -> None:
        self.actor_name: str = "signer"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "gen_update" or former == "gen_bootticket" or former == "gen_defticket":
                if (updated_message.variant != "none") and (updated_message.crypto != "none"):
                    updated_message = SignMessage.sign(SERVER, updated_message, S_STORAGE, S_PRIV_KEY, updated_message.variant, updated_message.crypto, updated_message.hash_algo)
                else:
                    print("[DEVICE] Dummy function: Message will not be signed.")

                self.send(updated_message.addresses.server_addr, updated_message)

            else:
                print("[SERVER] Signer Error")
                self.send(self.myAddress, ActorExitRequest())
        
