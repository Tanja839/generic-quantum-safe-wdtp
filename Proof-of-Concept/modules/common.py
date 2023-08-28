# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from pathlib import Path
from typing import Any, List, Tuple, Union

from thespian.actors import ActorExitRequest, ActorAddress, Actor

from modules.messagetypes import *

def equal(stored: Union[bytes, str, int], received: Union[bytes, str, int]) -> bool:
    """
    Checks if two strings are equal and returns True or False
    """
    if stored == received:
        print("[DEVICE] Stored and received nonce are the same.")
        return True
    else:
        print("[DEVICE] Stored and received nonce are NOT the same or could not read file or no nonce in bootticket.")
        return False

def former_step(message: Message, sender: ActorAddress, own_addr: ActorAddress, actor_name: str) -> Tuple[Message, str]:
    message.sequence_list.append(actor_name)
    former_state: int = message.state
    actual_state: int= message.state + 1
    former: str = ""
    if actual_state < len(message.sequence_list):
        former: str = message.sequence_list[former_state]
        message.state = actual_state
    else:
        print(f"{actual_state}: {message.sequence_list[actual_state]} addr: {own_addr} received from {sender}, no former step")

    return message, former

def send_ActorExitRequest(sender: Actor, host: str, actor_name: str, actor_address: ActorAddress) -> None:
    #print(f"[{host}] Received ChildActorExited: Shutting down actor {actor_name} with actoraddr: {actor_address}...")
    sender.send(actor_address, ActorExitRequest())

def data_processing(message: Message, path: Path, filename: str) -> None:
    if isinstance(message.mdata, MeasuredData):
        data: int = message.mdata.measured_data # data could by anything, but take only int here
        timestamp: int = message.mdata.timestamp

        with open(Path(path, f"{filename}.txt"), 'wt') as file:
            file.write(f"{data};{timestamp}\n")

        print(f"[SERVER] Data has been stored! {data};{timestamp}")

def copy_file_from_memory2temp(src: Path, dest: Path):
    src_path = Path("memory", src)
    dst_path = Path("temp", dest)
    shutil.copy(src_path, dst_path)
