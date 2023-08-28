# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

from typing import Any, ClassVar, Dict, Tuple, Union
from modules.messagetypes import *
from thespian.actors import Actor, ActorExitRequest
from settings import SERVER, DEVICE

class Utils:

    start_counter: ClassVar[float] = 0

    @staticmethod
    def create_and_send(sender: Actor, host: str, target: type, message: Message, global_name = False):
        name: str = target.__name__
        try:
            if global_name:
                target_addr: ActorAddress = sender.createActor(target, globalName=name)
            else:
                target_addr: ActorAddress = sender.createActor(target)
        except:
                print(f"[{host}] Error: Could not create Actor '{name}'")
                return
        
        try:
            sender.send(target_addr, message)
        except:
            print(f"[{host}] Error: Could not send Message")
            return


    @staticmethod
    def create_and_sendActorExitRequest(sender: Actor, host: str, target: type, global_name = False):
        name: str = target.__name__
        try:
            if global_name:
                target_addr: ActorAddress = sender.createActor(target, globalName=name)
            else:
                target_addr: ActorAddress = sender.createActor(target)
        except:
                print(f"[{host}] Actor '{name}' could not be created.")
                return
        
        try:
            sender.send(target_addr, ActorExitRequest())
        except:
            print(f"[{host}] Error: Could not send ActorExitRequest")
            return

    @staticmethod
    def create_and_send_tuple(sender: Actor, send_from: str, message: Message, updated_message: Message, former_sender_addr: ActorAddress):
        # Save the ActorAddresses in a dictionary variable to send them with the json to the server via the network.
        addresses: Addresses = message.addresses
        # To send it via network to the device: obj -> json
        msg_json: Dict[str, Any] = Utils.pack_json(updated_message)
        # Send the signed message to the server.
        send_tuple: Tuple[Dict, Addresses] = (msg_json, addresses)
        if send_from is SERVER:
            # Send the tuple with Message and Addresses to the device
            print(f"[{send_from}] Send message to device.")
            sender.send(addresses.device_addr, send_tuple)
        elif send_from is DEVICE:
            # Send the tuple with Message and Addresses to the server
            print(f"[{send_from}] Send message to server.")
            sender.send(addresses.server_addr, send_tuple)
        # End the Signer actor, because it is no longer needed.
        sender.send(former_sender_addr, ActorExitRequest())

    @staticmethod
    def open_tuple(host: str, message: Tuple[Dict[str, Any], Addresses]) -> Message:
        try:
            # Should receive an initial message from server with a message and the addresses as Addresses-class
            (message_dict, addresses) = message 

            # Unpack the message_dict (json) to work with the python message object internally.
            # If you want to send it via the network, you need to transform it to the json format with pack_json. 
            msg_obj = Utils.unpack_json(message_dict, addresses)
            if not isinstance(msg_obj, Message):
                raise TypeError(f"{host} has not received a message")

            print(f"[{host}] device_addr: {addresses.device_addr}")
            print(f"[{host}] server_addr: {addresses.server_addr}")

            return msg_obj
            
        except:
            raise ValueError("[DEVICE] No Addresses in message")

    @staticmethod
    def unpack_json(msg: Dict[str, Any], addresses: Addresses):

        msg_type = msg["messagetype"]
        
        if msg_type == "message":
            sequence_list: List[str] = msg["sequence_list"]
            state: int = msg["state"]
            signature = msg["signature"] 
            crypto: str = msg["crypto"]
            variant: str = msg["variant"]
            scenario: int = msg["scenario"]
            hash_algo: str = msg["hash_algo"]
            mdata: Union[DefTicket, MeasuredData, Update, BootTicket, Request] = msg["data"]["mdata"] 
            return Message(addresses, sequence_list, state, signature, crypto, variant, scenario, hash_algo, mdata)

        elif msg_type == "request":
            requesttype: str = msg["data"]["requesttype"]
            timestamp: int = msg["data"]["timestamp"]
            nonce: str = msg["data"]["nonce"]
            return Request(requesttype, timestamp, nonce)

        elif msg_type == "update":
            update_type: str = msg["updatetype"] 
            update: str = msg["data"]["update"]
            version_nr: int = msg["versionnr"]
            timestamp: int = msg["data"]["timestamp"]
            return Update(update_type, update, version_nr, timestamp)

        elif msg_type == "addresses":
            server_addr: ActorAddress = msg["data"]["server_addr"] 
            device_addr: ActorAddress = msg["data"]["device_addr"] 
            return Addresses(server_addr, device_addr)

        elif msg_type == "defticket":
            nonce: str = msg["data"]["nonce"]
            deferral_time: int = msg["data"]["deferral_time"]
            timestamp: int = msg["data"]["timestamp"]
            return DefTicket(nonce, deferral_time, timestamp)

        elif msg_type == "bootticket":
            bootticket: str = msg["data"]["bootticket"]
            nonce: str = msg["data"]["nonce"]
            timestamp: int = msg["data"]["timestamp"]
            counter_init_time: int = msg["data"]["counter_init_time"]
            return BootTicket(bootticket, nonce, timestamp, counter_init_time)

        elif msg_type == "measured_data":
            measured_data: int = msg["data"]["measured_data"]
            timestamp: int = msg["data"]["timestamp"]
            return MeasuredData(measured_data, timestamp)

    @staticmethod
    def pack_json(msg_obj: Union[Message, Request, Update, Addresses, DefTicket, BootTicket, MeasuredData, None]): 
        msg: Dict[str, Any] = {}
        if msg_obj is not None:
            msg["messagetype"] = msg_obj.name
        else:
            msg["messagetype"] = "message"
            
        msg["data"] = {}
        if isinstance(msg_obj, Message):
            msg["addresses"] = {}
            msg["addresses"]["server_addr"] = str(msg_obj.addresses.server_addr)
            msg["addresses"]["device_addr"] = str(msg_obj.addresses.device_addr)
            msg["sequence_list"] = msg_obj.sequence_list
            msg["state"] = msg_obj.state
            msg["signature"] = msg_obj.signature
            msg["crypto"] = msg_obj.crypto
            msg["variant"] = msg_obj.variant
            msg["scenario"] = msg_obj.scenario
            msg["hash_algo"] = msg_obj.hash_algo
            msg["data"]["mdata"] = msg_obj.mdata
        
        elif isinstance(msg_obj, Request):
            msg["data"]["requesttype"] = msg_obj.requesttype
            msg["data"]["timestamp"] = msg_obj.timestamp
            msg["data"]["nonce"] = msg_obj.nonce

        elif isinstance(msg_obj, Update):
            msg["updatetype"] = msg_obj.update_type
            msg["versionnr"] = msg_obj.version_nr
            msg["data"]["update"] = msg_obj.update
            msg["data"]["timestamp"] = msg_obj.timestamp

        elif isinstance(msg_obj, Addresses):
            msg["data"]["server_addr"] = msg_obj.server_addr
            msg["data"]["device_addr"] = msg_obj.device_addr

        elif isinstance(msg_obj, DefTicket):
            msg["data"]["nonce"] = msg_obj.nonce
            msg["data"]["deferral_time"] = msg_obj.deferral_time
            msg["data"]["timestamp"] = msg_obj.timestamp

        elif isinstance(msg_obj, BootTicket):
            msg["data"]["bootticket"] = msg_obj.bootticket
            msg["data"]["nonce"] = msg_obj.nonce
            msg["data"]["timestamp"] = msg_obj.timestamp
            msg["data"]["counter_init_time"] = msg_obj.counter_init_time

        elif isinstance(msg_obj, MeasuredData):
            msg["data"]["measured_data"] = msg_obj.measured_data
            msg["data"]["timestamp"] = msg_obj.timestamp

        return msg
