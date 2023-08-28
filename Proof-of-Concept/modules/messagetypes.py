# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

import enum
from typing import List, Optional, Union
from thespian.actors import ActorAddress

class MsgTypes(enum.Enum):
   Message = "message"
   Request = "request"
   Addresses = "addresses"
   DefTicket = "def_ticket"
   Update = "update"
   BootTicket = "boot_ticket"

class Request(object):
    """
    A class to save requests for different messagetypes.

    Attributes:
    -----------
    requesttype: str
        Can be "bootticketrequest", "updaterequest", "defticketrequest"
    nonce: 
        A random generated nonce 
    """
    name: str = "request"
    def __init__(self, requesttype: str, timestamp: int, nonce: str) -> None:
        self.requesttype = requesttype
        self.timestamp = timestamp
        self.nonce = nonce

class Addresses(object):
    """
    A class to save addresses of actor systems.

    Attributes:
    -----------
    server_addr: 
        Address of the server
    device_addr:
        Address of the device (client)
    """
    
    @property
    def name(self) -> str:
        return self.__name

    def __init__(self, server_addr: ActorAddress, device_addr: ActorAddress) -> None:
        self.__name: str = "addresses"

        self.server_addr = server_addr
        self.device_addr = device_addr        

class DefTicket(object):
    """
    A class to specify the time the watchdog timer has to add to the current counter to defer the reset and set up the countdown.

    Attributes:
    -----------
    deferral_time: int
        Time in seconds
    nonce: str
        A nonce
    timestamp: int
        Time stamp (epoch time) of the creation of the DefTicket object
    """
    name: str = "defticket"
    def __init__(self, nonce: str, deferral_time: int, timestamp: int) -> None:
        self.nonce = nonce
        self.deferral_time = deferral_time
        self.timestamp= timestamp

class MeasuredData(object):
    """
    A class to send the data that has been measured by the sensor of the device to send to the server for storage.

    Attributes:
    -----------
    measured_data: 
        Measured data (unit not specified)
    timestamp: 
        Time stamp (epoch time) of the creation of the MeasuredData object
    """
    name: str = "measured_data"
    def __init__(self, measured_data: int, timestamp: int) -> None:
        self.measured_data = measured_data
        self.timestamp = timestamp

class Update(object):
    """
    A class to send a new update from the server to the device.

    Attributes:
    -----------
    update_type: str
        What type of update has been sent, different origin senders possible.
    update: 
        Update (appearance or unit or datatype not specified)
    version_nr: int
        Each update type has an ascending number attached to it.
    timestamp:
        Time stamp (epoch time) of the creation of the MeasuredData object
    """
    name: str = "update"
    def __init__(self, update_type: str, update: str, version_nr: int, timestamp: int) -> None:
        self.update_type = update_type
        self.update = update
        self.version_nr = version_nr
        self.timestamp = timestamp

class BootTicket(object):
    """
    A class to send a new boot ticket from the server to the device.

    Attributes:
    -----------
    bootticket: 
        Boot ticket (appearance or unit or datatype not specified)
    nonce:
        Contains the nonce from the device which requested the boot ticket.
    timestamp:
        Time stamp (epoch time) of the creation of the MeasuredData object
    """
    name: str = "bootticket"
    def __init__(self, bootticket: str, nonce: str, timestamp: int, counter_init_time: int) -> None:
        self.bootticket = bootticket
        self.nonce = nonce
        self.timestamp = timestamp
        self.counter_init_time = counter_init_time

class Message(object):
    """
    A class to save messages with different content to send between server and device.
    This class will be packed to json before being send between server and device and unpacked to object afterwards.

    Attributes:
    -----------
    addresses: Addresses
        Contains the class Addresses with its content. If it is being sent between server and device it contains a dictionary of strings.
    sequence_list: list
        A list of the order a scenario needs to follow; a list of strings
    state: int
        Indicates at which position in the sequence_list one is currently located 
    signature:
        Signature of the data stored in mdata
    mdata: 
        Can be any class obejct from the messagetypes.py file:
        - DefTicket
        - MeasuredData
        - Update
        - BootTicket
        - Request
    """
    name: str = "message"
    def __init__(self, addresses: Addresses, sequence_list: List[str], state: int, signature: str, crypto: str, variant: str, scenario: Optional[int], hash_algo: str, mdata: Union[DefTicket, MeasuredData, Update, BootTicket, Request, None]) -> None:
        self.addresses = addresses
        self.sequence_list = sequence_list
        self.state = state             
        self.signature = signature
        self.crypto = crypto
        self.variant = variant
        self.scenario = scenario
        self.hash_algo = hash_algo
        self.mdata = mdata    