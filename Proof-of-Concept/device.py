# SPDX-License-Identifier: BSD-3-Clause
# ****************************************************************************
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.
# All rights reserved.
# ---------------------------------------------------------------------------- 
# Author:        Tanja Gutsche               
# ****************************************************************************

#################################################################################################
###                                         IMPORTS                                           ###
#################################################################################################
## Framework ##
from thespian.actors import Actor, ActorAddress, ActorExitRequest, ChildActorExited, WakeupMessage

## Own classes ##
import settings
from settings import DEVICE, D_STORAGE, D_PRIV_KEY, S_PUB_KEY, STAGING_AREA, WAKEUP_DEF_REQUEST, WAKEUP_SENSOR, UNIT, END_MEASUREMENT, M_APP_BENCHMARKING_SCENARIO, START_MEASUREMENT
from modules.messagetypes import *
from modules.common import *
from modules.utils import Utils
from modules.filehandling import FileHandling as fh
from modules.filehandling import SaveTimes2File as save
from modules.generate_objects import GenerateDeviceObjects as gen_obj
from modules.crypto import SignMessage, VerifyMessage

## Helper classes ##
import os
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

#################################################################################################
###                                   DEVICE ACTOR TYPES                                      ###
#################################################################################################

class Device(Actor):    
    def __init__(self) -> None:
        self.actor_name: str = "device"

    def receiveMessage(self, message: Union[Tuple[Dict[str, Any], Addresses], Message, ActorExitRequest, ChildActorExited], sender: ActorAddress) -> None:

        if isinstance(message, tuple): 
            message: Message = Utils.open_tuple(DEVICE, message)         

        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if former == "reset":
                Utils.create_and_send(self, DEVICE, Shutdown, updated_message)

            elif former == "boot":
                Utils.create_and_send(self, DEVICE, Boot, updated_message)

            elif former == "server" and isinstance(updated_message.mdata, DefTicket):
                Utils.create_and_send(self, DEVICE, Verifier, updated_message)

            elif former == "server":
                Utils.create_and_send(self, DEVICE, StagingArea, updated_message)

            elif former == "signer":
                Utils.create_and_send_tuple(self, DEVICE, message, updated_message, sender)

            else:
                print("[DEVICE] Device Error")
                self.send(self.myAddress, ActorExitRequest())


class Boot(Device):
    def __init__(self) -> None:
        self.actor_name: str = "boot"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if former == "device":
                print("[DEVICE] BOOT PROCESS, DICE, DICE++ etc... ")
                Utils.create_and_send(self, DEVICE, StagingArea, updated_message)

class StagingArea(Device):
    def __init__(self) -> None:
        self.actor_name: str = "staging_area"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if former == "device":
                if isinstance(updated_message.mdata, Update):
                    print("[DEVICE] Save update in staging area.")
                    fh.save_object(updated_message, STAGING_AREA)

                if isinstance(updated_message.mdata, BootTicket):
                    print("[DEVICE] Save boot ticket in staging area.")
                    fh.save_object(updated_message, STAGING_AREA)

                Utils.create_and_send(self, DEVICE, Shutdown, updated_message)

            elif former == "boot":
                print("[DEVICE] Checking for elements in Staging Area")
                update_available: bool = False
                bt_available: bool = False
                update: Union[Message, None] = None
                bootticket: Union[Message, None] = None
                filtered_dir: List[str] = []

                # Check for elements (files) in staging area
                dir: list[str] = os.listdir(STAGING_AREA)
                # Exclude filenames starting with . e.g. .gitkeep or .gitignore
                for filename in dir:
                    if not filename.startswith("."):
                        filtered_dir.append(filename)

                if len(filtered_dir) == 0:
                    print("[DEVICE] No element in staging area")
                else:       
                    print(f"[DEVICE] Found {len(filtered_dir)} elements in staging area: {filtered_dir}")

                # If elements present: check which ones
                # Unpickle every object and save it to list "objects"
                objects: Optional[List[Any]] = [fh.pickle_file_to_object(file, STAGING_AREA) for file in filtered_dir]

                if objects != False:
                    for i in range(len(objects)):
                        if not isinstance(objects[i], Message):
                            print(f"[DEVICE] ERROR! Other type than Message in staging area! type: {type(objects[i])}")
                        
                        if isinstance(objects[i].mdata, Update):
                            update_available: bool = True
                            update = objects[i]

                        elif isinstance(objects[i].mdata, BootTicket):
                            bt_available: bool = True
                            bootticket = objects[i]

                    # Case 1: Update available in staging area
                    if update_available and (update is not None):
                        print("[DEVICE] Update available in staging area")
                        # Use signature and mdata from the update
                        updated_message.signature = update.signature
                        updated_message.mdata = update.mdata
                        Utils.create_and_send(self, DEVICE, Verifier, updated_message)

                    elif not update_available:
                        # Case 2: BootTicket available in staging area
                        if bt_available and (bootticket is not None):
                            print("[DEVICE] No update, but a BootTicket available in staging area")
                            # Use signature and mdata from the bootticket
                            updated_message.signature = bootticket.signature
                            updated_message.mdata = bootticket.mdata
                            Utils.create_and_send(self, DEVICE, Verifier, updated_message)

                        # Case 3: No update or BootTicket available in staging area -> ask server for new Bootticket
                        elif not bt_available:
                            print("[DEVICE] No Update or BootTicket available (or invalid) in staging area")
                            # Create empty BootTicket for generating request during the next step
                            updated_message.mdata = BootTicket("", "", 0, 0) 
                            Utils.create_and_send(self, DEVICE, UpdateDownloader, updated_message)
                    else:
                        print("[DEVICE] Element in Staging Area cannot be unpickled. Request a new Update because element could be compromised.")
                        # Create empty BootTicket for generating request during the next step
                        updated_message.mdata = Update("", "", 0, 0) 
                        Utils.create_and_send(self, DEVICE, UpdateDownloader, updated_message)

class Signer(Device):
    def __init__(self) -> None:
        self.actor_name: str = "signer"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "sensor" or former == "verifier" or former == "update_downloader" or former == "awdt_getnonce":
                try:
                    if (updated_message.variant != "none") and (updated_message.crypto != "none"):
                        updated_message: Message = SignMessage.sign(DEVICE, updated_message, D_STORAGE, D_PRIV_KEY, updated_message.variant, updated_message.crypto, updated_message.hash_algo)
                    else:
                        print("[DEVICE] Dummy function: Message will not be signed.")

                    self.send(updated_message.addresses.device_addr, updated_message)

                except Exception as ex:
                    print(f"[DEVICE] Message could not be signed. {ex}")

            else:
                print("[DEVICE] Signer Error")
                self.send(self.myAddress, ActorExitRequest())
        
        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, DEVICE, self.actor_name, self.myAddress)

class Sensor(Device):
    def __init__(self) -> None:
        self.actor_name: str = "sensor"

    def receiveMessage(self, message: Union[Message, WakeupMessage], sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if former == "business_logic":
                print("[DEVICE] Sensor: Start measuring")
                # Sensor start is taking a measurement
                msg_obj: Message = gen_obj.gen_measured_data(updated_message)
                Utils.create_and_send(self, DEVICE, Signer, msg_obj)
                # Sensor will be reminded to take a measurement every x seconds/minutes/etc.
                self.wakeupAfter(WAKEUP_SENSOR, msg_obj)
    
        if isinstance(message, WakeupMessage):
            if message.payload is not None:
                message.payload.state = message.payload.state - 1
                message.payload.sequence_list.pop(-1)
                # Sensor sends a message to self to take a measurement
                self.send(self.myAddress, message.payload)
            else:
                print("[DEVICE] Sensor Error")

class CorePatcher(Device):
    def __init__(self) -> None:
        self.actor_name: str = "core_patcher"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "verifier" and isinstance(updated_message.mdata, Update):
                # Assume the update will be installed here.
                print("[DEVICE] Apply and install update. Then reset the device... ")
                
                # Save the version number of the received update to the secure device storage for future reference
                try: 
                    fh.save_to_txtfile(str(updated_message.mdata.version_nr), "version", D_STORAGE)
                except:
                    print("Could not save the update version nr to storage.")

                # Delete the applied update from staging area
                os.remove(Path(STAGING_AREA, "update"))
                print("[DEVICE] Removed the applied update from the staging area.")

                Utils.create_and_send(self, DEVICE, Shutdown, updated_message)

            else:
                print("[DEVICE] CorePatcher Error")
                self.send(self.myAddress, ActorExitRequest())
        
        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, DEVICE, self.actor_name, self.myAddress)

class BusinessLogic(Device):
    def __init__(self) -> None:
        self.actor_name: str = "business_logic"
        
    def receiveMessage(self, message: Union[Message, WakeupMessage], sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "device" or former == "verifier":
                print("[DEVICE] Start the sensor")

                if isinstance(updated_message.mdata, BootTicket):
                    os.remove(Path(STAGING_AREA, "bootticket"))
                    print("[DEVICE] Removed applied boot ticket from staging area")

                Utils.create_and_send(self, DEVICE, Sensor, updated_message, True)
                # Parallel to this: Requesting a DeferralTicket after x seconds
                self.wakeupAfter(WAKEUP_DEF_REQUEST, updated_message)
            else:
                print("[DEVICE] BusinessLogic Error")

        if isinstance(message, WakeupMessage):
            print("[DEVICE] TIMER RECEIVED WAKEUPMESSAGE")
            if settings.save_measurements and (message.payload.scenario == 4 or message.payload.scenario == 5):
                filepath = fh.gen_filepath(UNIT, message.payload.scenario, message.payload.variant, message.payload.hash_algo, M_APP_BENCHMARKING_SCENARIO)                    
                Utils.start_counter: float = START_MEASUREMENT()
                save.save_counter(filepath, Utils.start_counter, "s_bl_wakeup")
                print(f"[DEVICE] start deferralticket counter at: {Utils.start_counter}")

            awdt_getnonce_addr: ActorAddress = self.createActor(AWDT_GetNonce)
            self.send(awdt_getnonce_addr, message.payload)
            self.wakeupAfter(WAKEUP_DEF_REQUEST, message.payload)

class UpdateDownloader(Device):
    def __init__(self) -> None:
        self.actor_name: str = "update_downloader"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if former == "verifier" and isinstance(updated_message.mdata, Update):
                request_type = updated_message.mdata.name

            elif (former == "verifier" or former == "staging_area") and isinstance(updated_message.mdata, BootTicket):
                request_type = updated_message.mdata.name

            else:
                print("[DEVICE] UpdateDownloader Error")
                return
            
            msg_obj: Message = gen_obj.gen_request(updated_message, request_type) 
            Utils.create_and_send(self, DEVICE, Signer, msg_obj)
            
class Timer(Device):
    def __init__(self) -> None:
        self.actor_name: str = "timer"
        self.time_to_reset: int = 0

    @staticmethod
    def check_countdown(countdown_time: int) -> bool:
        current_time: int = int(time.time())
        diff: int = countdown_time - current_time
        if (diff < 0):
            print("[DEVICE] Timer expired. Resetting device...")
            return True
        else:
            return False
    
    @staticmethod
    def defer_countdown(deferral_time: int) -> None:
        current_time: int = int(time.time())
        Timer.time_to_reset: int = current_time + deferral_time
        print(f'[DEVICE] Timer expires in {deferral_time:.4f} seconds.')
        Timer.check_countdown(Timer.time_to_reset)

    def receiveMessage(self, message: Union[Message, WakeupMessage, ActorExitRequest], sender: ActorAddress) -> None:
        if isinstance(message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            print("[DEVICE] Initialize AWDT!")
            if former == "awdt_init" and isinstance(updated_message.mdata, BootTicket):
                # Setting and starting the timer
                counter: int = updated_message.mdata.counter_init_time
                print(f"[DEVICE] Timer started: {counter} seconds until reset")
                current_time: int = int(time.time())
                # time in future until the timer has to be ended
                Timer.time_to_reset: int = current_time + counter 

            elif former == "awdt_putticket" and isinstance(updated_message.mdata, DefTicket):
                # (Re)setting the timer
                deferral_time: int = updated_message.mdata.deferral_time
                Timer.defer_countdown(deferral_time)
                
                # End the measurement here for scenario 4
                if updated_message.scenario == 4 and settings.save_measurements:
                    filepath = fh.gen_filepath(UNIT, updated_message.scenario, updated_message.variant, updated_message.hash_algo, M_APP_BENCHMARKING_SCENARIO)
                    end_counter: float = END_MEASUREMENT()
                    print(f"[DEVICE] In timer (deferred countdown) end counter at: {end_counter}")
                    save.save_counter(filepath, end_counter, "e_timer_def")
                    # End the scenario and the measurement
                self.send(updated_message.addresses.device_addr, ActorExitRequest())

            # Check if the timer has expired
            expired: bool = Timer.check_countdown(Timer.time_to_reset)
            # end measurement here

            if updated_message.scenario == 3:
                filepath = fh.gen_filepath(UNIT, updated_message.scenario, updated_message.variant, updated_message.hash_algo, M_APP_BENCHMARKING_SCENARIO)
                end_counter: float = END_MEASUREMENT()
                print(f"[DEVICE] In Timer: end counter at: {end_counter}")
                save.save_counter(filepath, end_counter, "e_timer_init")

            self.wakeupAfter(2, message)

        if isinstance(message, WakeupMessage):
            expired: bool = Timer.check_countdown(Timer.time_to_reset)
            if expired:
                try:
                    shutdown_addr: ActorAddress = self.createActor(Shutdown)
                    self.send(shutdown_addr, message.payload)

                except:
                    print("Could not create actor 'Shutdown'")
            else:
                self.wakeupAfter(2, message.payload)


class Shutdown(Device):
    def __init__(self) -> None:
        self.actor_name: str = "shutdown"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            print("[DEVICE] Resetting device.")
            # Alternative: To reset and boot new, send a Message to device (device will check for former actor and send a new boot message)
            # self.send(updated_message.addresses.device_addr, updated_message)
            
            # To end the ActorSystem end the device, timer and sensor
            self.send(updated_message.addresses.device_addr, ActorExitRequest())
            # Call the global names to shut them down
            Utils.create_and_sendActorExitRequest(self, DEVICE, Timer, True)
            Utils.create_and_sendActorExitRequest(self, DEVICE, Sensor, True)


class AWDT_Init(Device):
    def __init__(self) -> None:
        self.actor_name: str = "awdt_init"
    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "verifier":
                Utils.create_and_send(self, DEVICE, Timer, updated_message, True)

        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, DEVICE, self.actor_name, self.myAddress)

class AWDT_GetNonce(Device):
    def __init__(self) -> None:
        self.actor_name: str = "awdt_getnonce"
    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)

            if former == "business_logic":
                msg_obj: Message = gen_obj.gen_request(updated_message, "defticket")
                Utils.create_and_send(self, DEVICE, Signer, msg_obj)

            else:
                print("[DEVICE] AWDT_GetNonce Error")
                self.send(self.myAddress, ActorExitRequest())

        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, DEVICE, self.actor_name, self.myAddress)

class AWDT_PutTicket(Device):
    def __init__(self) -> None:
        self.actor_name: str = "awdt_putticket"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)
            if former == "verifier":
                Utils.create_and_send(self, DEVICE, Timer, updated_message, True)

            else:
                print("[DEVICE] AWDT_PutTicket Error")
                self.send(self.myAddress, ActorExitRequest())

        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, DEVICE, self.actor_name, self.myAddress)

class Verifier(Device):
    def __init__(self) -> None:
        self.actor_name: str = "verifier"

    def receiveMessage(self, message, sender: ActorAddress) -> None:
        if isinstance (message, Message):
            updated_message, former = former_step(message, sender, self.myAddress, self.actor_name)        
            try:
                if (updated_message.variant != "none") and (updated_message.crypto != "none"):
                    # Verify signature of the received message with pub key of the server
                    msg_valid = VerifyMessage.verify(DEVICE, updated_message, D_STORAGE, S_PUB_KEY, updated_message.variant, updated_message.crypto, updated_message.hash_algo)
                else:
                    msg_valid = True
                    print("[DEVICE] Dummy function: No verification needed.")
                    
                if former == "staging_area" and isinstance(updated_message.mdata, Update):
                    # Verify new version number with the stored former version number
                    stored_version_nr: str = fh.read_from_file("version.txt", D_STORAGE) 

                    # If newly received version number is one higher than the stored one: version is valid ATTENTION: Only for this settings possible, changes might need to be applied if used in real systems.
                    if int(stored_version_nr)+1 == int(updated_message.mdata.version_nr):
                        version_valid = True

                    # If no crypto should be used: Assume version number is valid
                    elif (updated_message.variant == "none") and (updated_message.crypto == "none"):
                        version_valid = True
                    else:
                        version_valid = False

                    if (msg_valid == True) and (version_valid == True):
                        print(f"[DEVICE] Valid update: {msg_valid}")
                        Utils.create_and_send(self, DEVICE, CorePatcher, updated_message)
                        
                    elif (msg_valid == False) or (version_valid == False):
                        # Remove the invalid update from staging area
                        os.remove(Path(STAGING_AREA, "update"))
                        print("[DEVICE] Removed the invalid update from the staging area.")
                        # Empty Update for generating request during the next step
                        updated_message.mdata = Update("", "", 0, 0) 

                        print("[DEVICE] Invalid update: Execute UpdateDownloader and request a new update.")
                        Utils.create_and_send(self, DEVICE, UpdateDownloader, updated_message)

                elif former == "staging_area" and isinstance(updated_message.mdata, BootTicket):
                    if (updated_message.variant == "none") and (updated_message.crypto == "none"):
                        bt_valid = True
                    else:
                        # Verify nonce of the received message with the stored nonce
                        stored_nonce: str = fh.read_from_file("nonce.txt", D_STORAGE)
                        received_nonce: str = updated_message.mdata.nonce
                        bt_valid: bool = equal(stored_nonce, received_nonce)
                        print(f"stored nonce: {stored_nonce}")
                        print(f"received nonce: {received_nonce}")

                    if (bt_valid == True) and (msg_valid == True):
                        print(f"[DEVICE] Valid bootticket: {msg_valid}")
                        Utils.create_and_send(self, DEVICE, AWDT_Init, updated_message)
                        Utils.create_and_send(self, DEVICE, BusinessLogic, updated_message)

                    elif (bt_valid == False) or (msg_valid == False):
                        print(f"[DEVICE] Invalid bootticket: execute UpdateDownloader")
                        # Remove the invalid bootticket from staging area
                        os.remove(Path(STAGING_AREA, "bootticket"))
                        print("[DEVICE] Removed the invalid bootticket from the staging area.")

                        # Create a message to create a bootticketrequest during the next step
                        updated_message.mdata = BootTicket("", "", 0, 0)
                        Utils.create_and_send(self, DEVICE, UpdateDownloader, updated_message)

                elif former == "device" and isinstance(updated_message.mdata, DefTicket):
                    if (updated_message.variant == "none") and (updated_message.crypto == "none"):
                        dt_valid = True
                    else:
                        # Verify nonce of the received message with the stored nonce
                        stored_nonce: str = fh.read_from_file("nonce.txt", D_STORAGE)
                        received_nonce: str = updated_message.mdata.nonce
                        dt_valid: bool = equal(stored_nonce, received_nonce)
                    
                    if dt_valid:
                        print(f"[DEVICE] DefTicket valid: {dt_valid} => Valid deferral ticket for AWDT.")
                        Utils.create_and_send(self, DEVICE, AWDT_PutTicket, updated_message)

                    else:
                        print("[DEVICE] DeferraltTicket not valid.")

            except:
                print("[DEVICE] Verifier Error")
                self.send(self.myAddress, ActorExitRequest())

        if isinstance(message, ChildActorExited):
            send_ActorExitRequest(self, DEVICE, self.actor_name, self.myAddress)