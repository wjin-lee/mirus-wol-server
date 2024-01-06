import datetime
from enum import Enum
import platform
import queue
import socket
import argparse
import logging
from logging.handlers import RotatingFileHandler
import subprocess
import threading
import traceback
import firebase_admin
from firebase_admin import credentials
from firebase_admin import db
from firebase_admin.db import Event

UDP_PORT = 9  # Discard service port
LOG_FILE = "wol_server.log"
MAX_LOG_FILE_SIZE = 50000000  # Bytes
BROADCAST_ADDR = "255.255.255.255"

# Logger Setup
logger = logging.getLogger("wol_server_logger")
logger.setLevel(logging.DEBUG)

logfile_handler = RotatingFileHandler(LOG_FILE, maxBytes=MAX_LOG_FILE_SIZE)
logfile_handler.setLevel(logging.DEBUG)
logfile_handler.setFormatter(
    logging.Formatter("%(asctime)s: [%(levelname)s] %(message)s")
)
logger.addHandler(logfile_handler)


class PowerState(Enum):
    UNKNOWN = -1
    OFFLINE = 0
    ONLINE = 1


class RequestType(Enum):
    WAKE_ON_LAN = ("WAKE_ON_LAN",)
    DEVICE_STATUS_UPDATE = ("DEVICE_STATUS_UPDATE",)

    def strToRequestType(string: str):
        if string == "WAKE_ON_LAN":
            return RequestType.WAKE_ON_LAN
        elif string == "DEVICE_STATUS_UPDATE":
            return RequestType.DEVICE_STATUS_UPDATE
        else:
            raise ValueError(f"Cannot convert '{string}' into a RequestType!")


class RequestStatus(Enum):
    QUEUED = (0,)
    PROCESSING = (1,)
    COMPLETED = 2

    def intToRequestStatus(value: int):
        if value == 0:
            return RequestStatus.QUEUED
        elif value == 1:
            return RequestStatus.PROCESSING
        elif value == 2:
            return RequestStatus.COMPLETED
        else:
            raise ValueError(f"Cannot convert '{value}' into a RequestStatus!")


class WakeOnLanTarget:
    def __init__(self, name, ip, mac):
        self.name = name
        self.ip = ip  # Static IP used to check if device is online
        self.mac = mac


class WakeOnLanRequest:
    def __init__(self, timestamp: int, device: str, status: int, type: str):
        self.timestamp = timestamp
        self.device = device
        self.status = RequestStatus.intToRequestStatus(status)
        self.type = RequestType.strToRequestType(type)


# Network Util Functions
def is_device_online(device: WakeOnLanTarget):
    """Pings a device to check if it is online. True if ping is returned, false otherwise.
    NOTE: Blocking.
    """
    operating_system = platform.system()
    try:
        if operating_system == "Windows":
            result = subprocess.check_output(["ping", "-n", "1", "-w", "1", device.ip])
        elif operating_system == "Linux":
            result = subprocess.check_output(["ping", "-c", "1", "-W", "1", device.ip])
        else:
            raise Exception(f"Unsupported operating system: {operating_system}")

        # ping returns exit code 0 even when the host unreachable as destination is in local subnet.
        # An additional check is required to see if it failed or not.
        return str(result).lower().find("ttl") != -1

    except subprocess.CalledProcessError:
        return False


def send_wol_packet(wol_target: WakeOnLanTarget) -> None:
    magic_packet = b"".join([b"\xFF\xFF\xFF\xFF\xFF\xFF"] + [wol_target.mac] * 16)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # Allow broadcasts
        s.setblocking(False)
        s.sendto(magic_packet, (BROADCAST_ADDR, UDP_PORT))


class WakeOnLanServer:
    wol_targets = {}  # Maps wol target name to instance
    requests = {}  # Stores actual information on requests
    requestQueue = queue.Queue()  # List of IDs to process

    def register_wol_target(self, wol_target: WakeOnLanTarget):
        """Registers a Wake-on-Lan target with the server"""
        self.wol_targets[wol_target.name] = wol_target
        logger.info(
            f"Registered ({wol_target.name}, {wol_target.ip}, {wol_target.mac})"
        )

    def get_device_power_state(self, device: WakeOnLanTarget) -> PowerState:
        """Determines a device's power state"""
        return PowerState.ONLINE if is_device_online(device) else PowerState.OFFLINE

    def update_device_power_state(
        self, device: WakeOnLanTarget, power_state: PowerState
    ) -> None:
        """Updates a device's power state on the RTDB"""

        ref = db.reference(f"powerStates/{device.name}")
        ref.set(power_state.value)
        logger.info(f"Updated {device.name}'s power state to be {power_state}")

    def update_request_progress(self, requestId: str, status: RequestStatus) -> None:
        """Updates a requests status.
        NOTE: Completed orders are deleted.
        """

        if status == RequestStatus.PROCESSING:
            logger.debug(f"PROCESSING {requestId}")
            ref = db.reference(f"requests/{requestId}/status")
            ref.set(status.value)
            self.requests[requestId].status = RequestStatus.PROCESSING
            logger.info(f"Updated {requestId}'s power state to be {status}")

        elif status == RequestStatus.COMPLETED:
            # Delete to conserve space
            logger.debug(f"DELETE {requestId}")
            ref = db.reference(f"requests/{requestId}")
            ref.delete()
            del self.requests[requestId]
            logger.info(f"Updated {requestId}'s power state to be {status}")

        else:
            logger.warning(
                f"Invalid request progress '{status}' encountered during update"
            )

    def handle_request(self):
        """Process incoming requests"""
        while True:
            requestId = self.requestQueue.get()  # Blocks until request is available
            try:
                # Notify UI that it is now getting processed
                self.update_request_progress(requestId, RequestStatus.PROCESSING)

                request: WakeOnLanRequest = self.requests[requestId]
                device = self.wol_targets[request.device]
                if request.type == RequestType.WAKE_ON_LAN:
                    logger.info(f"Broadcasting WoL packet to {device.name}")
                    send_wol_packet(device)

                elif request.type == RequestType.DEVICE_STATUS_UPDATE:
                    logger.info(f"Updating power state info for {device.name}")
                    self.update_device_power_state(
                        device, self.get_device_power_state(device)
                    )

                else:
                    logger.warning(
                        f"Invalid request type '{request.type}' encountered!"
                    )

            except Exception as e:
                logger.critical(str(e))
                logger.debug(traceback.format_exc())

            finally:
                self.update_request_progress(requestId, RequestStatus.COMPLETED)
                self.requestQueue.task_done()  # Inform queue processing is complete

    def on_request(self, events: Event):
        """Add incoming requests to the queue.

        NOTE: Will also be invoked at least once an hour either by network dropout or credential expiration!
        """
        logger.info(f"Received: {events.event_type}, {events.path}, {events.data}")
        changed = {}
        if (
            events.path == "/"
        ):  # format is {'-NiNTdZWLeBH4hBlgbW-': {...}, '-NiNUGQ8CCYNUaxKwB-6': {...}}
            changed = events.data or {}

        elif (
            len(events.path) == 21
        ):  # format is {...} with the ID contained in the path
            if events.data:
                changed = {
                    events.path[
                        1:
                    ]: events.data  # Path has a leading / we must remove for the id
                }
        else:
            logger.info("No conditions matched. Ignoring...")

        for requestId, reqData in changed.items():
            if requestId not in self.requests:
                # If it's not a duplicate, add to request queue
                self.requests[requestId] = WakeOnLanRequest(
                    reqData["timestamp"],
                    reqData["device"],
                    reqData["status"],
                    reqData["type"],
                )
                self.requestQueue.put(requestId)

    def run(self):
        logger.info(f"WoL server started at {datetime.datetime.now()}.")
        print(f"WoL server started at {datetime.datetime.now()}.")

        # Start request processing worker
        worker_thread = threading.Thread(target=self.handle_request, daemon=True)
        worker_thread.start()

        # Subscribe to request queue changes
        ref = db.reference(f"requests/")
        ref.listen(self.on_request)

        worker_thread.join()  # Runs indefinitely


def main(service_acc_cert_path):
    wol_server = WakeOnLanServer()
    wol_server.register_wol_target(
        WakeOnLanTarget("orcinus", "192.168.20.205", b"\x04\x7C\x16\xBB\x5D\xA0")
    )

    # Connect to Firebase via Admin SDK
    cred = credentials.Certificate(service_acc_cert_path)
    firebase_admin.initialize_app(
        cred,
        {
            "databaseURL": "https://mirus-remote-default-rtdb.asia-southeast1.firebasedatabase.app"
        },
    )

    wol_server.run()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Mirus WoL Server",
        description="Processes WoL-related requests from Mirus Remote.",
    )
    parser.add_argument(
        "service_acc_cert_path", help="e.g. path/to/serviceAccountKey.json"
    )
    args = parser.parse_args()

    try:
        main(args.service_acc_cert_path)

    except Exception as e:
        logger.critical(str(e))
        logger.debug(traceback.format_exc())
