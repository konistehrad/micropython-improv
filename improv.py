import aioble
import asyncio
import bluetooth
import logging
import network
from micropython import const

logger = logging.getLogger(name=__name__)

IMPROV_CAPABILITIES_IDENTIFY = const(0x01)

IMPROV_ERROR_NONE = const(0x00)
IMPROV_ERROR_INVALID_RPC = const(0x01)
IMPROV_ERROR_UNKNOWN_RPC = const(0x02)
IMPROV_ERROR_UNABLE_TO_CONNECT = const(0x03)
IMPROV_ERROR_NOT_AUTHORIZED = const(0x04)
IMPROV_ERROR_UNKNOWN = const(0xFF)

IMPROV_STATE_STOPPED = const(0x00)
IMPROV_STATE_AWAITING_AUTHORIZATION = const(0x01)
IMPROV_STATE_AUTHORIZED = const(0x02)
IMPROV_STATE_PROVISIONING = const(0x03)
IMPROV_STATE_PROVISIONED = const(0x04)

IMPROV_COMMAND_UNKNOWN = const(0x00)
IMPROV_COMMAND_WIFI_SETTINGS = const(0x01)
IMPROV_COMMAND_IDENTIFY = const(0x02)
IMPROV_COMMAND_GET_CURRENT_STATE = const(0x02)
IMPROV_COMMAND_GET_DEVICE_INFO = const(0x03)
IMPROV_COMMAND_GET_WIFI_NETWORKS = const(0x04)
IMPROV_COMMAND_BAD_CHECKSUM = const(0xFF)

IMPROV_SERIAL_TYPE_CURRENT_STATE = const(0x01)
IMPROV_SERIAL_TYPE_ERROR_STATE = const(0x02)
IMPROV_SERIAL_TYPE_RPC = const(0x03)
IMPROV_SERIAL_TYPE_RPC_RESPONSE = const(0x04)

IMPROV_UUID_SERVICE = const("00467768-6228-2272-4663-277478268000")
IMPROV_UUID_STATUS = const("00467768-6228-2272-4663-277478268001")
IMPROV_UUID_ERROR = const("00467768-6228-2272-4663-277478268002")
IMPROV_UUID_RPC_COMMAND = const("00467768-6228-2272-4663-277478268003")
IMPROV_UUID_RPC_RESULT = const("00467768-6228-2272-4663-277478268004")
IMPROV_UUID_CAPABILITIES = const("00467768-6228-2272-4663-277478268005")

_MP_IMPROV_SERVICE_UUID = bluetooth.UUID(IMPROV_UUID_SERVICE)
_MP_IMPROV_STATUS_UUID = bluetooth.UUID(IMPROV_UUID_STATUS)
_MP_IMPROV_ERROR_UUID = bluetooth.UUID(IMPROV_UUID_ERROR)
_MP_IMPROV_RPC_COMMAND_UUID = bluetooth.UUID(IMPROV_UUID_RPC_COMMAND)
_MP_IMPROV_RPC_RESULT_UUID = bluetooth.UUID(IMPROV_UUID_RPC_RESULT)
_MP_IMPROV_CAPABILITIES_UUID = bluetooth.UUID(IMPROV_UUID_CAPABILITIES)

_MP_IMPROV_DEFAULT_ADVERT_INTERVAL_US = const(500_000)
_MP_IMPROV_DEFAULT_TIMEOUT_MS = const(15_000)
_MP_IMPROV_DEFAULT_CONNECT_RETRY_COUNT = const(10)

class ImprovService:
    VERSION = 1

    def __init__(self,
                 redirect_urls,
                 name: str = "Improv",
                 requires_authorization: bool = False,
                 identify_callback = None,
                 max_response_bytes = 100,
                 advertise_interval_us: int = _MP_IMPROV_DEFAULT_ADVERT_INTERVAL_US
                 ) -> None:
        self.redirect_urls = redirect_urls
        self.max_response_bytes = max_response_bytes
        self.__network_mon_task = None
        self.requires_authorization = requires_authorization
        self.identify_callback = identify_callback
        self._status = IMPROV_STATE_STOPPED
        self._last_error = IMPROV_ERROR_NONE
        self._advertise_interval = advertise_interval_us
        self.name = name

        improv_service = aioble.Service(_MP_IMPROV_SERVICE_UUID)
        status_char = aioble.Characteristic(improv_service, _MP_IMPROV_STATUS_UUID, 
            read=True, write=False, notify=True, initial=self._status.to_bytes(1, 'little'))
        error_char = aioble.Characteristic(improv_service, _MP_IMPROV_ERROR_UUID, 
            read=True, write=False, notify=True, initial=self._last_error.to_bytes(1, 'little'))
        rpc_command_char = aioble.BufferedCharacteristic(improv_service, _MP_IMPROV_RPC_COMMAND_UUID, 
            max_len=255, write=True, write_no_response=True, capture=True)
        rpc_result_char = aioble.Characteristic(improv_service, _MP_IMPROV_RPC_RESULT_UUID, 
            read=True, write=False, notify=True, initial=bytearray(max_response_bytes))
        rpc_capabilities_char = aioble.Characteristic(improv_service, _MP_IMPROV_CAPABILITIES_UUID, 
            read=True, write=False, notify=False, initial=(self.capabilities.to_bytes(1, 'little')))
        self._serivces_registered = False
        self.improv_service = improv_service
        self.status_char = status_char
        self.error_char = error_char
        self.rpc_command_char = rpc_command_char
        self.rpc_result_char = rpc_result_char
        self.rpc_capabilities_char = rpc_capabilities_char
        logger.debug("Activating BLE.")
        aioble.register_services(improv_service)


    @property
    def status(self):
        return self._status
    @status.setter
    def status(self, value):
        self._status = value
        if hasattr(self, 'status_char'):
            self.status_char.write(value.to_bytes(1, 'little'), True)

    @property
    def last_error(self):
        return self._last_error
    @last_error.setter
    def last_error(self, value):
        self._last_error = value
        if hasattr(self, 'error_char'):
            self.error_char.write(value.to_bytes(1, 'little'), True)

    @property
    def capabilities(self):
        return 1 if self.identify_callback is not None else 0

    def start_network_monitoring(self):
        if self.__network_mon_task is not None:
            logger.error("Improv network monitor already started!")
            return

        # activate the WiFi, wait for association...
        network.WLAN(network.STA_IF).active(True)
        self.__network_mon_task = asyncio.create_task(self.__network_monitor_loop())

    def stop_network_monitoring(self):
        if self.__network_mon_task is None:
            logger.error("Improv network monitor already stopped!")
            return
        self.__network_mon_task.cancel()
        self.__network_mon_task = None

    async def __wait_for_wifi_connect(self):
        sta = network.WLAN(network.STA_IF)
        wifi_status = sta.status()
        retry_count = _MP_IMPROV_DEFAULT_CONNECT_RETRY_COUNT
        while wifi_status is network.STAT_CONNECTING and retry_count > 0:
            retry_count -= 1
            logger.debug("Waiting for network to finish connecting attempt...")
            await asyncio.sleep(2)
            if sta.isconnected():
                logger.debug("WiFi connected!")
                return network.STAT_GOT_IP
        return wifi_status

    async def __try_wifi_connect(self, ssid: str, passwd: str):
        sta = network.WLAN(network.STA_IF)

        if sta.isconnected() and sta.config('ssid') is ssid:
            logger.debug("Duplicate request for connected ssid; passing...")
            return network.STAT_GOT_IP

        logger.debug("Doing just in case disconnect...")
        sta.disconnect()
        await asyncio.sleep(0.1)

        logger.debug("Attempting to connect to %s...", ssid)
        sta.connect(ssid, passwd)
        await asyncio.sleep(0.2)
        wifi_status = await self.__wait_for_wifi_connect()
        return wifi_status

    async def __netmon_loop_connected(self, wait_for_connect: bool = True):
        logger.debug("Starting connected loop...")
        sta = network.WLAN(network.STA_IF)
        # first time thru...
        if wait_for_connect:
            await self.__wait_for_wifi_connect()
        while True:
            while sta.isconnected():
                await asyncio.sleep(15)
            # ok we were connected, then we fell off, but we're in a connecting
            # state again; see if we can't ride it out ...
            logger.debug("WiFi disconnected; checking for reconnect...")
            if sta.status() is network.STAT_CONNECTING:
                await self.__wait_for_wifi_connect()
            if not sta.isconnected():
                logger.debug("WiFi disconnected; falling out to disconnected loop")
                # nothing doing; bail
                return


    async def __netmon_loop_disconnected(self):
        logger.debug("Starting disconnected loop...")
        ble = bluetooth.BLE()
        sta = network.WLAN(network.STA_IF)
        # Just late to the party, I guess...
        await self.__wait_for_wifi_connect()
        if sta.isconnected():
            logger.debug("Starting WiFi came back! returning to connected loop.")
            return

        # Restore values to initial...
        if self.requires_authorization:
            self.status = IMPROV_STATE_AWAITING_AUTHORIZATION
        else: 
            self.status = IMPROV_STATE_AUTHORIZED
        self.last_error = IMPROV_ERROR_NONE
        self.rpc_result_char.write(b'')

        connection = None
        while True:
            # await connection if we're not reusing an existing one
            if connection is None or not connection.is_connected():
                connection = None

            if connection is None:
                logger.info("Waiting for BLE connection...")
                # Start advertising!
                connection = await aioble.advertise(
                    self._advertise_interval,
                    name=self.name,
                    services=[_MP_IMPROV_SERVICE_UUID]
                )
                logger.info("BLE connection from %s", connection.device)
            else:
                logger.info("Reusing connection from %s", connection.device)

            try:
                _, data = await self.rpc_command_char.written() # TODO: add timeout here!
                logger.debug("got data %s", data)
                parsed = self.parse_improv_data(data)
                command = parsed[0]
                if command is IMPROV_COMMAND_UNKNOWN:
                    self.last_error = IMPROV_ERROR_UNKNOWN_RPC
                    self.status = IMPROV_STATE_AUTHORIZED
                elif command is IMPROV_COMMAND_BAD_CHECKSUM:
                    self.last_error = IMPROV_ERROR_INVALID_RPC
                    self.status = IMPROV_STATE_AUTHORIZED
                elif command is IMPROV_COMMAND_IDENTIFY:
                    if self.identify_callback is not None:
                        pass
                    else:
                        self.last_error = IMPROV_ERROR_UNKNOWN_RPC
                        self.status = IMPROV_STATE_AUTHORIZED
                elif command is IMPROV_COMMAND_WIFI_SETTINGS:
                    if len(parsed) < 3:
                        self.last_error = IMPROV_ERROR_INVALID_RPC
                        continue

                    (_, ssid, password) = parsed
                    self.status = IMPROV_STATE_PROVISIONING
                    connectresult = await self.__try_wifi_connect(ssid.decode("utf-8"), password.decode("utf-8"))
                    if connectresult is network.STAT_GOT_IP:
                        self.last_error = IMPROV_ERROR_NONE
                        self.status = IMPROV_STATE_PROVISIONED
                        reply = self.build_rpc_response(IMPROV_COMMAND_WIFI_SETTINGS, self.redirect_urls)
                        self.rpc_result_char.write(reply[0], True)
                        # Signal we're good and get out!
                        return
                    else:
                        self.last_error = IMPROV_ERROR_UNABLE_TO_CONNECT
                        self.status = IMPROV_STATE_AUTHORIZED
                else:
                    self.last_error = IMPROV_ERROR_UNKNOWN_RPC
                    self.status = IMPROV_STATE_AUTHORIZED


            except asyncio.CancelledError:
                logger.debug("Cancelled error on written; probably disconnect")
                connection = None
            except asyncio.TimeoutError:
                # Got a timeout on a read. Start from the top?
                logger.debug("Timeout on internal command; resuming...")

    async def __network_monitor_loop(self):
        while True:
            # optimistically see if we're waiting for a default reconnect...
            await self.__netmon_loop_connected()
            # okay fine that didn't work, drop out.
            await self.__netmon_loop_disconnected()


    def calculateChecksum(self, data: bytearray) -> int:
        calculated_checksum = 0
        for b in data:
            calculated_checksum += b
        return (calculated_checksum & 0xFF)

    def parse_improv_data(self, data: bytearray) -> tuple:
        """Boundschecks and Parses a raw bytearray into an RPC command

        Args:
            data (bytearray): raw ble data

        Returns:
            tuple: First entry for the command, following entries are parameters
        """
        command = data[0]

        logger.debug(f"Command recieved: {command}")
        if len(data) == 1:
            if command == IMPROV_COMMAND_WIFI_SETTINGS:
                logger.warning("WIFI settings command without payload")
                return (IMPROV_COMMAND_UNKNOWN,)
            return (command,)
        length = data[1]

        if (length != len(data) - 3):
            logger.debug(f"length mismatch: {length}  != {len(data) - 3}")
            return (IMPROV_COMMAND_UNKNOWN,)

        checksum = data[-1]
        calculated_checksum = self.calculateChecksum(data[:-1])

        if ((calculated_checksum & 0xFF) != checksum):
            logger.debug(
                f"Checksums are {hex(checksum)} and {hex(calculated_checksum)}")
            return (IMPROV_COMMAND_BAD_CHECKSUM,)

        if (command == IMPROV_COMMAND_WIFI_SETTINGS):
            ssid_length = data[2]
            ssid_end = 3 + ssid_length
            # We need at least one byte for the pw length
            if ssid_end >= len(data) - 1:
                return (command,)
            ssid = bytearray(data[3: ssid_end])

            password_length = data[ssid_end]
            password_start = ssid_end + 1
            if password_start + password_length >= len(data):
                return (command,)
            password = bytearray(
                data[password_start: password_start + password_length])

            return (command, ssid, password)

        return (command,)

    def build_rpc_response(self, command: ImprovCommand, data: list[str]) -> bytearray:
        """Builds an bytearray from an command and data to be passed to the caller

        Args:
            command (ImprovCommand): The RPC command this is answering
            data (list[str]): data to be passed to the caller, e.g. redirect urls 

        Returns:
            bytearray: Formated bytearray with length and checksum fields
        """
        responses = []
        current_response = bytearray()
        current_response += command.to_bytes(1, 'little')
        # Leave space for length field
        current_response += b"\x00"
        for component in data:
            if len(current_response) - 2 + 1 + len(component) > self.max_response_bytes:
                current_response[1] = len(current_response) - 2
                current_response += self.calculateChecksum(
                    current_response).to_bytes(1, 'little')
                # Add finished response to answer field
                if len(current_response) <= self.max_response_bytes:
                    responses.append(current_response)
                # Create new response
                current_response = bytearray()
                current_response += command.to_bytes(1, 'little')
                # Leave space for length field
                current_response += b"\x00"

            current_response += len(component).to_bytes(1, 'little')
            current_response += component.encode("utf-8")

        current_response[1] = len(current_response) - 2
        current_response += self.calculateChecksum(
            current_response).to_bytes(1, 'little')
        responses.append(current_response)
        return responses
