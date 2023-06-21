import logging
from binascii import hexlify
from enum import Enum
from struct import pack
from typing import ClassVar, Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from nfc.tag.tt4 import Type4Tag, Type4TagCommandError

from ..util import NULL_IV, bytes_xor

LOGGER = logging.getLogger(__name__)


class NTAG424DNA:
    tag: Type4Tag
    cmdctr: int
    ti: bytes
    current_key_nr: int
    k_ses_auth_enc: bytes
    k_ses_auth_mac: bytes

    _keys: list[bytes]

    _prefix_ivc: ClassVar[bytes] = b"\xa5\x5a"
    _prefix_ivr: ClassVar[bytes] = b"\x5a\xa5"

    class CommandHeader(Enum):
        ISO_SELECT_NDEF_APP = (0x00, 0xA4, 0x04, 0x0C)
        AUTH_EV2_FIRST = (0x90, 0x71, 0x00, 0x00)
        AUTH_AES_NON_FIRST = (0x90, 0x77, 0x00, 0x00)
        ADDITIONAL_DF = (0x90, 0xAF, 0x00, 0x00)
        CHANGE_KEY = (0x90, 0xC4, 0x00, 0x00)

    class Status(Enum):
        COMMAND_SUCCESSFUL = b"\x90\x00"
        OK = b"\x91\x00"
        ADDITIONAL_DF_EXPECTED = b"\x91\xAF"

    class Application(Enum):
        NDEF = b"\xd2\x76\x00\x00\x85\x01\x01"

    def __init__(self, tag: Type4Tag):
        self.tag = tag

        self.reset_keys()
        self.reset_session()

    def reset_keys(self):
        LOGGER.debug("Resetting keys to NULL")
        self._keys = [16 * b"\0"] * 4

    def reset_session(self):
        LOGGER.debug("Resetting transaction id, command counter and session keys")
        self.cmdctr = 0
        self.ti = 4 * b"\0"
        self.current_key_nr = 0
        self.k_ses_auth_enc = 16 * b"\0"
        self.k_ses_auth_mac = 16 * b"\0"

    def set_key(self, key_nr: int, key: bytes):
        if key_nr >= len(self._keys):
            raise IndexError("Key number out of range")

        LOGGER.debug("Setting key nr %d", key_nr)
        self._keys[key_nr] = key

    @property
    def ivc(self) -> bytes:
        LOGGER.debug(
            "Deriving IV for TI %s at counter %d with key nr %d",
            self.ti,
            self.cmdctr,
            self.current_key_nr,
        )

        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, NULL_IV)
        return cipher.encrypt(self._prefix_ivc + self.ti + pack("<H", self.cmdctr) + 8 * b"\0")

    def send_command(
        self,
        command: "CommandHeader",
        data: bytes,
        mrl: int = 256,
        expected: Optional[bytes] = None,
    ) -> bytes:
        if expected is None:
            expected = self.Status.COMMAND_SUCCESSFUL

        LOGGER.debug(
            "SEND: command %s, payload %s", hexlify(bytearray(command.value)), hexlify(data)
        )
        res = self.tag.send_apdu(*command.value, data, mrl=mrl, check_status=False)
        status, rapdu = res[-2:], res[:-2]
        LOGGER.debug("RECV: status %s, payload %s", hexlify(status), hexlify(rapdu))

        if status != expected.value:
            raise Type4TagCommandError.from_status(status)

        return rapdu

    def send_command_secure(
        self,
        key_nr: int,
        command: "CommandHeader",
        data: bytes,
        mrl: int = 256,
        expected: Optional[bytes] = None,
    ) -> bytes:
        LOGGER.debug("ENC: payload %s", hexlify(data))
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, self.ivc)
        encrypted = cipher.encrypt(data)

        LOGGER.debug(
            "MAC: command %s, counter %d, TI %s, key nr %d, payload %s",
            hexlify(command.value[1].to_bytes()),
            self.cmdctr,
            hexlify(self.ti),
            key_nr,
            hexlify(encrypted),
        )
        mac_input = (
            command.value[1].to_bytes()
            + pack("<H", self.cmdctr)
            + self.ti
            + key_nr.to_bytes()
            + encrypted
        )
        cmac = CMAC.new(self.k_ses_auth_mac, ciphermod=AES)
        cmac.update(mac_input)
        cmact = cmac.digest()[1::2]

        try:
            self.send_command(command, key_nr.to_bytes() + encrypted + cmact, mrl, expected)
        except Type4TagCommandError:
            self.reset_session()
            raise
        else:
            LOGGER.debug("Incrementing command counter")
            self.cmdctr += 1

    def select_application(self, aid: "Application"):
        LOGGER.debug("Selecting application %s", hexlify(aid.value))
        self.send_command(self.CommandHeader.ISO_SELECT_NDEF_APP, aid.value)
        self.reset_session()

    def derive_challenge_response(self, key: bytes, e_rndb: bytes) -> tuple[bytes, bytes, bytes]:
        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        rndb = cipher.decrypt(e_rndb)
        rndb_ = rndb[1:] + rndb[0].to_bytes()
        rnda = get_random_bytes(16)
        LOGGER.debug("AUTH: RndA %s, RndB %s", hexlify(rnda), hexlify(rndb))

        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        encrypted = cipher.encrypt(rnda + rndb_)

        return rnda, rndb, encrypted

    def derive_session_keys(self, key: bytes, rnda: bytes, rndb: bytes) -> tuple[bytes, bytes]:
        sv_1 = (
            b"\xa5\x5a\x00\x01\x00\x80"
            + rnda[0:2]
            + bytes_xor(rnda[2:8], rndb[0:6])
            + rndb[6:]
            + rnda[8:]
        )
        sv_2 = (
            b"\x5a\xa5\x00\x01\x00\x80"
            + rnda[0:2]
            + bytes_xor(rnda[2:8], rndb[0:6])
            + rndb[6:]
            + rnda[8:]
        )

        cmac = CMAC.new(key, ciphermod=AES)
        cmac.update(sv_1)
        k_ses_auth_enc = cmac.digest()
        LOGGER.debug("AUTH: Calculated session ENC key")

        cmac = CMAC.new(key, ciphermod=AES)
        cmac.update(sv_2)
        k_ses_auth_mac = cmac.digest()
        LOGGER.debug("AUTH: Calculated session MAC key")

        return k_ses_auth_enc, k_ses_auth_mac

    def authenticate_ev2_first(self, key_nr: int = 0) -> bool:
        self.select_application(self.Application.NDEF)
        self.reset_session()

        LOGGER.debug("AUTH: Doing EV2 authentication with key nr %d", key_nr)

        key = self._keys[key_nr]

        e_rndb = self.send_command(
            self.CommandHeader.AUTH_EV2_FIRST,
            pack("<H", key_nr),
            expected=self.Status.ADDITIONAL_DF_EXPECTED,
        )

        rnda, rndb, encrypted = self.derive_challenge_response(key, e_rndb)
        e_data = self.send_command(
            self.CommandHeader.ADDITIONAL_DF, encrypted, expected=self.Status.OK
        )

        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        data = cipher.decrypt(e_data)

        self.ti = data[0:4]
        self.pdcap2 = data[20:26]
        self.pcdcap2 = data[26:32]
        LOGGER.debug(
            "AUTH: TI %s, PDCAP %s, PCDCAP %s",
            hexlify(self.ti),
            hexlify(self.pdcap2),
            hexlify(self.pcdcap2),
        )

        rnda_ = data[4:20]
        rnda_recv = rnda_[-1].to_bytes() + rnda_[:-1]
        if rnda_recv != rnda:
            raise ValueError("Received RndA does not match")
        LOGGER.debug("AUTH: RndA challenge response matches")

        self.k_ses_auth_enc, self.k_ses_auth_mac = self.derive_session_keys(key, rnda, rndb)
        self.current_key_nr = key_nr
        LOGGER.debug("AUTH: Set current key nr to %d", key_nr)

    def authenticate_aes_non_first(self, key_nr: int = 0) -> bool:
        self.select_application(self.Application.NDEF)
        self.reset_session()

        LOGGER.debug("AUTH: Doing AES authentication with key nr %d", key_nr)

        key = self._keys[key_nr]

        e_rndb = self.send_command(
            self.CommandHeader.AUTH_AES_NON_FIRST,
            key_nr.to_bytes(),
            expected=self.Status.ADDITIONAL_DF_EXPECTED,
        )

        rnda, rndb, encrypted = self.derive_challenge_response(key, e_rndb)
        e_rnda_ = self.send_command(
            self.CommandHeader.ADDITIONAL_DF, encrypted, expected=self.Status.OK
        )

        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        rnda_ = cipher.decrypt(e_rnda_)

        rnda_recv = rnda_[-1].to_bytes() + rnda_[:-1]
        if rnda_recv != rnda:
            raise ValueError("Received RndA does not match")
        LOGGER.debug("AUTH: RndA challenge response matches")

        self.k_ses_auth_enc, self.k_ses_auth_mac = self.derive_session_keys(key, rnda, rndb)
        self.current_key_nr = key_nr
        LOGGER.debug("AUTH: Set current key nr to %d", key_nr)

    def change_key_same(
        self, key_nr: int, new_key: bytes, version: int = 1, auth_first: bool = True
    ) -> bool:
        LOGGER.debug("Changing key nr %d using same key for auth", key_nr)

        if auth_first:
            self.authenticate_ev2_first(key_nr)

        plain_input = pad(new_key + version.to_bytes(), 16, style="iso7816")
        self.send_command_secure(
            key_nr, self.CommandHeader.CHANGE_KEY, plain_input, expected=self.Status.OK
        )

        return True
