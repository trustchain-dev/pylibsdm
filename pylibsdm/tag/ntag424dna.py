# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Implementation of tag management fro the NXP NTAG424 DNA.

Reference: https://www.nxp.com/docs/en/data-sheet/NT4H2421Tx.pdf
"""

import logging
from binascii import hexlify
from dataclasses import dataclass
from enum import Enum, IntEnum
from struct import pack, unpack
from typing import ClassVar, Optional, Self

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from nfc.tag.tt4 import Type4Tag, Type4TagCommandError

from ..util import NULL_IV, bytes_xor
from .tag import Tag

LOGGER = logging.getLogger(__name__)


class CommMode(IntEnum):
    # ref: page 13, table 12
    PLAIN = 0
    MAC = 1
    FULL = 2


class FileType(IntEnum):
    # ref: page 11, table 6
    STANDARD_DATA = 0


class AccessCondition(Enum):
    # ref: page 11, table 6
    KEY_0 = 0
    KEY_1 = 1
    KEY_2 = 2
    KEY_3 = 3
    KEY_4 = 4
    FREE_ACCESS = 0xE
    NO_ACCESS = 0xF


@dataclass
class AccessConditionSet:
    read: AccessCondition
    write: AccessCondition
    read_write: AccessCondition
    change: AccessCondition

    def to_bytes(self):
        # ref: page 11, table 7
        b1 = self.read_write.value * 16 + self.change.value
        b2 = self.read.value * 16 + self.write.value
        return b1.to_bytes() + b2.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        read = AccessCondition(data[1] >> 4)
        write = AccessCondition(data[1] & 15)
        read_write = AccessCondition(data[0] >> 4)
        change = AccessCondition(data[0] & 15)

        return cls(read, write, read_write, change)


# FIXME maybe implement standard files, table 8 et al


@dataclass
class FileSettings:
    sdm_enabled: bool
    mirror_enabled: bool
    comm_mode: CommMode
    file_ar_rw_key: int
    file_ar_c_key: int
    file_ar_r_key: int
    file_ar_w_key: int
    uid_mirror: bool
    read_ctr: bool
    read_ctr_limit: bool
    enc_file_data: bool
    ascii_encoding: bool
    rfu_key: int
    ctr_ret_key: int
    meta_read_key: int
    file_read_key: int
    enc_picc_data_offset: Optional[int] = None
    mac_offset: Optional[int] = None
    mac_input_offset: Optional[int] = None

    file_type: Optional[int] = 0
    file_size: Optional[int] = 256

    @classmethod
    def from_rapdu_data(cls, settings_data: bytes) -> Self:
        # ref: page 75, table 73
        fields = {}

        fields["file_type"] = settings_data[0]

        file_options = settings_data[1].to_bytes()
        if file_options != b"\x40":
            raise NotImplementedError("File options not supported due to lack of specs")
        else:
            fields["sdm_enabled"] = True
            fields["mirror_enabled"] = True
            fields["comm_mode"] = CommMode.PLAIN

        access_rights = settings_data[2:4]
        fields["file_ar_rw_key"] = access_rights[0] >> 4
        fields["file_ar_c_key"] = access_rights[0] % 15
        fields["file_ar_r_key"] = access_rights[1] >> 4
        fields["file_ar_w_key"] = access_rights[1] % 15

        # FIXME find out how to get from 8 to 256 really
        fields["file_size"] = unpack("<L", settings_data[4:7] + b"\0") * 32

        # FIXME really?
        sdm_options = settings_data[7]
        fields["uid_mirror"] = bool(sdm_options & 128)
        fields["read_ctr"] = bool(sdm_options & 64)
        fields["read_ctr_limit"] = bool(sdm_options & 4)
        fields["enc_file_data"] = bool(sdm_options & 2)
        fields["ascii_encoding"] = bool(sdm_options & 1)

        sdm_access_rights = settings_data[8:10]
        fields["rfu_key"] = sdm_access_rights[0] >> 4
        fields["ctr_ret_key"] = sdm_access_rights[0] % 15
        fields["meta_read_key"] = sdm_access_rights[1] >> 4
        fields["file_read_key"] = sdm_access_rights[1] % 15

        next_offset = 10
        # FIXME implement offset parsing; missing due to lack of specs
        # if fields["uid_mirror"]:
        #    fields["uid_offset"] = unpack("<H", settings_data[next_offset:next_offset+3])
        #    next_offset += 3
        # if fields["read_ctr"]:
        #    fields["read_ctr_offset"] = unpack("<H", settings_data[next_offset:next_offset+3])
        #    next_offset += 3

        return cls(**fields)

    def to_capdu_data(self) -> bytes:
        # ref: page 70, chapter 69
        settings_data = b""

        if (
            self.sdm_enabled
            and self.mirror_enabled
            and self.comm_mode == CommMode.PLAIN
        ):
            settings_data += b"\x40"
        else:
            raise NotImplementedError(
                "Combination not implemented due to lack of specs"
            )

        settings_data += (self.file_ar_c_key + self.file_ar_rw_key * 16).to_bytes()
        settings_data += (self.file_ar_w_key + self.file_ar_r_key * 16).to_bytes()

        # FIXME really?
        flags = 0
        flags |= self.ascii_encoding * 1
        flags |= self.enc_file_data * 2
        flags |= self.read_ctr_limit * 4
        flags |= self.read_ctr * 64
        flags |= self.uid_mirror * 128
        settings_data += flags.to_bytes()

        settings_data += (self.ctr_ret_key + self.rfu_key * 16).to_bytes()
        settings_data += (self.file_read_key + self.meta_read_key * 16).to_bytes()

        settings_data += pack("<L", self.enc_picc_data_offset)[:3]
        settings_data += pack("<L", self.mac_offset)[:3]
        settings_data += pack("<L", self.mac_input_offset)[:3]

        return settings_data


class NTAG424DNA(Tag):
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
        # ref: page 47, table 22
        # FIXME complete, if that makes sense
        ISO_SELECT_NDEF_APP = (0x00, 0xA4, 0x04, 0x0C)
        AUTH_EV2_FIRST = (0x90, 0x71, 0x00, 0x00)
        AUTH_AES_NON_FIRST = (0x90, 0x77, 0x00, 0x00)
        ADDITIONAL_DF = (0x90, 0xAF, 0x00, 0x00)
        CHANGE_KEY = (0x90, 0xC4, 0x00, 0x00)
        GET_FILE_SETTINGS = (0x90, 0xF5, 0x00, 0x00)

    class Status(Enum):
        # ref: page 48, table 23
        # FIXME complete, if that makes sense
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
        self._keys = [16 * b"\0"] * 5

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
        return cipher.encrypt(
            self._prefix_ivc + self.ti + pack("<H", self.cmdctr) + 8 * b"\0"
        )

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
            "SEND: command %s, payload %s",
            hexlify(bytearray(command.value)),
            hexlify(data),
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
            self.send_command(
                command, key_nr.to_bytes() + encrypted + cmact, mrl, expected
            )
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

    def derive_challenge_response(
        self, key: bytes, e_rndb: bytes
    ) -> tuple[bytes, bytes, bytes]:
        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        rndb = cipher.decrypt(e_rndb)
        rndb_ = rndb[1:] + rndb[0].to_bytes()
        rnda = get_random_bytes(16)
        LOGGER.debug("AUTH: RndA %s, RndB %s", hexlify(rnda), hexlify(rndb))

        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        encrypted = cipher.encrypt(rnda + rndb_)

        return rnda, rndb, encrypted

    def derive_session_keys(
        self, key: bytes, rnda: bytes, rndb: bytes
    ) -> tuple[bytes, bytes]:
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
        # ref: page 50, chapter 11.4.1
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

        self.k_ses_auth_enc, self.k_ses_auth_mac = self.derive_session_keys(
            key, rnda, rndb
        )
        self.current_key_nr = key_nr
        LOGGER.debug("AUTH: Set current key nr to %d", key_nr)

        return True

    def authenticate_ev2_non_first(self, key_nr: int = 0) -> bool:
        # ref: page 53, capter 11.4.2
        raise NotImplementedError()

    def authenticate_lrp_first(self, key_nr: int = 0) -> bool:
        # ref: page 55, capter 11.4.3
        raise NotImplementedError()

    def authenticate_lrp_non_first(self, key_nr: int = 0) -> bool:
        # ref: page 57, capter 11.4.4
        raise NotImplementedError()

    def set_configuration(self):
        # ref: page 59, chapter 11.5.1
        raise NotImplementedError()

    def get_version(self):
        # ref: page 63, chapter 11.5.2
        raise NotImplementedError()

    def get_card_uid(self):
        # ref: page 66, chapter 11.5.2
        raise NotImplementedError()

    def change_key(
        self, key_nr: int, new_key: bytes, version: int = 1, auth_first: bool = True
    ) -> bool:
        # ref: page 67, chapter 11.6.1
        LOGGER.debug("Changing key nr %d using same key for auth", key_nr)

        if auth_first:
            self.authenticate_ev2_first(0)

        plain_input = pad(new_key + version.to_bytes(), 16, style="iso7816")
        self.send_command_secure(
            key_nr, self.CommandHeader.CHANGE_KEY, plain_input, expected=self.Status.OK
        )

        return True

    def get_key_version(self):
        # ref: page 69, chapter 11.6.2
        raise NotImplementedError()

    def get_file_settings(self, file_nr: int) -> FileSettings:
        # ref: page 75, chapter 11.7.2
        raise NotImplementedError()

    def change_file_settings(self):
        # ref: page 70, chapter 11.7.1
        raise NotImplementedError()

    def read_data(self):
        # ref: page 79, chapter 11.8.1
        raise NotImplementedError()

    def write_data(self):
        # ref: page 81, chapter 11.8.2
        raise NotImplementedError()
