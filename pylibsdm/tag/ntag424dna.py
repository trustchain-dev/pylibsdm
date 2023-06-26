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
from Crypto.Util.Padding import pad
from nfc.tag.tt4 import Type4Tag, Type4TagCommandError

from ..util import NULL_IV, bytes_xor
from .tag import Tag

LOGGER = logging.getLogger(__name__)


DEFAULT_STATUS_OK = b"\x90\x00"


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
class AccessRights:
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


@dataclass
class FileOption:
    sdm_enabled: bool
    comm_mode: CommMode

    def to_bytes(self) -> bytes:
        # ref: page 75, table 73
        data = 0
        data |= int(self.sdm_enabled) * 64
        data |= self.comm_mode.value
        return data.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        sdm_enabled = bool(data[0] & 64)
        comm_mode = CommMode(data[0] & 3)
        return cls(sdm_enabled, comm_mode)


@dataclass
class SDMOptions:
    uid: bool
    read_ctr: bool
    read_ctr_limit: bool
    enc_file_data: bool
    tt_status: bool
    ascii_encoding: bool = True

    def to_bytes(self) -> bytes:
        # ref: page 71, table 69
        value = (
            self.ascii_encoding * 1
            + self.tt_status * 8
            + self.enc_file_data * 16
            + self.read_ctr_limit * 32
            + self.read_ctr * 64
            + self.uid * 128
        )
        return value.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        ascii_encoding = bool(data[0] & 1)
        tt_status = bool(data[0] & 8)
        enc_file_data = bool(data[0] & 16)
        read_ctr_limit = bool(data[0] & 32)
        read_ctr = bool(data[0] & 64)
        uid = bool(data[0] & 128)
        return cls(
            uid, read_ctr, read_ctr_limit, enc_file_data, tt_status, ascii_encoding
        )


@dataclass
class SDMAccessRights:
    meta_read: AccessCondition
    file_read: AccessCondition
    ctr_ret: AccessCondition

    def to_bytes(self):
        # ref: page 71, table 69
        b1 = 15 * 16 + self.ctr_ret.value
        b2 = self.meta_read.value * 16 + self.file_read.value
        return b1.to_bytes() + b2.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        meta_read = AccessCondition(data[1] >> 4)
        file_read = AccessCondition(data[1] & 15)
        ctr_ret = AccessCondition(data[0] & 15)

        return cls(meta_read, file_read, ctr_ret)


# FIXME maybe implement standard files, table 8 et al


@dataclass
class FileSettings:
    file_option: FileOption
    access_rights: AccessRights
    sdm_options: Optional[SDMOptions] = None
    sdm_access_rights: Optional[SDMAccessRights] = None

    uid_offset: Optional[int] = None
    read_ctr_offset: Optional[int] = None
    picc_data_offset: Optional[int] = None
    tt_status_offset: Optional[int] = None
    mac_input_offset: Optional[int] = None
    enc_offset: Optional[int] = None
    enc_length: Optional[int] = None
    mac_offset: Optional[int] = None
    read_ctr_limit: Optional[int] = None

    file_type: FileType = FileType.STANDARD_DATA
    file_size: Optional[int] = None

    def to_bytes(self) -> bytes:
        # ref: page 70, table 69
        data = b""

        data += self.file_option.to_bytes()
        data += self.access_rights.to_bytes()

        if self.file_option.sdm_enabled:
            if self.sdm_options is None or self.sdm_access_rights is None:
                raise TypeError("SDM enabled but options or AR unset")
            data += self.sdm_options.to_bytes()
            data += self.sdm_access_rights.to_bytes()

            # FIXME implement offset/length validation/calculation
            if (
                self.sdm_options.uid
                and self.sdm_access_rights.meta_read == AccessCondition.FREE_ACCESS
            ):
                data += pack("<L", self.uid_offset)[:3]
            if (
                self.sdm_options.read_ctr
                and self.sdm_access_rights.meta_read == AccessCondition.FREE_ACCESS
            ):
                data += pack("<L", self.read_ctr_offset)[:3]
            if (
                self.sdm_access_rights.meta_read.value
                < AccessCondition.FREE_ACCESS.value
            ):
                data += pack("<L", self.picc_data_offset)[:3]
            if self.sdm_options.tt_status:
                data += pack("<L", self.tt_status_offset)[:3]
            if self.sdm_access_rights.file_read != AccessCondition.NO_ACCESS:
                data += pack("<L", self.mac_input_offset)[:3]
                if self.sdm_options.enc_file_data:
                    data += pack("<L", self.enc_offset)[:3]
                    data += pack("<L", self.enc_length)[:3]
                data += pack("<L", self.mac_offset)[:3]
            if self.sdm_options.read_ctr_limit:
                data += pack("<L", self.read_ctr_limit)[:3]

        return data

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        # ref: page 75, table 73
        file_type = FileType(data[0])
        file_option = FileOption.from_bytes(data[1].to_bytes())
        access_rights = AccessRights.from_bytes(data[2:4])
        file_size = unpack("<L", data[4:7] + b"\0")[0]

        next_offset = 7

        sdm_options = None
        sdm_access_rights = None
        uid_offset = None
        read_ctr_offset = None
        picc_data_offset = None
        tt_status_offset = None
        mac_input_offset = None
        enc_offset = None
        enc_length = None
        mac_offset = None
        read_ctr_limit = None

        if file_option.sdm_enabled:
            sdm_options = SDMOptions.from_bytes(data[7:8])
            sdm_access_rights = SDMAccessRights.from_bytes(data[8:10])

            next_offset = 10

            if (
                sdm_options.uid
                and sdm_access_rights.meta_read == AccessCondition.FREE_ACCESS
            ):
                uid_offset = unpack("<L", data[next_offset : next_offset + 3] + b"\0")[
                    0
                ]
                next_offset += 3
            if (
                sdm_options.read_ctr
                and sdm_access_rights.meta_read == AccessCondition.FREE_ACCESS
            ):
                read_ctr_offset = unpack(
                    "<L", data[next_offset : next_offset + 3] + b"\0"
                )[0]
                next_offset += 3
            if sdm_access_rights.meta_read.value < AccessCondition.FREE_ACCESS.value:
                picc_data_offset = unpack(
                    "<L", data[next_offset : next_offset + 3] + b"\0"
                )[0]
                next_offset += 3
            if sdm_options.tt_status:
                tt_status_offset = unpack(
                    "<L", data[next_offset : next_offset + 3] + b"\0"
                )[0]
                next_offset += 3
            if sdm_access_rights.file_read != AccessCondition.NO_ACCESS:
                mac_input_offset = unpack(
                    "<L", data[next_offset : next_offset + 3] + b"\0"
                )[0]
                next_offset += 3
                if sdm_options.enc_file_data:
                    enc_offset = unpack(
                        "<L", data[next_offset : next_offset + 3] + b"\0"
                    )[0]
                    next_offset += 3
                    enc_length = unpack(
                        "<L", data[next_offset : next_offset + 3] + b"\0"
                    )[0]
                    next_offset += 3
                mac_offset = unpack("<L", data[next_offset : next_offset + 3] + b"\0")[
                    0
                ]
                next_offset += 3
            if sdm_options.read_ctr_limit:
                read_ctr_limit = unpack(
                    "<L", data[next_offset : next_offset + 3] + b"\0"
                )[0]
                next_offset += 3

        return cls(
            file_option,
            access_rights,
            sdm_options,
            sdm_access_rights,
            uid_offset,
            read_ctr_offset,
            picc_data_offset,
            tt_status_offset,
            mac_input_offset,
            enc_offset,
            enc_length,
            mac_offset,
            read_ctr_limit,
            file_type,
            file_size,
        )


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

    @property
    def ivr(self) -> bytes:
        LOGGER.debug(
            "Deriving IV for TI %s at counter %d with key nr %d",
            self.ti,
            self.cmdctr,
            self.current_key_nr,
        )

        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, NULL_IV)
        return cipher.encrypt(
            self._prefix_ivr + self.ti + pack("<H", self.cmdctr) + 8 * b"\0"
        )

    def send_command_plain(
        self,
        command: "CommandHeader",
        data: bytes,
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        # ref: page 28, chapter 9.1.8
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

    def send_command_mac(
        self,
        key_nr: int,
        command: "CommandHeader",
        data: bytes,
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        # ref: page 28, chapter 9.1.9
        if self.ti == 4 * b"\0":
            LOGGER.info("Not authenticated for command mode FULL; authenticating")
            self.authenticate_ev2_first(key_nr)

        LOGGER.debug(
            "MAC: command %s, counter %d, TI %s, payload %s",
            hexlify(command.value[1].to_bytes()),
            self.cmdctr,
            hexlify(self.ti),
            hexlify(data),
        )
        mac_input = (
            command.value[1].to_bytes() + pack("<H", self.cmdctr) + self.ti + data
        )
        cmac = CMAC.new(self.k_ses_auth_mac, ciphermod=AES)
        cmac.update(mac_input)
        cmact = cmac.digest()[1::2]

        try:
            res = self.send_command_plain(command, data + cmact, mrl, expected)
        except Type4TagCommandError:
            self.reset_session()
            raise

        LOGGER.debug("Incrementing command counter")
        self.cmdctr += 1

        if len(res) > 8:
            data_verified, mac_returned = res[:-8], res[-8:]

            # ref: page 29, figure 8
            mac_return_input = (
                expected.value[1].to_bytes()
                + pack("<H", self.cmdctr)
                + self.ti
                + data_verified
            )
            cmac = CMAC.new(self.k_ses_auth_mac, ciphermod=AES)
            cmac.update(mac_return_input)
            mac_returned_expected = cmac.digest()[1::2]

            if mac_returned != mac_returned_expected:
                raise ValueError(
                    "Returned MAC %s does not match expected MAC %s",
                    hexlify(mac_returned).decode(),
                    hexlify(mac_returned_expected).decode(),
                )
            LOGGER.debug("Returned MAC matches expected MAC")
        else:
            LOGGER.debug("No MAC provided in response")
            data_verified = b""

        return data_verified

    def send_command_full(
        self,
        key_nr: int,
        command: "CommandHeader",
        data: bytes,
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        if self.ti == 4 * b"\0":
            LOGGER.info("Not authenticated for command mode FULL; authenticating")
            self.authenticate_ev2_first(key_nr)

        LOGGER.debug("ENC: payload %s", hexlify(data))
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, self.ivc)
        encrypted = cipher.encrypt(data)

        try:
            res = self.send_command_mac(
                key_nr, command, key_nr.to_bytes() + encrypted, mrl, expected
            )
        except Type4TagCommandError:
            self.reset_session()
            raise

        if res:
            LOGGER.debug("DEC: payload %s", hexlify(res))
            cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, self.ivr)
            decrypted = cipher.decrypt(res)
        else:
            LOGGER.debug("No payload to decrypt")
            decrypted = encrypted

        return decrypted

    def select_application(self, aid: "Application"):
        LOGGER.debug("Selecting application %s", hexlify(aid.value))
        self.send_command_plain(CommandHeader.ISO_SELECT_NDEF_APP, aid.value)
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
        self.select_application(Application.NDEF)
        self.reset_session()

        LOGGER.debug("AUTH: Doing EV2 authentication with key nr %d", key_nr)

        key = self._keys[key_nr]

        e_rndb = self.send_command_plain(
            CommandHeader.AUTH_EV2_FIRST,
            pack("<H", key_nr),
            expected=Status.ADDITIONAL_DF_EXPECTED,
        )

        rnda, rndb, encrypted = self.derive_challenge_response(key, e_rndb)
        e_data = self.send_command_plain(
            CommandHeader.ADDITIONAL_DF, encrypted, expected=Status.OK
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

    def change_key(self, key_nr: int, new_key: bytes, version: int = 1) -> bool:
        # ref: page 67, chapter 11.6.1
        LOGGER.debug("Changing key nr %d using same key for auth", key_nr)

        plain_input = pad(new_key + version.to_bytes(), 16, style="iso7816")
        self.send_command_full(
            key_nr, CommandHeader.CHANGE_KEY, plain_input, expected=Status.OK
        )

        return True

    def get_key_version(self):
        # ref: page 69, chapter 11.6.2
        raise NotImplementedError()

    def get_file_settings(self, file_nr: int) -> FileSettings:
        # ref: page 75, chapter 11.7.2
        LOGGER.debug("Getting settings of file number %d", file_nr)

        data = self.send_command_mac(
            0,
            CommandHeader.GET_FILE_SETTINGS,
            file_nr.to_bytes(),
            expected=Status.OK,
        )
        return FileSettings.from_bytes(data)

    def change_file_settings(self):
        # ref: page 70, chapter 11.7.1
        raise NotImplementedError()

    def read_data(self):
        # ref: page 79, chapter 11.8.1
        raise NotImplementedError()

    def write_data(self):
        # ref: page 81, chapter 11.8.2
        raise NotImplementedError()
