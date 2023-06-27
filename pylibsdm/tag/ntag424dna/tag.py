# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Implementation of tag management fro the NXP NTAG424 DNA.

Reference: https://www.nxp.com/docs/en/data-sheet/NT4H2421Tx.pdf
"""

import logging
from binascii import hexlify
from struct import pack
from typing import ClassVar

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from nfc.tag.tt4 import Type4Tag, Type4TagCommandError

from ...util import NULL_IV, bytes_xor
from ..tag import Tag
from .const import Application, DEFAULT_STATUS_OK, CommandHeader, Status
from .structs import FileSettings

LOGGER = logging.getLogger(__name__)


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
        hdr: bytes = b"",
        data: bytes = b"",
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        # ref: page 28, chapter 9.1.8
        LOGGER.debug(
            "SEND: command %s, hdr %s, data %s",
            hexlify(bytearray(command.value)),
            hexlify(hdr),
            hexlify(data),
        )
        res = self.tag.send_apdu(
            *command.value, hdr + data, mrl=mrl, check_status=False
        )
        status, rapdu = res[-2:], res[:-2]
        LOGGER.debug("RECV: status %s, payload %s", hexlify(status), hexlify(rapdu))

        if status != expected.value:
            raise Type4TagCommandError.from_status(status)

        return rapdu

    def send_command_mac(
        self,
        key_nr: int,
        command: "CommandHeader",
        hdr: bytes,
        data: bytes,
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        # ref: page 28, chapter 9.1.9
        if self.ti == 4 * b"\0":
            LOGGER.info("Not authenticated for command mode FULL; authenticating")
            self.authenticate_ev2_first(key_nr)

        LOGGER.debug(
            "MAC: command %s, counter %d, TI %s, hdr %s, data %s",
            hexlify(command.value[1].to_bytes()),
            self.cmdctr,
            hexlify(self.ti),
            hexlify(hdr),
            hexlify(data),
        )
        mac_input = (
            command.value[1].to_bytes() + pack("<H", self.cmdctr) + self.ti + hdr + data
        )
        cmac = CMAC.new(self.k_ses_auth_mac, ciphermod=AES)
        cmac.update(mac_input)
        cmact = cmac.digest()[1::2]

        try:
            res = self.send_command_plain(command, hdr, data + cmact, mrl, expected)
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
        hdr: bytes,
        data: bytes,
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        if self.ti == 4 * b"\0":
            LOGGER.info("Not authenticated for command mode FULL; authenticating")
            self.authenticate_ev2_first(key_nr)

        LOGGER.debug("ENC: payload %s", hexlify(data))
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, self.ivc)
        encrypted = cipher.encrypt(pad(data, 16, style="iso7816"))

        try:
            res = self.send_command_mac(key_nr, command, hdr, encrypted, mrl, expected)
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
        self.send_command_plain(CommandHeader.ISO_SELECT_NDEF_APP, data=aid.value)
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
            b"",
            expected=Status.ADDITIONAL_DF_EXPECTED,
        )

        rnda, rndb, encrypted = self.derive_challenge_response(key, e_rndb)
        e_data = self.send_command_plain(
            CommandHeader.ADDITIONAL_DF, b"", encrypted, expected=Status.OK
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

        self.send_command_full(
            key_nr,
            CommandHeader.CHANGE_KEY,
            key_nr.to_bytes(),
            new_key + version.to_bytes(),
            expected=Status.OK,
        )

        return True

    def get_key_version(self):
        # ref: page 69, chapter 11.6.2
        raise NotImplementedError()

    def get_file_settings(self, file_nr: int) -> FileSettings:
        # ref: page 75, chapter 11.7.2
        LOGGER.debug("Getting settings of file number %d", file_nr)

        # FIXME make key number selectable
        data = self.send_command_mac(
            0,
            CommandHeader.GET_FILE_SETTINGS,
            file_nr.to_bytes(),
            b"",
            expected=Status.OK,
        )
        LOGGER.debug("Received file settings: %s", hexlify(data))

        return FileSettings.from_bytes(data)

    def change_file_settings(self, file_nr: int, file_settings: FileSettings):
        # ref: page 70, chapter 11.7.1
        LOGGER.debug("Changing settings of file number %d", file_nr)

        settings_data = file_settings.to_bytes()
        LOGGER.debug("Sending file settings: %s", hexlify(settings_data))

        # FIXME make key number selectable
        self.send_command_full(
            0,
            CommandHeader.CHANGE_FILE_SETTINGS,
            file_nr.to_bytes(),
            settings_data,
            expected=Status.OK,
        )

    def read_data(self):
        # ref: page 79, chapter 11.8.1
        raise NotImplementedError()

    def write_data(self):
        # ref: page 81, chapter 11.8.2
        raise NotImplementedError()
