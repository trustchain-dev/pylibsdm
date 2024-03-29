# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Implementation of tag management fro the NXP NTAG424 DNA.

Reference: https://www.nxp.com/docs/en/data-sheet/NT4H2421Tx.pdf
"""

import logging
from struct import pack
from typing import ClassVar, Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from crc import Calculator, Configuration
from nfc.tag.tt4 import Type4Tag, Type4TagCommandError

from ...util import NULL_IV, bytes_xor
from ..tag import Tag
from .const import Application, DEFAULT_STATUS_OK, CommandHeader, Status
from .structs import CommMode, FileSettings

LOGGER = logging.getLogger(__name__)


class NTAG424DNA(Tag):
    _num_keys = 5

    cmdctr: int
    ti: bytes
    current_key_nr: int
    k_ses_auth_enc: bytes
    k_ses_auth_mac: bytes

    _prefix_ivc: ClassVar[bytes] = b"\xa5\x5a"
    _prefix_ivr: ClassVar[bytes] = b"\x5a\xa5"

    def __init__(self, tag: Type4Tag, *args, **kwargs):
        super().__init__(tag, *args, **kwargs)
        self.reset_session()

    def reset_session(self, current_key_nr: int = 0):
        LOGGER.debug("Resetting transaction id, command counter and session keys")
        self.cmdctr = 0
        self.ti = 4 * b"\0"
        self.current_key_nr = current_key_nr
        self.k_ses_auth_enc = 16 * b"\0"
        self.k_ses_auth_mac = 16 * b"\0"

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

    def crc(self, data: bytes) -> bytes:
        config = Configuration(
            width=32,
            polynomial=0x04C11DB7,
            init_value=0xFFFFFFFF,
            final_xor_value=0x00,
            reverse_output=True,
            reverse_input=True,
        )
        jamcrc = Calculator(config)
        return pack("<L", jamcrc.checksum(data))

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
            bytearray(command.value).hex(),
            hdr.hex(),
            data.hex(),
        )
        res = self.tag.send_apdu(
            *command.value, hdr + data, mrl=mrl, check_status=False
        )
        status, rapdu = res[-2:], res[:-2]
        LOGGER.debug("RECV: status %s, payload %s", status.hex(), rapdu.hex())

        if status != expected.value:
            raise Type4TagCommandError.from_status(status)

        return rapdu

    def send_command_mac(
        self,
        command: "CommandHeader",
        hdr: bytes,
        data: bytes,
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        # ref: page 28, chapter 9.1.9
        if self.ti == 4 * b"\0":
            LOGGER.info("Not authenticated for command mode FULL; authenticating")
            self.authenticate_ev2_first()

        LOGGER.debug(
            "MAC: command %s, counter %d, TI %s, hdr %s, data %s",
            command.value[1].to_bytes().hex(),
            self.cmdctr,
            self.ti.hex(),
            hdr.hex(),
            data.hex(),
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
            self.reset_session(self.current_key_nr)
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
                    mac_returned.hex(),
                    mac_returned_expected.hex(),
                )
            LOGGER.debug("Returned MAC matches expected MAC")
        else:
            LOGGER.debug("No MAC provided in response")
            data_verified = b""

        return data_verified

    def send_command_full(
        self,
        command: "CommandHeader",
        hdr: bytes,
        data: bytes,
        mrl: int = 256,
        expected: Status = Status(DEFAULT_STATUS_OK),
    ) -> bytes:
        if self.ti == 4 * b"\0":
            LOGGER.info("Not authenticated for command mode FULL; authenticating")
            self.authenticate_ev2_first()

        LOGGER.debug("ENC: payload %s", data.hex())
        cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, self.ivc)
        encrypted = cipher.encrypt(pad(data, 16, style="iso7816"))

        try:
            res = self.send_command_mac(command, hdr, encrypted, mrl, expected)
        except Type4TagCommandError:
            self.reset_session(self.current_key_nr)
            raise

        if res:
            LOGGER.debug("DEC: payload %s", res.hex())
            cipher = AES.new(self.k_ses_auth_enc, AES.MODE_CBC, self.ivr)
            decrypted = cipher.decrypt(res)
        else:
            LOGGER.debug("No payload to decrypt")
            decrypted = encrypted

        return decrypted

    def select_application(self, aid: "Application"):
        LOGGER.debug("Selecting application %s", aid.value.hex())
        self.send_command_plain(CommandHeader.ISO_SELECT_NDEF_APP, data=aid.value)
        self.reset_session(self.current_key_nr)

    def derive_challenge_response(
        self, key: bytes, e_rndb: bytes
    ) -> tuple[bytes, bytes, bytes]:
        cipher = AES.new(key, AES.MODE_CBC, NULL_IV)
        rndb = cipher.decrypt(e_rndb)
        rndb_ = rndb[1:] + rndb[0].to_bytes()
        rnda = get_random_bytes(16)
        LOGGER.debug("AUTH: RndA %s, RndB %s", rnda.hex(), rndb.hex())

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

    def authenticate_ev2_first(self) -> bool:
        # ref: page 50, chapter 11.4.1
        self.select_application(Application.NDEF)
        self.reset_session(self.current_key_nr)

        LOGGER.debug(
            "AUTH: Doing EV2 authentication with key nr %d", self.current_key_nr
        )

        key = self._keys[self.current_key_nr]

        e_rndb = self.send_command_plain(
            CommandHeader.AUTH_EV2_FIRST,
            pack("<H", self.current_key_nr),
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
            self.ti.hex(),
            self.pdcap2.hex(),
            self.pcdcap2.hex(),
        )

        rnda_ = data[4:20]
        rnda_recv = rnda_[-1].to_bytes() + rnda_[:-1]
        if rnda_recv != rnda:
            raise ValueError("Received RndA does not match")
        LOGGER.debug("AUTH: RndA challenge response matches")

        self.k_ses_auth_enc, self.k_ses_auth_mac = self.derive_session_keys(
            key, rnda, rndb
        )

        return True

    def authenticate_ev2_non_first(self) -> bool:
        # ref: page 53, capter 11.4.2
        raise NotImplementedError()

    def authenticate_lrp_first(self) -> bool:
        # ref: page 55, capter 11.4.3
        raise NotImplementedError()

    def authenticate_lrp_non_first(self) -> bool:
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
        LOGGER.debug("Changing key nr %d", key_nr)

        if self.current_key_nr == key_nr:
            LOGGER.debug("Authenticated as same key to be changed")
            key_data = new_key + version.to_bytes()
        else:
            LOGGER.debug("Authenticated as different key than that to be changed")
            key_data = (
                bytes_xor(new_key, self._keys[key_nr])
                + version.to_bytes()
                + self.crc(new_key)
            )

        self.send_command_full(
            CommandHeader.CHANGE_KEY,
            key_nr.to_bytes(),
            key_data,
            expected=Status.OK,
        )

        self._keys[key_nr] = new_key
        self.reset_session(self.current_key_nr)
        return True

    def get_key_version(self):
        # ref: page 69, chapter 11.6.2
        raise NotImplementedError()

    def get_file_settings(self, file_nr: int) -> FileSettings:
        # ref: page 75, chapter 11.7.2
        LOGGER.debug("Getting settings of file number %d", file_nr)

        # FIXME make key number selectable
        data = self.send_command_mac(
            CommandHeader.GET_FILE_SETTINGS,
            file_nr.to_bytes(),
            b"",
            expected=Status.OK,
        )
        LOGGER.debug("Received file settings: %s", data.hex())

        return FileSettings.from_bytes(data)

    def change_file_settings(self, file_nr: int, file_settings: FileSettings):
        # ref: page 70, chapter 11.7.1
        LOGGER.debug("Changing settings of file number %d", file_nr)

        settings_data = file_settings.to_bytes()
        LOGGER.debug("Sending file settings: %s", settings_data.hex())

        # FIXME make key number selectable
        self.send_command_full(
            CommandHeader.CHANGE_FILE_SETTINGS,
            file_nr.to_bytes(),
            settings_data,
            expected=Status.OK,
        )

    def read_data(
        self,
        file_nr: int,
        file_settings: Optional[FileSettings] = None,
        offset: int = 0,
        length: int = 0,
        reauth: bool = False,
    ) -> bytes:
        # ref: page 79, chapter 11.8.1
        if file_settings is None:
            file_settings = self.get_file_settings(file_nr)

        if length == 0:
            length = file_settings.file_size - offset - 2

        if offset + length > file_settings.file_size:
            raise ValueError("Requested data is longer than file")

        if length > 254:
            # FIXME we could fragment into multiple commands here
            raise ValueError("Data does not fit into response")

        header = file_nr.to_bytes() + pack("<L", offset)[:3] + pack("<L", length)[:3]

        _previous_key_nr = self.current_key_nr
        if self.current_key_nr not in (
            file_settings.access_rights.read.value,
            file_settings.access_rights.read_write.value,
        ):
            if reauth:
                LOGGER.warning(
                    "Current key %d has no read access to file; changing key to %d",
                    self.current_key_nr,
                    file_settings.access_rights.read.value,
                )
                self.reset_session(file_settings.access_rights.read.value)
            else:
                LOGGER.warning(
                    "Current key %d has no read access to file; trying anyway",
                    self.current_key_nr,
                )

        if file_settings.file_option.comm_mode == CommMode.PLAIN:
            res = self.send_command_plain(
                CommandHeader.READ_DATA, header, b"", expected=Status.OK
            )
        elif file_settings.file_option.comm_mode == CommMode.MAC:
            res = self.send_command_mac(
                CommandHeader.READ_DATA, header, b"", expected=Status.OK
            )
        elif file_settings.file_option.comm_mode == CommMode.FULL:
            res = self.send_command_full(
                CommandHeader.READ_DATA, header, b"", expected=Status.OK
            )
        else:
            res = b""

        if reauth and self.current_key_nr != _previous_key_nr:
            LOGGER.warning("Changing key back to %d", _previous_key_nr)
            self.reset_session(_previous_key_nr)

        return res

    def write_data(
        self,
        file_nr: int,
        data: bytes,
        file_settings: Optional[FileSettings] = None,
        offset: int = 0,
        pad: bool = False,
        reauth: bool = False,
    ):
        # ref: page 81, chapter 11.8.2
        if file_settings is None:
            file_settings = self.get_file_settings(file_nr)

        if offset + len(data) > file_settings.file_size:
            raise ValueError("Data does not fit into file")

        if pad and len(data) - offset < 248:
            data += (248 - len(data) - offset) * b"\0"

        if len(data) > 248:
            # FIXME we could fragment into multiple commands here
            raise ValueError("Data does not fit into command")

        header = file_nr.to_bytes() + pack("<L", offset)[:3] + pack("<L", len(data))[:3]

        _previous_key_nr = self.current_key_nr
        if self.current_key_nr not in (
            file_settings.access_rights.write.value,
            file_settings.access_rights.read_write.value,
        ):
            if reauth:
                LOGGER.warning(
                    "Current key %d has no write access to file; changing key to %d",
                    self.current_key_nr,
                    file_settings.access_rights.write.value,
                )
                self.reset_session(file_settings.access_rights.write.value)
            else:
                LOGGER.warning(
                    "Current key %d has no write access to file; trying anyway",
                    self.current_key_nr,
                )

        if file_settings.file_option.comm_mode == CommMode.PLAIN:
            self.send_command_plain(
                CommandHeader.WRITE_DATA, header, data, expected=Status.OK
            )
        elif file_settings.file_option.comm_mode == CommMode.MAC:
            self.send_command_mac(
                CommandHeader.WRITE_DATA, header, data, expected=Status.OK
            )
        elif file_settings.file_option.comm_mode == CommMode.FULL:
            self.send_command_full(
                CommandHeader.WRITE_DATA, header, data, expected=Status.OK
            )

        if reauth and self.current_key_nr != _previous_key_nr:
            LOGGER.warning("Changing key back to %d", _previous_key_nr)
            self.reset_session(_previous_key_nr)
