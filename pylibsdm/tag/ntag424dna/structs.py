# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Structures for communication with NTAG424DNA"""

from enum import IntEnum
from logging import getLogger
from struct import pack, unpack
from typing import Optional, Self

from pydantic import BaseModel, model_validator
from pydantic.types import NonNegativeInt, PositiveInt

logger = getLogger(__name__)


class CommMode(IntEnum):
    """Communication mode for commands sent to PICC.

    The communication mode defines security and authentication while communicating
    with the PICC.

    Defined in spec on page 13, table 12.
    """

    #: Plain mode; commands are neither sigend nor encrypted
    PLAIN = 0
    #: MAC mode; commands are signed using CMAC with an AES key
    MAC = 1
    #: Full mode; commands are signed with CMAC and command data is encrypted
    FULL = 2


class FileType(IntEnum):
    """File type of one data file on the PICC.

    Defined in spec on page 11, table 6.
    """

    STANDARD_DATA = 0


class AccessCondition(IntEnum):
    """Access condition / key selection for various features.

    This structure is used both for file access rights and SDM access rights.

    Defined in spec on page 11, table 6.
    """

    #: App MasterKey (slot number 0)
    KEY_0 = 0
    #: App key number 1
    KEY_1 = 1
    #: App key number 2
    KEY_2 = 2
    #: App key number 3
    KEY_3 = 3
    #: App key number 4
    KEY_4 = 4
    #: Access without providing a key / unauthenticated access
    FREE_ACCESS = 0xE
    #: No access / access denied
    NO_ACCESS = 0xF


class AccessRights(BaseModel):
    """Access rights to a data file on the PICC.

    Defined in spec on page 11, table 7.
    """

    #: Selects a key which can read the file data
    read: AccessCondition
    #: Selects a key which can write the file data
    write: AccessCondition
    #: Selects a key which can both read and write the file data
    read_write: AccessCondition
    #: Selects a key which can change the file settings
    change: AccessCondition

    def to_bytes(self):
        """Serialize access rights for use on wire (e.g. ChangeFileSettings)."""
        b1 = self.read_write.value * 16 + self.change.value
        b2 = self.read.value * 16 + self.write.value
        return b1.to_bytes() + b2.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Deserialize access rights from wire (e.g. in GetFileSettings)."""
        read = AccessCondition(data[1] >> 4)
        write = AccessCondition(data[1] & 15)
        read_write = AccessCondition(data[0] >> 4)
        change = AccessCondition(data[0] & 15)

        return cls(read=read, write=write, read_write=read_write, change=change)


class FileOption(BaseModel):
    """Options to set on a file.

    Defined in spec on page 75, table 73.
    """

    #: SDM (Secure Dynamic Messaging) and mirroring is enabled
    sdm_enabled: bool
    #: Communication mode needed to access file data
    comm_mode: CommMode

    def to_bytes(self) -> bytes:
        """Serialize file option for wire (e.g. in ChangeFileSettings)."""
        data = 0
        data |= int(self.sdm_enabled) * 64
        data |= self.comm_mode.value
        return data.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Deserialize file option from wire, e.g. in GetFileSettings)."""
        sdm_enabled = bool(data[0] & 64)
        comm_mode = CommMode(data[0] & 3)
        return cls(sdm_enabled=sdm_enabled, comm_mode=comm_mode)


class SDMOptions(BaseModel):
    """Detailed options for SDM (Secure Dynamic Messaging).

    These options define exactly which mirroring features are enabled.

    Defined in spec on page 71, table 69.
    """

    #: Enable UID mirroring
    uid: bool
    #: Enable read counter mirroring
    read_ctr: bool
    #: Enable limitation for read counter
    read_ctr_limit: bool
    #: Enable mirroring of encrypted file data
    enc_file_data: bool
    #: Enable mirroring of tag tamper status
    tt_status: bool
    #: Enable ASCII encoding of mirrored data
    ascii_encoding: bool = True

    def to_bytes(self) -> bytes:
        """Serialize SDM options for wire (e.g. in ChangeFileSettings)."""
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
        """Deserialize SDM options from wire (e.g. in GetFileSettings)."""
        ascii_encoding = bool(data[0] & 1)
        tt_status = bool(data[0] & 8)
        enc_file_data = bool(data[0] & 16)
        read_ctr_limit = bool(data[0] & 32)
        read_ctr = bool(data[0] & 64)
        uid = bool(data[0] & 128)
        return cls(
            uid=uid,
            read_ctr=read_ctr,
            read_ctr_limit=read_ctr_limit,
            enc_file_data=enc_file_data,
            tt_status=tt_status,
            ascii_encoding=ascii_encoding,
        )


class SDMAccessRights(BaseModel):
    """Access rights during read of NDEF data with mirroring.

    Defined in spec on page 71, table 69.
    """

    #: Key allowed to read meta data (UID)
    meta_read: AccessCondition
    #: Key allowed to read encrypted file data
    file_read: AccessCondition
    #: Key allowed to read counter
    ctr_ret: AccessCondition

    def to_bytes(self):
        """Serialize SDM access rights for wire (e.g. in ChangeFileSettings)."""
        b1 = 15 * 16 + self.ctr_ret.value
        b2 = self.meta_read.value * 16 + self.file_read.value
        return b1.to_bytes() + b2.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Deserialize SDM access rights from wire (e.g. in GetFileSettings)."""
        meta_read = AccessCondition(data[1] >> 4)
        file_read = AccessCondition(data[1] & 15)
        ctr_ret = AccessCondition(data[0] & 15)

        return cls(meta_read=meta_read, file_read=file_read, ctr_ret=ctr_ret)


# FIXME maybe implement standard files, table 8 et al


class FileSettings(BaseModel):
    """Container for all settings of a data file.

    Defined in spec on page 75, table 73.
    """

    file_option: FileOption
    access_rights: AccessRights
    sdm_options: Optional[SDMOptions] = None
    sdm_access_rights: Optional[SDMAccessRights] = None

    #: Offset to mirror UID at
    uid_offset: Optional[NonNegativeInt] = None
    #: Offset to mirror read counter at
    read_ctr_offset: Optional[NonNegativeInt] = None
    #: Offset to mirror PICC data at
    picc_data_offset: Optional[NonNegativeInt] = None
    #: Offset to mirror tag tamper status at
    tt_status_offset: Optional[NonNegativeInt] = None
    #: Offset to begin reading CMAC input from
    mac_input_offset: Optional[NonNegativeInt] = None
    #: Offset to mirror encrypted fiel data at, and start reading from
    enc_offset: Optional[NonNegativeInt] = None
    #: Length of file data to encrypt
    enc_length: Optional[NonNegativeInt] = None
    #: Offset to mirror CMAC at
    mac_offset: Optional[NonNegativeInt] = None
    #: Limit for read counter
    read_ctr_limit: Optional[PositiveInt] = None

    file_type: FileType = FileType.STANDARD_DATA
    #: Available size for file data
    file_size: Optional[PositiveInt] = None

    @model_validator(mode="after")
    def _check_combinations(cls, self: Self) -> Self:
        # ref: page 71, table 69
        logger.debug("Validating combinations of SDM options/offsets/lengths")

        if self.file_option.sdm_enabled:
            assert (
                self.sdm_options is not None
            ), "SDM options must be given if SDM is enabled"
            assert (
                self.sdm_access_rights is not None
            ), "SDM access rights must be given SDM is enabled"

        if (
            self.sdm_access_rights
            and self.sdm_access_rights.meta_read == AccessCondition.FREE_ACCESS
            and self.sdm_options
        ):
            if self.sdm_options.uid:
                assert (
                    self.uid_offset is not None
                ), "UID offset must be given if plain UID mirror is enabled"
            if self.sdm_options.read_ctr:
                assert (
                    self.read_ctr_offset is not None
                ), "Read counter offset must be given if plain read counter mirror is enabled"

        if (
            self.sdm_access_rights
            and self.sdm_access_rights.meta_read < AccessCondition.FREE_ACCESS
        ):
            assert (
                self.picc_data_offset is not None
            ), "PICC data offset must be given if encrypted meta access is enabled"

        if self.sdm_options and self.sdm_options.tt_status:
            assert (
                self.tt_status_offset is not None
            ), "TT status offset must be given if TT status mirror is enabled"

        if (
            self.sdm_access_rights
            and self.sdm_access_rights.file_read != AccessCondition.NO_ACCESS
        ):
            assert (
                self.mac_input_offset is not None
            ), "MAC input offset must be given if file read access is enabled"
            assert (
                self.mac_offset is not None
            ), "MAC offset must be given if file read access is enabled"
            assert (
                self.mac_input_offset <= self.mac_offset
            ), "MAC offset must be less or equal to MAC input offset"

            if self.sdm_options.enc_file_data:
                assert (
                    self.enc_offset is not None
                ), "Enc data offset must be given if enc file data mirror is enabled"
                assert (
                    self.enc_length is not None
                ), "Enc data length must be given if enc file data mirror is enabled"
                assert (
                    self.mac_input_offset <= self.enc_offset <= self.mac_offset - 32
                ), "Enc offset must be >= MAC input offset and <= MAC offset-32"
                assert (
                    32 <= self.enc_length <= self.mac_offset - self.enc_offset
                ), "Enc length must be between 32 and MAC offset - Enc offset"
                assert (
                    self.mac_offset >= self.enc_offset + self.enc_length
                ), "MAC offset must be greater than or equal to Enc offset + Enc length"

        if self.sdm_options and self.sdm_options.read_ctr_limit:
            assert (
                self.read_ctr_limit is not None
            ), "Read counter limit must be given if enabled"

        return self

    def to_bytes(self) -> bytes:
        """Serialize for wire (e.g. in ChangeFileSettings).

        `file_type` and `file_size` are not encoded; cf. page 70, table 69.
        """
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
        """Deserialize from wire (e.g. in GetFileSettings)."""
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
            file_option=file_option,
            access_rights=access_rights,
            sdm_options=sdm_options,
            sdm_access_rights=sdm_access_rights,
            uid_offset=uid_offset,
            read_ctr_offset=read_ctr_offset,
            picc_data_offset=picc_data_offset,
            tt_status_offset=tt_status_offset,
            mac_input_offset=mac_input_offset,
            enc_offset=enc_offset,
            enc_length=enc_length,
            mac_offset=mac_offset,
            read_ctr_limit=read_ctr_limit,
            file_type=file_type,
            file_size=file_size,
        )
