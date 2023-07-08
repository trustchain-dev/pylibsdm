# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Structures for communication with NTAG424DNA"""

from enum import IntEnum
from logging import getLogger
from struct import pack, unpack
from types import SimpleNamespace
from typing import Any, ClassVar, Optional, Self
from urllib.parse import parse_qsl, urldefrag, urlencode, urlparse, urlunparse

from pydantic import BaseModel, Field, root_validator
from pydantic.types import NonNegativeInt, PositiveInt

from ..structs import (
    FileSettings as BaseFileSettings,
    URLParamConfig as BaseURLParamConfig,
)


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
    read: AccessCondition = AccessCondition.FREE_ACCESS
    #: Selects a key which can write the file data
    write: AccessCondition = AccessCondition.FREE_ACCESS
    #: Selects a key which can both read and write the file data
    read_write: AccessCondition = AccessCondition.FREE_ACCESS
    #: Selects a key which can change the file settings
    change: AccessCondition = AccessCondition.KEY_0

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
    sdm_enabled: bool = False
    #: Communication mode needed to access file data
    comm_mode: CommMode = CommMode.PLAIN

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
    uid: bool = False
    #: Enable read counter mirroring
    read_ctr: bool = False
    #: Enable limitation for read counter
    read_ctr_limit: bool = False
    #: Enable mirroring of encrypted file data
    enc_file_data: bool = False
    #: Enable mirroring of tag tamper status
    tt_status: bool = False
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
    meta_read: AccessCondition = AccessCondition.NO_ACCESS
    #: Key allowed to read encrypted file data
    file_read: AccessCondition = AccessCondition.NO_ACCESS
    #: Key allowed to read counter
    ctr_ret: AccessCondition = AccessCondition.NO_ACCESS

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


class FileSettings(BaseFileSettings):
    """Container for all settings of a data file.

    Defined in spec on page 75, table 73.
    """

    file_option: FileOption = Field(default_factory=FileOption)
    access_rights: AccessRights = Field(default_factory=AccessRights)
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

    # FIXME get file attributes reliably
    file_type: FileType = FileType.STANDARD_DATA
    #: Available size for file data
    file_size: PositiveInt = 256

    # ASCII armored hex bytes
    # FIXME do we need to get these dynamically? do they differ betwwen tags?
    uid_length: ClassVar[int] = 14
    read_ctr_length: ClassVar[int] = 6
    picc_data_length: ClassVar[int] = 32

    @root_validator(pre=False, skip_on_failure=True)
    def _check_combinations(cls, data: dict[str, Any]) -> dict[str, Any]:
        # ref: page 71, table 69
        logger.debug("Validating combinations of SDM options/offsets/lengths")

        # FIXME Workaround to ease migration to Pydantic 2.0 style
        self = SimpleNamespace(**data)

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
                assert (
                    self.uid_offset <= self.file_size - cls.uid_length
                ), "UID does nto fit into file"
            if self.sdm_options.read_ctr:
                assert (
                    self.read_ctr_offset is not None
                ), "Read counter offset must be given if plain read counter mirror is enabled"
                assert (
                    self.read_ctr_offset <= self.file_size - cls.read_ctr_length
                ), "Read coutner does not fit into file"

            if self.sdm_options.uid and self.sdm_options.read_ctr:
                # ref: page 37, chapter 9.3.3
                assert (
                    self.uid_offset >= self.read_ctr_offset + cls.read_ctr_length
                    or self.read_ctr_offset >= self.uid_offset + cls.uid_length
                ), "UID and read counter must not overlap"

        if (
            self.sdm_access_rights
            and self.sdm_access_rights.meta_read < AccessCondition.FREE_ACCESS
        ):
            assert (
                self.picc_data_offset is not None
            ), "PICC data offset must be given if encrypted meta access is enabled"

            assert self.picc_data_offset <= self.file_size - cls.picc_data_length

            if (
                self.sdm_options.uid
                and self.sdm_access_rights
                and self.sdm_access_rights.meta_read == AccessCondition.FREE_ACCESS
            ):
                # ref: page 40, chapter 9.3.6
                assert (
                    self.uid_offset >= self.picc_data_offset + cls.picc_data_length
                    or self.picc_data_offset >= self.uid_offset + cls.uid_length
                ), "PICC data and UID must not overlap"
            if (
                self.sdm_options.read_ctr
                and self.sdm_access_rights
                and self.sdm_access_rights.meta_read == AccessCondition.FREE_ACCESS
            ):
                # ref: page 40, chapter 9.3.6
                assert (
                    self.read_ctr_offset >= self.picc_data_offset + cls.picc_data_length
                    or self.picc_data_offset
                    >= self.read_ctr_offset + cls.read_ctr_length
                ), "PICC data and read counter must not overlap"
            if self.sdm_options.enc_file_data:
                # ref: page 40, chapter 9.3.6
                assert (
                    self.enc_offset >= self.picc_data_offset + cls.picc_data_length
                    or self.picc_data_offset >= self.enc_offset + self.enc_length
                ), "PICC data and Enc data must not overlap"

        if self.sdm_options and self.sdm_options.tt_status:
            assert (
                self.tt_status_offset is not None
            ), "TT status offset must be given if TT status mirror is enabled"
            assert (
                self.tt_status_offset <= self.file_size - 2
            ), "TT status does not fit into file"

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
                assert self.enc_length >= 32, "Enc length must be at least 32"
                assert (
                    self.mac_input_offset
                    <= self.enc_offset
                    <= self.mac_offset - self.enc_length
                ), "Enc offset must be >= MAC input offset and <= MAC offset-enc length"
                assert (
                    self.enc_length
                    <= self.enc_length
                    <= self.mac_offset - self.enc_offset
                ), "Enc length must be between enc length and MAC offset - Enc offset"
                assert (
                    self.mac_offset >= self.enc_offset + self.enc_length
                ), "MAC offset must be greater than or equal to Enc offset + Enc length"

        if self.sdm_options and self.sdm_options.read_ctr_limit:
            assert (
                self.read_ctr_limit is not None
            ), "Read counter limit must be given if enabled"

        return data

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

    @classmethod
    def for_url(cls, config: "URLParamConfig") -> tuple[Self, str]:
        """Construct file settings for a desired URL to write to a tag.

        This method is the counterpart for
        :class:`pylibsdm.backend.validate.ParamValidator`
        and constructs a URL that can be validated with it
        if the same set of araguments is passed.
        """
        # FIXME Move to a generic location

        url, fragment = urldefrag(str(config.base_url))
        url = urlparse(url)
        params = parse_qsl(url.query)

        next_offset = len(urlunparse(url)) + 1

        file_option = FileOption(sdm_enabled=True, comm_mode=CommMode.PLAIN)
        access_rights = config.access_rights or AccessRights()
        sdm_options = config.sdm_options or SDMOptions()
        sdm_access_rights = config.sdm_access_rights or SDMAccessRights()
        file_settings = {}

        if config.param_uid:
            params.append((config.param_uid, cls.uid_length * "0"))
            sdm_options.uid = True
            file_settings["uid_offset"] = next_offset + len(config.param_uid) + 1
            next_offset += len(config.param_uid) + cls.uid_length + 2
            sdm_access_rights.meta_read = AccessCondition.FREE_ACCESS

        if config.param_read_ctr:
            params.append((config.param_read_ctr, cls.read_ctr_length * "0"))
            sdm_options.read_ctr = True
            file_settings["read_ctr_offset"] = (
                next_offset + len(config.param_read_ctr) + 1
            )
            next_offset += len(config.param_read_ctr) + cls.read_ctr_length + 2
            sdm_access_rights.meta_read = AccessCondition.FREE_ACCESS

        if config.param_picc_data:
            if config.param_uid or config.param_read_ctr:
                raise ValueError(
                    "PICC data cannot be combined with plain UID or read counter"
                )
            params.append((config.param_picc_data, cls.picc_data_length * "0"))
            sdm_options.uid = True
            sdm_options.read_ctr = True
            file_settings["picc_data_offset"] = (
                next_offset + len(config.param_picc_data) + 1
            )
            next_offset += len(config.param_picc_data) + cls.picc_data_length + 2
            if sdm_access_rights.meta_read >= AccessCondition.FREE_ACCESS:
                sdm_access_rights.meta_read = AccessCondition.KEY_0

        if config.param_enc_data:
            if not config.plain_enc_data:
                raise ValueError(
                    "Plain enc data must be provided to use enc data in URL"
                )
            if len(config.plain_enc_data) % 16 > 0:
                config.plain_enc_data += (16 - (len(config.plain_enc_data) % 16)) * "0"
            params.append(
                (
                    config.param_enc_data,
                    config.plain_enc_data + len(config.plain_enc_data) * "0",
                )
            )
            sdm_options.enc_file_data = True
            file_settings["enc_length"] = len(config.plain_enc_data) * 2
            file_settings["enc_offset"] = next_offset + len(config.param_enc_data) + 1
            next_offset += (
                len(config.param_enc_data) + len(config.plain_enc_data) * 2 + 2
            )
            if sdm_access_rights.file_read == AccessCondition.NO_ACCESS:
                sdm_access_rights.file_read = AccessCondition.KEY_0

        if config.param_cmac:
            params.append((config.param_cmac, 16 * "0"))
            file_settings["mac_offset"] = next_offset + len(config.param_cmac) + 1
            next_offset += len(config.param_cmac) + 16 * 2
            if sdm_access_rights.file_read == AccessCondition.NO_ACCESS:
                sdm_access_rights.file_read = AccessCondition.KEY_0

            if config.param_uid:
                file_settings["mac_input_offset"] = file_settings["uid_offset"]
            elif config.param_read_ctr:
                file_settings["mac_input_offset"] = file_settings["read_ctr_offset"]
            elif config.param_picc_data:
                file_settings["mac_input_offset"] = file_settings["picc_data_offset"]
            elif config.param_enc_data:
                file_settings["mac_input_offset"] = file_settings["enc_offset"]
            else:
                file_settings["mac_input_offset"] = file_settings["mac_offset"]

        file_settings = FileSettings(
            file_option=file_option,
            access_rights=access_rights,
            sdm_options=sdm_options,
            sdm_access_rights=sdm_access_rights,
            **file_settings,
        )

        file_url = url._replace(query=urlencode(params), fragment=fragment or None)

        return file_settings, urlunparse(file_url)


class URLParamConfig(BaseURLParamConfig):
    param_uid: Optional[str] = None
    param_read_ctr: Optional[str] = None
    param_picc_data: Optional[str] = None
    param_enc_data: Optional[str] = None
    param_cmac: Optional[str] = None
    plain_enc_data: Optional[str] = None
    access_rights: Optional[AccessRights] = None
    sdm_options: Optional[SDMOptions] = None
    sdm_access_rights: Optional[SDMAccessRights] = None

    def get_file_settings(self) -> "FileSettings":
        return FileSettings.for_url(self)[0]
