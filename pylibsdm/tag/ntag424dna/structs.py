from dataclasses import dataclass
from enum import IntEnum
from struct import pack, unpack
from typing import Optional, Self


class CommMode(IntEnum):
    # ref: page 13, table 12
    PLAIN = 0
    MAC = 1
    FULL = 2


class FileType(IntEnum):
    # ref: page 11, table 6
    STANDARD_DATA = 0


class AccessCondition(IntEnum):
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
