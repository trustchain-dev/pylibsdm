# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Constants for communication protocol of NTAG424DNA"""

from enum import Enum


class CommandHeader(Enum):
    # ref: page 47, table 22
    # FIXME complete, if that makes sense
    # FIXME only store command numbers here?
    ISO_SELECT_NDEF_APP = (0x00, 0xA4, 0x04, 0x0C)
    AUTH_EV2_FIRST = (0x90, 0x71, 0x00, 0x00)
    AUTH_AES_NON_FIRST = (0x90, 0x77, 0x00, 0x00)
    ADDITIONAL_DF = (0x90, 0xAF, 0x00, 0x00)
    CHANGE_KEY = (0x90, 0xC4, 0x00, 0x00)
    GET_FILE_SETTINGS = (0x90, 0xF5, 0x00, 0x00)
    CHANGE_FILE_SETTINGS = (0x90, 0x5F, 0x00, 0x00)


class Status(Enum):
    # ref: page 48, table 23
    # FIXME complete, if that makes sense
    COMMAND_SUCCESSFUL = b"\x90\x00"
    OK = b"\x91\x00"
    ADDITIONAL_DF_EXPECTED = b"\x91\xAF"


class Application(Enum):
    NDEF = b"\xd2\x76\x00\x00\x85\x01\x01"


DEFAULT_STATUS_OK = b"\x90\x00"
