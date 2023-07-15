# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

import pytest

from typer.models import NoneType

from pylibsdm.tag.ntag424dna.structs import (
    AccessCondition,
    AccessRights,
    CommMode,
    FileSettings,
    FileType,
)


def test_access_rights_from_bytes():
    # ref: page 26
    acs = AccessRights.from_bytes(bytes.fromhex("00E0"))
    assert acs.read_write == AccessCondition.KEY_0
    assert acs.change == AccessCondition.KEY_0
    assert acs.read == AccessCondition.FREE_ACCESS
    assert acs.write == AccessCondition.KEY_0


@pytest.mark.xfail(True, reason="Apparently broken test case in spec")
def test_file_settings_from_bytes():
    # ref: page 26, table 12
    file_settings = FileSettings.from_bytes(
        bytes.fromhex("004000E0000100C1F121200000430000")
    )

    assert file_settings.file_type == FileType.STANDARD_DATA
    assert file_settings.file_size == 256

    assert file_settings.file_option.sdm_enabled
    assert file_settings.file_option.comm_mode == CommMode.PLAIN

    assert file_settings.access_rights.read_write == AccessCondition.KEY_0
    assert file_settings.access_rights.change == AccessCondition.KEY_0
    assert file_settings.access_rights.read == AccessCondition.FREE_ACCESS
    assert file_settings.access_rights.write == AccessCondition.KEY_0

    assert file_settings.sdm_options is not None
    assert file_settings.sdm_access_rights is not None

    assert file_settings.sdm_options.uid
    assert file_settings.sdm_options.read_ctr
    assert file_settings.sdm_options.ascii_encoding
    assert not file_settings.sdm_options.read_ctr_limit

    assert file_settings.sdm_access_rights.ctr_ret == AccessCondition.KEY_1
    assert file_settings.sdm_access_rights.meta_read == AccessCondition.KEY_2
    assert file_settings.sdm_access_rights.file_read == AccessCondition.KEY_1

    assert file_settings.uid_offset == 32
    assert file_settings.read_ctr_offset == 67


def test_file_settings_for_url_against_tagwriter():
    # URL constructed using NXP TagWriter some time ago
    file_settings, file_data = FileSettings.for_url(
        "http://172.31.201.52:8000/o/core/person/1?authenticators=nfc_sdm",
        param_picc_data="picc_data",
        param_enc_data="enc",
        param_cmac="cmac",
        plain_enc_data=16 * "x",
    )

    assert file_settings.file_option.sdm_enabled

    assert file_settings.sdm_options is not None
    assert file_settings.sdm_access_rights is not None

    assert file_settings.sdm_options.uid
    assert file_settings.sdm_options.read_ctr
    assert file_settings.sdm_options.enc_file_data
    assert file_settings.sdm_options.ascii_encoding

    assert file_settings.sdm_access_rights.meta_read < AccessCondition.FREE_ACCESS
    assert file_settings.sdm_access_rights.file_read < AccessCondition.FREE_ACCESS

    assert file_settings.uid_offset is None
    assert file_settings.read_ctr_offset is None
    assert file_settings.picc_data_offset == 75
    assert file_settings.enc_length == 32
    assert file_settings.enc_offset == 112
    assert file_settings.mac_input_offset == 75
    assert file_settings.mac_offset == 150
