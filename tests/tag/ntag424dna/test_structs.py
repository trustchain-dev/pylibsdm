import pytest
from binascii import unhexlify

from pylibsdm.tag.ntag424dna.structs import (
    AccessCondition,
    AccessRights,
    CommMode,
    FileSettings,
    FileType,
)


def test_access_rights_from_bytes():
    # ref: page 26
    acs = AccessRights.from_bytes(unhexlify("00E0"))
    assert acs.read_write == AccessCondition.KEY_0
    assert acs.change == AccessCondition.KEY_0
    assert acs.read == AccessCondition.FREE_ACCESS
    assert acs.write == AccessCondition.KEY_0


@pytest.mark.xfail(True, reason="Apparently broken test case in spec")
def test_file_settings_from_bytes():
    # ref: page 26, table 12
    file_settings = FileSettings.from_bytes(
        unhexlify("004000E0000100C1F121200000430000")
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
