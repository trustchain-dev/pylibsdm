# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Test cases derived from examples in NXP's documentation.

Reference: https://www.nxp.com/docs/en/application-note/AN12196.pdf
"""
from binascii import unhexlify

from pylibsdm.backend.validate import ParamValidator


def test_generate_sdm_session_keys():
    # ref: page 10, table 2
    validator = ParamValidator("5ACE7E50AB65D5D51FD5BF5A16B8205B")
    validator.uid = unhexlify("04C767F2066180")
    validator.read_ctr = 1

    validator.generate_sdm_session_keys()

    assert validator.k_ses_sdm_file_read_enc == unhexlify("66DA61797E23DECA5D8ECA13BBADF7A9")
    assert validator.k_ses_sdm_file_read_mac == unhexlify("3A3E8110E05311F7A3FCF0D969BF2B48")


def test_decrypt_picc_data():
    # ref: page 12, table 3
    validator = ParamValidator()
    validator.decrypt_picc_data("EF963FF7828658A599F3041510671E88")

    assert validator.uid == unhexlify("04DE5F1EACC040")
    assert validator.read_ctr == 61


def test_decrypt_file_data():
    # ref: page 13, table 4
    validator = ParamValidator()
    file_data = validator.decrypt_file_data(
        "94592FDE69FA06E8E3B6CA686A22842B", "FDE4AFA99B5C820A2C1BB0F1C792D0EB"
    )

    assert file_data == unhexlify("78787878787878787878787878787878")


def test_validate_cmac_zero_length():
    # ref: apge 15, table 5
    validator = ParamValidator()

    assert validator.validate_cmac("94EED9EE65337086", "EF963FF7828658A599F3041510671E88")


def test_validate_cmac_input():
    # ref: page 17, table 6
    validator = ParamValidator()

    assert validator.validate_cmac(
        "ECC1E7F6C6C73BF6",
        "FD91EC264309878BE6345CBE53BADF40",
        "CEE9A53E3E463EF1F459635736738962&cmac=",
    )


def test_parse_uri_picc_data():
    # ref: page 11, table 3
    validator = ParamValidator(param_picc_data="e", param_cmac="c")
    validator.parse_uri(
        "https://ntag.nxp.com/424?e=EF963FF7828658A599F3041510671E88&c=94EED9EE65337086"
    )

    assert validator.uid == unhexlify("04DE5F1EACC040")
    assert validator.read_ctr == 61
    assert validator.uid_mirror
    assert validator.read_ctr_mirror


def test_parse_uri_enc_data():
    # ref: page 13, table 4
    validator = ParamValidator(param_picc_data="picc_data", param_enc_data="enc", param_cmac="cmac")
    validator.parse_uri(
        "https://my424dna.com/?picc_data=FDE4AFA99B5C820A2C1BB0F1C792D0EB&enc=94592FDE69FA06E8E3B6CA686A22842B&cmac=C48B89C17A233B2C"
    )

    assert validator.uid == unhexlify("04958CAA5C5E80")
    assert validator.read_ctr == 1
    assert validator.uid_mirror
    assert validator.read_ctr_mirror
    assert validator.file_data == unhexlify("78787878787878787878787878787878")


def test_parse_uri_cmac_zero_input():
    # ref: page 15, table 5
    validator = ParamValidator(param_picc_data="e", param_cmac="c")
    validator.parse_uri(
        "https://ntag.nxp.com/424?e=EF963FF7828658A599F3041510671E88&c=94EED9EE65337086"
    )

    assert validator.uid == unhexlify("04DE5F1EACC040")
    assert validator.read_ctr == 61
    assert validator.uid_mirror
    assert validator.read_ctr_mirror
    assert validator.cmac_valid


def test_parse_uri_cmac_param_input():
    # ref: page 17, table 6
    validator = ParamValidator(
        param_picc_data="picc_data", param_enc_data="enc", param_cmac="cmac", param_cmac_input="enc"
    )
    validator.parse_uri(
        "https://www.my424dna.com/?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6"
    )

    assert validator.uid == unhexlify("04958CAA5C5E80")
    assert validator.read_ctr == 8
    assert validator.uid_mirror
    assert validator.read_ctr_mirror
    assert validator.cmac_valid


def test_cmac_input_from_uri():
    cmac_input = ParamValidator.cmac_input_from_uri(
        "https://www.my424dna.com/?picc_data=FD91EC264309878BE6345CBE53BADF40&enc=CEE9A53E3E463EF1F459635736738962&cmac=ECC1E7F6C6C73BF6",
        "enc",
        "cmac",
    )

    assert cmac_input == "CEE9A53E3E463EF1F459635736738962&cmac="
