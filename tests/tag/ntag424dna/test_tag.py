# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""Test cases derived from examples in NXP's documentation.

Reference: https://www.nxp.com/docs/en/application-note/AN12196.pdf
"""
from binascii import hexlify, unhexlify
from typing import Optional
from unittest import mock

import pytest

from pylibsdm.tag.ntag424dna.const import Application, CommandHeader, Status
from pylibsdm.tag.ntag424dna.structs import (
    AccessCondition,
    AccessRights,
    CommMode,
    FileOption,
    FileSettings,
    SDMAccessRights,
    SDMOptions,
)
from pylibsdm.tag.ntag424dna.tag import NTAG424DNA


class MockType4Tag:
    """Mocks an ndeflib tag so that its send_apdu method returns defined values."""

    apdu_map: dict[str, str] = {
        "00A4040C07D276000085010100": "9000",
        "9071000002000000": "A04C124213C186F22399D33AC2A3021591AF",
        "9071000002030000": "B875CEB0E66A6C5CD00898DC371F92D191AF",
        "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00": "3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F081206639100",
        "90AF000020FF0306E47DFBC50087C4D8A78E88E62DE1E8BE457AA477C707E2F0874916A8B100": "0CC9A8094A8EEA683ECAAC5C7BF20584206D0608D477110FC6B3D5D3F65C3A6A9100",
        "90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FDA6610234BDED643200": "9100",
        "90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600": "203BB55D1089D5879100",
        "90770000010000": "A6A2B3C572D06C097BB8DB70463E22DC91AF",
        # FIXME two following lines probably wrong due to broken spec
        "90AF000020BE7D45753F2CAB85F34BC60CE58B940763FE969658A532DF6D95EA2773F6E99100": "B888349C24B315EAB5B589E279C8263E9100",
        "905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400": "57BFF87B1241E93D9100",
        "908D00001F030000000A00006B5E6804909962FC4E3FF5522CF0F8436C0C53315B9C73AA00": "C26D236E4A7C046D9100",
        "908D000019010E0000120000FF0506E1050080828300000000000000000000": "9100",
    }

    def __init__(self, apdu_map: Optional[dict[str, str]] = None):
        self.apdu_map.update(apdu_map or {})
        self.apdus_called = []

    def send_apdu(self, cla, ins, ps1, ps2, data, mrl, check_status):
        """Returns defined R-APDUs instead of talking to a real tag."""
        apdu = (
            cla.to_bytes()
            + ins.to_bytes()
            + ps1.to_bytes()
            + ps2.to_bytes()
            + len(data).to_bytes()
            + data
            + (mrl % 256).to_bytes()
        )

        apdu_hex = hexlify(apdu).decode().upper()
        self.apdus_called.append(apdu_hex)

        rapdu = unhexlify(self.apdu_map.get(apdu_hex))
        if rapdu is None:
            raise ValueError(f"Unexpected APDU: {apdu}")

        return rapdu


@pytest.fixture
def sdm_tag():
    return NTAG424DNA(MockType4Tag())


def test_reset_keys(sdm_tag):
    assert sdm_tag._keys == [16 * b"\0"] * 5
    sdm_tag.set_key(0, b"0123456789abcdef")
    sdm_tag.set_key(1, b"0123456789abcdef")
    sdm_tag.set_key(2, b"0123456789abcdef")
    sdm_tag.set_key(3, b"0123456789abcdef")
    sdm_tag.set_key(4, b"0123456789abcdef")
    assert sdm_tag._keys == [b"0123456789abcdef"] * 5
    sdm_tag.reset_keys()
    assert sdm_tag._keys == [16 * b"\0"] * 5


def test_reset_session(sdm_tag):
    assert (sdm_tag.ti, sdm_tag.cmdctr, sdm_tag.current_key_nr) == (4 * b"\0", 0, 0)
    assert sdm_tag.k_ses_auth_enc == 16 * b"\0"
    assert sdm_tag.k_ses_auth_mac == 16 * b"\0"
    sdm_tag.ti, sdm_tag.cmdctr, sdm_tag.current_key_nr = 4 * b"\xAF", 1, 2
    sdm_tag.k_ses_auth_enc = 16 * b"\xAF"
    sdm_tag.k_ses_auth_mac = 16 * b"\xAF"
    sdm_tag.reset_session()
    assert (sdm_tag.ti, sdm_tag.cmdctr, sdm_tag.current_key_nr) == (4 * b"\0", 0, 0)
    assert sdm_tag.k_ses_auth_enc == 16 * b"\0"
    assert sdm_tag.k_ses_auth_mac == 16 * b"\0"


@pytest.mark.parametrize("key_nr", [0, 1, 2, 3, 4])
def test_set_key(sdm_tag, key_nr):
    expected = [16 * b"\0"] * 5
    expected[key_nr] = 16 * b"\xAF"

    sdm_tag.set_key(key_nr, 16 * b"\xAF")
    assert sdm_tag._keys == expected


def test_ivc(sdm_tag):
    # ref: page 41, table 27
    sdm_tag.ti = unhexlify("7614281A")
    sdm_tag.cmdctr = 3
    sdm_tag.k_ses_auth_enc = unhexlify("4CF3CB41A22583A61E89B158D252FC53")
    assert sdm_tag.ivc == unhexlify("01602D579423B2797BE8B478B0B4D27B")


def test_send_command_plain(sdm_tag):
    # ref: page 29, table 14
    rapdu = sdm_tag.send_command_plain(
        CommandHeader.AUTH_EV2_FIRST,
        b"\0\0",
        expected=Status.ADDITIONAL_DF_EXPECTED,
    )
    assert rapdu == unhexlify("A04C124213C186F22399D33AC2A30215")


def test_select_application(sdm_tag):
    # ref: page 25, table 11
    sdm_tag.select_application(Application.NDEF)
    assert "00A4040C07D276000085010100" in sdm_tag.tag.apdus_called


def test_authenticate_ev2_first_key_0(sdm_tag):
    # ref: page 29, table 14
    with mock.patch(
        "pylibsdm.tag.ntag424dna.tag.get_random_bytes",
        return_value=unhexlify("13C5DB8A5930439FC3DEF9A4C675360F"),
    ):
        sdm_tag.authenticate_ev2_first()

    assert sdm_tag.tag.apdus_called == [
        "00A4040C07D276000085010100",
        "9071000002000000",
        "90AF00002035C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D00",
    ]
    assert sdm_tag.ti == unhexlify("9D00C4DF")
    assert sdm_tag.pdcap2 == unhexlify("000000000000")
    assert sdm_tag.pcdcap2 == unhexlify("000000000000")
    assert sdm_tag.k_ses_auth_enc == unhexlify("1309C877509E5A215007FF0ED19CA564")
    assert sdm_tag.k_ses_auth_mac == unhexlify("4C6626F5E72EA694202139295C7A7FC7")


def test_authenticate_ev2_first_key_3(sdm_tag):
    # ref: page 35, table 20
    with mock.patch(
        "pylibsdm.tag.ntag424dna.tag.get_random_bytes",
        return_value=unhexlify("B98F4C50CF1C2E084FD150E33992B048"),
    ):
        sdm_tag.reset_session(3)
        sdm_tag.authenticate_ev2_first()

    assert sdm_tag.tag.apdus_called == [
        "00A4040C07D276000085010100",
        "9071000002030000",
        "90AF000020FF0306E47DFBC50087C4D8A78E88E62DE1E8BE457AA477C707E2F0874916A8B100",
    ]
    assert sdm_tag.ti == unhexlify("7614281A")
    assert sdm_tag.pdcap2 == unhexlify("000000000000")
    assert sdm_tag.pcdcap2 == unhexlify("000000000000")
    assert sdm_tag.k_ses_auth_enc == unhexlify("7A93D6571E4B180FCA6AC90C9A7488D4")
    assert sdm_tag.k_ses_auth_mac == unhexlify("FC4AF159B62E549B5812394CAB1918CC")


def test_change_key_0(sdm_tag):
    # ref: page 41, table 27
    sdm_tag.k_ses_auth_enc = unhexlify("4CF3CB41A22583A61E89B158D252FC53")
    sdm_tag.k_ses_auth_mac = unhexlify("5529860B2FC5FB6154B7F28361D30BF9")
    sdm_tag.ti = unhexlify("7614281A")
    sdm_tag.cmdctr = 3

    res = sdm_tag.change_key(0, unhexlify("5004BF991F408672B1EF00F08F9E8647"))
    assert res
    assert (
        "90C400002900C0EB4DEEFEDDF0B513A03A95A75491818580503190D4D05053FF75668A01D6FDA6610234BDED643200"
        in sdm_tag.tag.apdus_called
    )


def test_change_key_2(sdm_tag):
    # ref: page 41, table 27
    sdm_tag.k_ses_auth_enc = unhexlify("4CF3CB41A22583A61E89B158D252FC53")
    sdm_tag.k_ses_auth_mac = unhexlify("5529860B2FC5FB6154B7F28361D30BF9")
    sdm_tag.ti = unhexlify("7614281A")
    sdm_tag.cmdctr = 2

    res = sdm_tag.change_key(2, unhexlify("F3847D627727ED3BC9C4CC050489B966"))
    assert res
    assert (
        "90C4000029022CF362B7BF4311FF3BE1DAA295E8C68DE09050560D19B9E16C2393AE9CD1FAC75D0CE20BCD1D06E600"
        in sdm_tag.tag.apdus_called
    )


def test_get_file_settings(sdm_tag):
    pass


@pytest.mark.xfail(True, reason="Test data broken in spec")
def test_change_file_settings(sdm_tag):
    # ref: page 34, table 19
    sdm_tag.k_ses_auth_enc = unhexlify("1309C877509E5A215007FF0ED19CA564")
    sdm_tag.k_ses_auth_mac = unhexlify("4C6626F5E72EA694202139295C7A7FC7")

    file_option = FileOption(sdm_enabled=True, comm_mode=CommMode.PLAIN)
    access_rights = AccessRights(
        AccessCondition.FREE_ACCESS,
        AccessCondition.KEY_0,
        AccessCondition.KEY_0,
        AccessCondition.KEY_0,
    )
    sdm_options = SDMOptions(
        uid=True,
        read_ctr=True,
        read_ctr_limit=False,
        enc_file_data=False,
        tt_status=False,
        ascii_encoding=True,
    )
    sdm_acceess_rights = SDMAccessRights(
        AccessCondition.KEY_2, AccessCondition.KEY_1, AccessCondition.KEY_1
    )

    file_settings = FileSettings(
        file_option=file_option,
        access_rights=access_rights,
        sdm_options=sdm_options,
        sdm_access_rights=sdm_acceess_rights,
        picc_data_offset=32,
        mac_offset=67,
        mac_input_offset=67,
    )
    sdm_tag.change_file_settings(2, file_settings)

    assert (
        "905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400"
        in sdm_tag.tag.apdus_called
    )


def test_write_data_3(sdm_tag):
    # ref: page 37, table 22
    sdm_tag.k_ses_auth_enc = unhexlify("7A93D6571E4B180FCA6AC90C9A7488D4")
    sdm_tag.k_ses_auth_mac = unhexlify("FC4AF159B62E549B5812394CAB1918CC")
    sdm_tag.ti = unhexlify("7614281A")
    sdm_tag.cmdctr = 0

    file_settings = FileSettings(
        file_option=FileOption(comm_mode=CommMode.FULL), file_size=128
    )

    sdm_tag.write_data(3, unhexlify("0102030405060708090A"), file_settings)

    assert (
        "908D00001F030000000A00006B5E6804909962FC4E3FF5522CF0F8436C0C53315B9C73AA00"
        in sdm_tag.tag.apdus_called
    )


def test_write_data_1(sdm_tag):
    # ref: page 37, table 22
    file_settings = FileSettings(
        file_option=FileOption(comm_mode=CommMode.PLAIN), file_size=32
    )

    sdm_tag.write_data(
        1, unhexlify("FF0506E10500808283000000000000000000"), file_settings, offset=14
    )

    assert (
        "908D000019010E0000120000FF0506E1050080828300000000000000000000"
        in sdm_tag.tag.apdus_called
    )
