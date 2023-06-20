from binascii import unhexlify

from pylibsdm.backend.validate import ParamValidator


def test_generate_sdm_session_key():
    validator = ParamValidator(unhexlify("5ACE7E50AB65D5D51FD5BF5A16B8205B"))
    validator.uid = unhexlify("04C767F2066180")
    validator.read_ctr = 1

    k_ses_sdm_file_read_enc, k_ses_sdm_file_read_mac = validator.generate_sdm_session_key()

    assert k_ses_sdm_file_read_enc == unhexlify("66DA61797E23DECA5D8ECA13BBADF7A9")
    assert k_ses_sdm_file_read_mac == unhexlify("3A3E8110E05311F7A3FCF0D969BF2B48")


def test_decrypt_picc_data():
    validator = ParamValidator()
    validator.decrypt_picc_data("EF963FF7828658A599F3041510671E88")

    assert validator.uid == unhexlify("04DE5F1EACC040")
    assert validator.read_ctr == 61
