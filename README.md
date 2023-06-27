<!--
SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>

SPDX-License-Identifier: LGPL-2.0-or-later
-->

# pylibsdm - NFC Secure Dynamic Messaging with Python

pylibsdm is a Python library (SDK) for handling Secure Dynamic Messaging (SDM)
of NFC cards with Python.

Secure Dynamic Messaging is a technology that adds security features to
NFC tags using standard mechanisms. While standard NFC data (so-called
NDEF messages, e.g. texts, URLs, etc.) can be written to any compatible
tag, SUN-capable tags can cryptographically sign and optionally also
encrypt parts of the data, which can then still be read by any standard
NFC reader.

## Features

* Card management / configuration
  * Configuration of NDEF file settings (mirrors, offsets, used keys,…)
  * Configuration of NDEF file data (URL)
  * Provisioning of keys
* Backend implementation for SUN (Secure Unique NFC)
  * Decryption and validation of SDM data (mirrors)
  * Validation of information from URI parameters

## Supported tags

* [NTAG 424 DNA](https://www.nxp.com/products/rfid-nfc/nfc-hf/ntag-for-tags-and-labels/ntag-424-dna-424-dna-tagtamper-advanced-security-and-privacy-for-trusted-iot-applications:NTAG424DNA)
  ([specification](https://www.nxp.com/docs/en/application-note/AN12196.pdf))

## Installation and usage

`pylibsdm` is shipped as a standard Python library and cann be installed
from PyPI:

```sh
pip install "pylibsdm[cli]"
```

The `cli` extra installs the `sdmutil` command-line utility, which can
be used as a stand-alone tool to handle tags.

### Usage as a library in own code

The following examples show how to use `pylibsdm` within custom
applications. It can, as such, be seen as an SDK for writing SUN-capable
applications.

#### Configuring a tag in code

We will configure a tag for the following behaviour:

 * Change app keys 1 and 2 to our own keys
 * Configure write access to NDEF data to need authentication with app key 1
 * Configure SDM to encrypt and sign data with key 2
 * Mirror encrypted PICC data (UID and read counter)
 * Mirror a CMAC for validation

```python
from pylibsdm.tag.ntag424dna import Tag

# We need a working tag object from nfcpy
nfc_tag = ...

# Configure the SDM tag object for communication
sdm_tag = Tag(nfc_tag)

# Set current master app key nr 0 for authentication
sdm_tag.set_key(0, b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff")

# Change app keys 1 and 2 for later use
sdm_tag.change_key(1, 16 * b"\xaa")
sdm_tag.change_key(2, 16 * b"\xaa")

# Configure attributes for mirroring
file_option = FileOption(sdm_enabled=True, comm_mode=CommMode.PLAIN)
sdm_options = SDMOptions(
    uid=True,
    read_ctr=True,
    read_ctr_limit=False,
    enc_file_data=False,
    tt_status=False,
    ascii_encoding=True,
)

# We configure free reading access of NDEF, writing data is limited to app key 1,
#  and changing file settings to the master app key 0
access_rights = AccessRights(
    read=AccessCondition.FREE_ACCESS,
    write=AccessCondition.1,
    read_write=AccessCondition.KEY_1,
    change=AccessCondition.KEY_0,
)
# When reading the NDEF message, app key 2 is used for
sdm_acceess_rights = SDMAccessRights(
    file_read=AccessCondition.KEY_2,
    meta_read=AccessCondition.KEY_2,
    ctr_ret=AccessCondition.KEY_2,
)

# Aggregate options and offsets in NDEF data
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
```
