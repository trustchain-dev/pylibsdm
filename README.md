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

`pylibsdm` can be used for arbitrarily complex configurations, but is designed
to cover the most common use cases with some semantic sugar.

In this example, we will configure an NTAG424DNA for the following behaviour:

 * Change app key 1 to our own key
 * Configure write access to NDEF data to need authentication with app key 0
 * Configure the NDEF file to mirror UID and read counter encrypted with key 1,
   and a CMAC using key 1

This is a common configuration allowing a backend to verify tag authenticity
when the URL is requested with minimal overhead.

```python
import ndef
from pylibsdm.tag.ntag424dna import FileSettings, Tag

# We need a working tag object from nfcpy
nfc_tag = ...

# Configure the SDM tag object for communication
sdm_tag = Tag(nfc_tag)

# Set current master app key nr 0 for authentication
sdm_tag.set_key(0, bytes.fromhex("00112233445566778899aabbccddeeff"))

# Change app key 1 for later use
sdm_tag.change_key(1, 16 * b"\xaa")

# When reading the NDEF message, app key 1 is used for encryption
sdm_acceess_rights = SDMAccessRights(
    file_read=AccessCondition.KEY_1,
    meta_read=AccessCondition.KEY_1,
)

# Generate file settings for URL and placeholder URL
file_settings, file_data = FileSettings(
    "https://example.com/thing/12",
    param_picc_data="p",
    param_cmac="c"
)

# Change the NDEF file settings to the generated values
sdm_tag.change_file_settings(2, file_settings)

# Write the generated URL
#  https://example.com/thing/12?p=00000000000000000000000000000000&c=0000000000000000
nfc_tag.ndef.records = [ndef.URIRecord(file_data)]
```
