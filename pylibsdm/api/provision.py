# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""(JSON) API definitions for provisioning of NFC tags."""

import logging
from typing import Literal, Optional, Union

import nfc
from pydantic import BaseModel, Field, NonNegativeInt

from ..tag.structs import FileSettings, URLParamConfig
from ..tag.tag import Tag

logger = logging.getLogger(__name__)


tag_config_types: dict[str, type] = {}
for name, module in Tag.get_tag_modules().items():
    logger.debug("Defining API types for %s", name)

    class RawFileConfig(BaseModel):
        f"""Manual configuration of all file attributes and data of a {name} tag."""

        settings: module.FileSettings = Field(
            description="Settings for the file to deploy"
        )
        data: bytes = Field(description="Raw binary data for the file")

        def get_file_settings(self) -> module.FileSettings:
            return self.settings

        def get_file_data(self) -> bytes:
            return self.data

    class TagConfig(BaseModel):
        f"""Configuration container for provisioning a {name} tag."""

        tag_module: Literal[name] = name

        keys: dict[NonNegativeInt, bytes] = Field(
            description="Set of keys to change on tag", default_factory=dict
        )
        files: dict[NonNegativeInt, module.URLParamConfig | RawFileConfig] = Field(
            description="Set of files to change on tag", default_factory=dict
        )

    tag_config_types[name] = TagConfig


class ProvisionResult(BaseModel):
    """Result of a provisioning job."""

    tag_uid: bytes = Field(description="UID of provisioned NFC tag")
    # FIXME add status of some sort


class ProvisionJob(BaseModel):
    """Job definition for a tag provisioning job."""

    keys: Optional[dict[NonNegativeInt, bytes]] = Field(
        default=None, description="Current set of cryptographic keys (if needed)"
    )
    tag_config: Union[tuple(tag_config_types.values())] = Field(
        description="Configuration to provision to tag"
    )

    def run(self, nfc_tag: nfc.tag.Tag) -> ProvisionResult:
        """Provision one tag"""
        logger.info("Provisioning tag %s", str(nfc_tag))
        # FIXME error handling, ProvisionResult generation
        # FIXME should we get an sdm_tag directly?
        sdm_tag: Tag = Tag.get_tag_module(self.tag_config.tag_module).Tag(
            nfc_tag, self.keys
        )

        for key_nr, key in self.tag_config.keys.items():
            logger.info("Deploying key nr. %d", key_nr)
            sdm_tag.change_key(key_nr, key)

        for file_nr, file_config in self.tag_config.files.items():
            file_settings = file_config.get_file_settings()
            logger.info("Changing file settings for file nr. %d", file_nr)
            sdm_tag.change_file_settings(file_nr, file_settings)

            file_data = file_config.get_file_data()
            logger.info("Writing file data for file nr. %d", file_nr)
            sdm_tag.write_data(file_nr, file_data, file_settings, pad=True)
