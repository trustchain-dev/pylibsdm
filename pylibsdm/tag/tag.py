# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

import logging
from importlib import import_module
from importlib.metadata import entry_points
from typing import Any, Callable, ClassVar

import nfc


logger = logging.getLogger(__name__)


class Tag:
    _tag_modules: ClassVar[dict[str, Any]] = {}

    @classmethod
    def load_tag_modules(cls):
        eps = entry_points(group="pylibsdm.tags")
        for ep in eps:
            logger.debug("Discovered tag module %s", ep.module)
            mod = import_module(ep.module)
            cls._tag_modules[mod.Tag.__name__] = mod

    @classmethod
    def get_tag_modules(cls) -> dict[str, Any]:
        if not cls._tag_modules:
            cls.load_tag_modules()
        return cls._tag_modules

    @classmethod
    def get_tag_module(cls, name: str) -> Any:
        if not cls._tag_modules:
            cls.load_tag_modules()
        return cls._tag_modules[name]

    @classmethod
    def connect_loop(
        cls, clf: nfc.clf.ContactlessFrontend, cb: Callable[["Tag"], bool]
    ):
        """Enter connect loop and call a callback for every connect."""

        def _wrap_connect(nfc_tag: nfc.tag.Tag) -> bool:
            sdm_tag = cls(nfc_tag)
            return cb(sdm_tag)

        clf.connect(
            rdwr={
                "on-connect": _wrap_connect,
            }
        )
