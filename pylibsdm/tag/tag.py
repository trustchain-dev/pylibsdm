from typing import Callable

import nfc


class Tag:
    _tag_types: dict[str, type] = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._tag_types[cls.__name__] = cls

    @classmethod
    def connect_loop(cls, clf: nfc.clf.ContactlessFrontend, cb: Callable[["Tag"], bool]):
        """Enter connect loop and call a callback for every connect."""

        def _wrap_connect(nfc_tag: nfc.tag.Tag) -> bool:
            sdm_tag = cls(nfc_tag)
            return cb(sdm_tag)

        clf.connect(
            rdwr={
                "on-connect": _wrap_connect,
            }
        )
