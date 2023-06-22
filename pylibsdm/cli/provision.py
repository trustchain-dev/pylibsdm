import logging
from enum import StrEnum
from typing import Annotated, Optional

import nfc
import typer

from ..tag.tag import Tag

TagType = StrEnum("TagType", {name: name for name in Tag._tag_types.keys()})

app = typer.Typer()

logger = logging.getLogger(__name__)


@app.callback()
def configure_provision(
    ctx: typer.Context,
    tag_type: TagType = typer.Argument(
        ..., help="Type of NFC tag to provision", case_sensitive=False
    ),
    key: Annotated[
        Optional[list[str]],
        typer.Option(help="(Current) key for slot x as hex string, e.g. 0:aabbcc"),
    ] = None,
):
    """Provision (configure) NFC tokens for SDM usage"""
    ctx.obj["tag_class"] = Tag._tag_types[tag_type.value]
    # TODO handle keys


@app.command()
def auth(
    ctx: typer.Context, key_nr: int = typer.Argument(help="Key slot number to test auth with")
):
    def _do_auth(tag: Tag) -> bool:
        msg = "unknown failure"
        try:
            # FIXME support dynamic authentication commands
            res = tag.authenticate_ev2_first(key_nr)
        except nfc.tag.TagCommandError as exc:
            res = False
            msg = str(exc)

        if res:
            logger.info("Authentication with key number %d successful.", key_nr)
            if not ctx.obj["batch"]:
                raise typer.Exit(code=0)
        else:
            logger.error("Authentication with key number %d unsuccessful: %s", key_nr, msg)
            if not ctx.obj["batch"]:
                raise typer.Exit(code=1)

        return True

    while True:
        # FIXME add timeout; possibly move elsewhere
        ctx.obj["tag_class"].connect_loop(ctx.obj["clf"], _do_auth)
