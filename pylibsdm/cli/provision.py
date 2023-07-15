# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

import logging
from pathlib import Path
from typing import Annotated, Optional

import nfc
import typer
from rich.pretty import pretty_repr

from .. import tag

TagModule = tag.Tag.get_tag_modules_enum()

app = typer.Typer()

logger = logging.getLogger(__name__)


@app.callback()
def configure_provision(
    ctx: typer.Context,
    tag_module: Optional[TagModule] = typer.Option(
        None, help="Type of NFC tag to provision", case_sensitive=False
    ),
    key: Annotated[
        Optional[list[str]],
        typer.Option(help="(Current) key for slot x as hex string, e.g. 0:aabbcc"),
    ] = None,
    json: Optional[Path] = typer.Option(None, help="Path to a JSON file to read/write"),
):
    """Provision (configure) NFC tokens for SDM usage"""
    if tag_module:
        ctx.obj["tag_module"] = tag.Tag.get_tag_module(tag_module)
    else:
        ctx.obj["tag_module"] = tag

    ctx.obj["keys"] = {}
    for slot_key in key or []:
        slot, key_hex = slot_key.split(":")
        ctx.obj["keys"][int(slot)] = bytes.fromhex(key_hex)

    ctx.obj["json"] = json


@app.command()
def get_file_settings(
    ctx: typer.Context,
    file_nr: int = typer.Argument(help="File number to retrieve settings for"),
):
    """Retrieve current settings for a file on tag"""

    def _do_get_file_settings(tag: tag.Tag) -> bool:
        try:
            file_settings = tag.get_file_settings(file_nr)
            logger.info(
                "Retrieved file settings:\n%s", pretty_repr(dict(file_settings))
            )
            if ctx.obj["json"]:
                with open(ctx.obj["json"], "wt") as json_file:
                    json_file.write(file_settings.model_dump_json(indent=2))
            if not ctx.obj["batch"]:
                raise typer.Exit(code=0)
        except nfc.tag.TagCommandError as exc:
            logger.error("Could not retrieve file settings: %s", str(exc))
            if not ctx.obj["batch"]:
                raise typer.Exit(code=1)

        return True

    while True:
        # FIXME add timeout; possibly move elsewhere
        ctx.obj["tag_module"].Tag.connect_loop(
            ctx.obj["clf"], _do_get_file_settings, keys=ctx.obj["keys"]
        )


@app.command()
def change_file_settings(
    ctx: typer.Context,
    file_nr: int = typer.Argument(help="File number to retrieve settings for"),
    yes: bool = typer.Option(help="Confirm changing file settings", prompt=True),
):
    """Change settings for a file on tag"""
    if ctx.obj["json"]:
        with open(ctx.obj["json"], "rt") as json_file:
            file_settings = ctx.obj["tag_module"].FileSettings.model_validate_json(
                json_file.read()
            )
    else:
        logger.critical(
            "Changing file settings is currently only possible with --json input"
        )
        raise typer.Exit(code=2)

    def _do_change_file_settings(tag: tag.Tag) -> bool:
        try:
            tag.change_file_settings(file_nr, file_settings)
            logger.info("Changed file settings of file nr. %d", file_nr)
            if not ctx.obj["batch"]:
                raise typer.Exit(code=0)
        except nfc.tag.TagCommandError as exc:
            logger.error("Could not change file settings: %s", str(exc))
            if not ctx.obj["batch"]:
                raise typer.Exit(code=1)

        return True

    while True:
        # FIXME add timeout; possibly move elsewhere
        ctx.obj["tag_module"].Tag.connect_loop(
            ctx.obj["clf"], _do_change_file_settings, keys=ctx.obj["keys"]
        )
