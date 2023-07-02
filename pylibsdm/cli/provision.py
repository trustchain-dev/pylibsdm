# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

import logging
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Optional

import nfc
import typer
from rich.pretty import pretty_repr

from ..tag.tag import Tag

TagModule = StrEnum("TagModule", {name: name for name in Tag.get_tag_modules().keys()})

app = typer.Typer()

logger = logging.getLogger(__name__)


@app.callback()
def configure_provision(
    ctx: typer.Context,
    tag_module: TagModule = typer.Argument(
        ..., help="Type of NFC tag to provision", case_sensitive=False
    ),
    key: Annotated[
        Optional[list[str]],
        typer.Option(help="(Current) key for slot x as hex string, e.g. 0:aabbcc"),
    ] = None,
    json: Optional[Path] = typer.Option(None, help="Path to a JSON file to read/write"),
):
    """Provision (configure) NFC tokens for SDM usage"""
    ctx.obj["tag_module"] = Tag.get_tag_module(tag_module)

    # TODO handle keys

    ctx.obj["json"] = json


@app.command()
def auth(
    ctx: typer.Context,
    key_nr: int = typer.Argument(help="Key slot number to test auth with"),
):
    """Test authentication with a key number"""

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
            logger.error(
                "Authentication with key number %d unsuccessful: %s", key_nr, msg
            )
            if not ctx.obj["batch"]:
                raise typer.Exit(code=1)

        return True

    while True:
        # FIXME add timeout; possibly move elsewhere
        ctx.obj["tag_module"].Tag.connect_loop(ctx.obj["clf"], _do_auth)


@app.command()
def get_file_settings(
    ctx: typer.Context,
    file_nr: int = typer.Argument(help="File number to retrieve settings for"),
):
    """Retrieve current settings for a file on tag"""

    def _do_get_file_settings(tag: Tag) -> bool:
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
        ctx.obj["tag_module"].Tag.connect_loop(ctx.obj["clf"], _do_get_file_settings)


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

    def _do_change_file_settings(tag: Tag) -> bool:
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
        ctx.obj["tag_module"].Tag.connect_loop(ctx.obj["clf"], _do_change_file_settings)
