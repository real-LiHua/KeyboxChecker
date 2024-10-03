#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# pylint: disable=C0114
import argparse
import sys

from keyboxchecker import main

parser = argparse.ArgumentParser("keyboxchecker")
parser.add_argument(
    "-a",
    "--aosp",
    action="store_true",
    help='Categorizes the AOSP keybox as "Survivor" with a default value of "False"',
)
parser.add_argument(
    "-o",
    "--output",
    default=".",
    help="Resulting output directory, defaults to current directory",
)
parser.add_argument(
    "-p",
    "--path",
    default=".",
    help="Directory where keybox is located, defaults to current directory",
)


def cli():
    main(parser.parse_args())


if __name__ == "__main__":
    sys.exit(cli())
