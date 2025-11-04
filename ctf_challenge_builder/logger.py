#!/usr/bin/env python3
"""
Logger module for Challenge Builder
"""

import sys
from typing import Optional

import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init(autoreset=True)

_LEVEL_STYLES = {
    "INFO": Fore.CYAN,
    "SUCCESS": Fore.GREEN,
    "FINAL": Fore.GREEN + Style.BRIGHT,
    "WARNING": Fore.YELLOW,
    "ERROR": Fore.RED,
    "STEP": Fore.MAGENTA,
    "BUILD": Fore.MAGENTA,
    "PUSH": Fore.BLUE,
    "PULL": Fore.BLUE,
}


def _emit(level: str, message: str, stream: Optional[int] = None):
    colour = _LEVEL_STYLES.get(level, "")
    prefix = f"[{level}]"
    output = f"{colour}{prefix} {message}{Style.RESET_ALL}"
    print(output, file=sys.stderr if level in {"WARNING", "ERROR"} else sys.stdout)


class Logger:
    @staticmethod
    def info(message: str):
        _emit("INFO", message)

    @staticmethod
    def success(message: str):
        _emit("SUCCESS", message)

    @staticmethod
    def final(message: str):
        _emit("FINAL", message)

    @staticmethod
    def warning(message: str):
        _emit("WARNING", message)

    @staticmethod
    def error(message: str):
        _emit("ERROR", message)

    @staticmethod
    def step(message: str):
        _emit("STEP", message)

    @staticmethod
    def build(message: str):
        _emit("BUILD", message)

    @staticmethod
    def push(message: str):
        _emit("PUSH", message)

    @staticmethod
    def pull(message: str):
        _emit("PULL", message)
