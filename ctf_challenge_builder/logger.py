#!/usr/bin/env python3
"""
Logger module for Challenge Builder
"""

import colorama
from colorama import Fore, Back, Style

# Initialize colorama
colorama.init(autoreset=True)


class Logger:
    @staticmethod
    def info(message: str):
        print(f"{Fore.LIGHTBLUE_EX}ℹ️  {message}{Style.RESET_ALL}")

    @staticmethod
    def success(message: str):
        print(f"{Fore.GREEN}✅ {message}{Style.RESET_ALL}")

    @staticmethod
    def final(message: str):
        print(f"{Back.GREEN}{Fore.BLACK}🎉 {message} {Style.RESET_ALL}")

    @staticmethod
    def warning(message: str):
        print(f"{Fore.YELLOW}⚠️  {message}{Style.RESET_ALL}")

    @staticmethod
    def error(message: str):
        print(f"{Fore.RED}❌ {message}{Style.RESET_ALL}")

    @staticmethod
    def step(message: str):
        print(f"{Fore.CYAN}🔧 {message}{Style.RESET_ALL}")

    @staticmethod
    def build(message: str):
        print(f"{Fore.MAGENTA}🏗️  {message}{Style.RESET_ALL}")

    @staticmethod
    def push(message: str):
        print(f"{Fore.LIGHTBLUE_EX}📤 {message}{Style.RESET_ALL}")

    @staticmethod
    def pull(message: str):
        print(f"{Fore.LIGHTBLUE_EX}📥 {message}{Style.RESET_ALL}")