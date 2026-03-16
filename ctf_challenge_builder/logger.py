#!/usr/bin/env python3
"""
Logger module for Challenge Builder
"""

import logging
import sys

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    grey = "\x1b[38;20m"
    green = "\x1b[32;20m"
    yellow = "\x1b[33;20m"
    red = "\x1b[31;20m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"
    
    FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

    def __init__(self):
        super().__init__(fmt=self.FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
        self.FORMATS = {
            logging.DEBUG: self.grey + self.FORMAT + self.reset,
            logging.INFO: self.grey + self.FORMAT + self.reset,
            logging.WARNING: self.yellow + self.FORMAT + self.reset,
            logging.ERROR: self.red + self.FORMAT + self.reset,
            logging.CRITICAL: self.bold_red + self.FORMAT + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

def setup_logging():
    """Configure root logger with colored output"""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColoredFormatter())
    
    logging.basicConfig(
        level=logging.INFO,
        handlers=[handler]
    )

