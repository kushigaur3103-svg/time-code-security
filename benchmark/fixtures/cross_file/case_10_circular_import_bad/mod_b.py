import os

from mod_a import DEFAULT_TARGET


def process_step(host):
    return os.system("ping -c 1 " + host)


def describe_target():
    return DEFAULT_TARGET
