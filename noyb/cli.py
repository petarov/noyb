#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import logging
import tempfile

from .commands import *

reload(sys)
sys.setdefaultencoding('utf-8')

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout, level=logging.DEBUG)
logging.getLogger('gnupg').setLevel(logging.WARNING)
logging.getLogger('oauth2client').setLevel(logging.WARNING)


COMMANDS = ['config', 'init', 'push']

def main():
    """
        Parse command line parameters
    """
    parser = argparse.ArgumentParser(add_help=False,
        description="Don't worry loves, cavalry's here!")
    subparsers = parser.add_subparsers(dest='command')

    parser_config = subparsers.add_parser('config',
        description='Configure general authentication.')
    parser_config.add_argument('-cs', '--clientsecret',
        help='path to Google Drive client secret json file')
    parser_config.add_argument('-ac', '--authcode',
        help='Google Drive OAuth2 authorization code')
    parser_config.add_argument('-a', '--appname',
        help='name of Google Drive app to register (custom)')
    parser_config.add_argument('-t', '--temp',
        default=tempfile.gettempdir(),
        help='save temporary files to this path')

    parser_init = subparsers.add_parser('init',
        description='Initializes a directory to be pushed to remote.')
    parser_init.add_argument('-g', '--gnupg',
        help='GnuPG key rings directory path')
    parser_init.add_argument('-i', '--keyid',
        help='keypair ID to use to encrypt directory files')
    parser_init.add_argument('-n', '--enable-names',
        help='do not encrypt file names',
        action='store_true', default=False)

    parser_push = subparsers.add_parser('push',
        description='Pushes all unchanged files in the current directory.')
    parser_push.add_argument('-f', '--force', action='store_true',
        help='skips file change verification')

    parser_pull = subparsers.add_parser('pull',
        description='Pulls all unchanged files in the current directory')
    parser_pull.add_argument('-f', '--force', action='store_true',
        help='skips file change verification')

    args = parser.parse_args()
    command = args.command
    if (command not in COMMANDS):
        parser.print_help()
        sys.exit(-1)

    if (command == 'config'):
        cmd_config(args)
    elif (command == 'init'):
        cmd_init(args)
    elif (command == 'push'):
        cmd_push(args)
    elif (command == 'pull'):
        cmd_pull(args)

if __name__ == "__main__":
    main()
