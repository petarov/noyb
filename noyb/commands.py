# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import sys
import argparse
import logging

from .config import *

def cmd_config(args):
    logging.info('configuring ...')

    home_dir = os.path.expanduser('~')
    config_dir = os.path.join(home_dir, CFG_DIRNAME)

    config = config_load(config_dir, args)
    gdrive_creds = gdrive_get_creds(config_dir, args)
    if not gdrive_creds or gdrive_creds.invalid:
        logging.error('No valid credentials found! Cannot continue.')

    gdrive_service = gdrive_get_service(gdrive_creds)

def cmd_init(args):
    local_config = config_local_load(os.getcwd(), args)

def cmd_push(args):
    logging.info('pushing ...')

    home_dir = os.path.expanduser('~')
    config_dir = os.path.join(home_dir, CFG_DIRNAME)

    config = config_load(config_dir, args)
    gdrive_creds = gdrive_get_creds(config_dir, args)
    if not gdrive_creds or gdrive_creds.invalid:
        logging.error('No valid credentials found! Cannot continue.')

    gdrive_service = gdrive_get_service(gdrive_creds)

    local_config = config_local_load(os.getcwd(), args)
    gpg = gnupg.GPG(verbose=False,
        homedir=local_config['gnupg'])

    for file in os.listdir(os.getcwd()):
        if file.endswith('.zip'):
            dest_path = os.path.join(config['temp'], file + '.gpg')

            logging.debug('encrypt {0} ...'.format(file))
            f = open(file, 'r')
            encrypted = gpg.encrypt(f,
                local_config['keyid'], always_trust=True,
                output=dest_path)

            logging.debug('uploading {0} ...'.format(dest_path))
            media_body = apiclient.http.MediaFileUpload(
                dest_path,
                mimetype='application/octet-stream'
            )
            metadata = {
              'name': file,
              'description': 'my test upload',
              'custom_noyb': 'NOYB'
            }
            new_file = gdrive_service.files().create(body=metadata,
                media_body=media_body).execute()
