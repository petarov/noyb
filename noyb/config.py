# -*- coding: utf-8 -*-

import os
import sys
import logging
import tempfile
import json
import gnupg

#
# Globals
#
CFG_DIRNAME = '.noyb'
CFG_DIRNAME_LOCAL = '.noyb'
CFG_FILENAME = 'config.json'
CFG_GDRIVE_FILENAME = 'gdrive.json'
CFG_GDRIFE_SCOPES = 'https://www.googleapis.com/auth/drive.file '
'https://www.googleapis.com/auth/drive.metadata.readonly'


def config_create_default(config_path, args):
    logging.debug('creating new config file at {0}'.format(config_path))

    if not os.path.exists(args.temp):
        logging.error('temp path ''{0}'' does not exist!'.format(args.temp))
        sys.exit(500)

    data = {'temp': args.temp}
    with open(config_path, 'w') as outfile:
        json.dump(data, outfile, indent=2, ensure_ascii=False)


def config_load(config_dir, args):
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    config_path = os.path.join(config_dir, CFG_FILENAME)
    if not os.path.exists(config_path):
        config_create_default(config_path, args)

    logging.debug('loading existing configuration from {0}'.format(config_path))
    with open(config_path, 'r') as infile:
        config = json.load(infile)
        return config


def config_gnupg_getkey(gnupg_path, keyid):
    logging.debug('verifying key={0} ...'.format(keyid))

    if not gnupg_path:
        gnupg_path = None

    gpg = gnupg.GPG(verbose='basic',
        homedir=gnupg_path)
    allkeys = gpg.list_keys()
    for gpgkey in allkeys:
        print (gpgkey['keyid'])
        if gpgkey['fingerprint'].endswith(keyid):
            logging.debug('Found GPG key={0}'.format(gpgkey['fingerprint']))
            return gpgkey


def config_local_create_default(config_path, args):
    logging.debug('creating new local repo config file at {0}'.format(config_path))
    data = {'gnupg': args.gnupg or '', 'keyid': args.keyid or ''}
    with open(config_path, 'w') as outfile:
        json.dump(data, outfile, indent=2, ensure_ascii=False)


def config_local_load(local_dir, args):
    local_config_path = os.path.join(local_dir, CFG_DIRNAME_LOCAL)
    if not os.path.exists(local_config_path):
        os.makedirs(local_config_path)

    local_config_path = os.path.join(local_config_path, CFG_FILENAME)
    if os.path.exists(local_config_path):
        logging.info('{0} is already initialized'.format(local_dir))
    else:
        logging.info('initializing ...')
        config_local_create_default(local_config_path, args)

    logging.debug('loading local configuration from {0}'.format(local_config_path))
    with open(local_config_path, 'r') as infile:
        config = json.load(infile)
        gpgkey = config_gnupg_getkey(config['gnupg'], config['keyid'])
        if not gpgkey:
            logging.error('Could not find GPG key={0}'.format(config['keyid']))
            sys.exit(401)

        return config
