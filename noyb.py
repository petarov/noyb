#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import sys
import argparse
import logging
import tempfile
import json

import gnupg

import httplib2
from mimetypes import guess_type
from apiclient import discovery
import apiclient
import oauth2client

#
# Set defaults
#
reload(sys)
sys.setdefaultencoding('utf-8')
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout, level=logging.DEBUG)
logging.getLogger('gnupg').setLevel(logging.WARNING)
logging.getLogger('oauth2client').setLevel(logging.WARNING)

#
# Globals
#
CFG_DIRNAME = '.noyb'
CFG_DIRNAME_LOCAL = '.noyb'
CFG_FILENAME = 'config.json'
CFG_GDRIVE_FILENAME = 'gdrive.json'
CFG_GDRIFE_SCOPES = 'https://www.googleapis.com/auth/drive.file '
'https://www.googleapis.com/auth/drive.metadata.readonly'

#
# Functions
#

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


def gdrive_get_creds(config_dir, args):
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)

    credential_path = os.path.join(config_dir, CFG_GDRIVE_FILENAME)
    logging.debug('loading google drive credentials from {0}'.format(
        credential_path))
    store = oauth2client.file.Storage(credential_path)
    credentials = store.get()
    if not credentials or credentials.invalid:
        flow = oauth2client.client.flow_from_clientsecrets(args.clientsecret,
            scope=CFG_GDRIFE_SCOPES,
            redirect_uri='http://localhost')
        flow.access_type = 'offline'
        flow.user_agent = args.appname

        if args.authcode:
            logging.debug('storing google drive credentials to {0}'.format(
                credential_path))
            credentials = flow.step2_exchange(args.authcode)
            storage = oauth2client.file.Storage(credential_path)
            storage.put(credentials)
        else:
            auth_uri = flow.step1_get_authorize_url()
            print ('You need to generate a Google API access token. '
                'Please open the following url: \n\n{0}\n\n'
                'Afterwards pass the authentication token using '
                'the ''-ac'' parameter.'.format(auth_uri))
            sys.exit(401)
    elif credentials.access_token_expired:
        print (vars(credentials))
        logging.debug('google drive credentials are expired!')
        sys.exit(401)

    return credentials

def gdrive_get_service(creds):
    http = creds.authorize(httplib2.Http())
    service = discovery.build('drive', 'v3', http=http)
    return service


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

#
# Parse arguments
#
COMMANDS = ['config', 'init', 'push']

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
