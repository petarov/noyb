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
import oauth2client

#
# Set defaults
#
reload(sys)
sys.setdefaultencoding('utf-8')
logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s',
    stream=sys.stdout, level=logging.DEBUG)
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
    data = {'temp': args.temp}
    with open(config_path, 'w') as outfile:
        json.dump(data, outfile, indent = 2, ensure_ascii=False)

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

def config_local_create_default(config_path, args):
    logging.debug('creating new local repo config file at {0}'.format(config_path))
    data = {'gnupg': args.gnupg, 'keyid': args.keyid}
    with open(config_path, 'w') as outfile:
        json.dump(data, outfile, indent = 2, ensure_ascii=False)

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
            print ('You need to generate a Google API access token.\n'
                'Please open the following url: {0}\n'
                'and save'.format(auth_uri))
    elif credentials.access_token_expired:
        logging.debug('google drive credentials are expired!')
        sys.exit(401)

    return credentials

def gdrive_get_service(creds):
    http = creds.authorize(httplib2.Http())
    service = discovery.build('drive', 'v3', http=http)
    return service

def cmd_enr():
    logging.info('initializing ...')

    gpg = gnupg.GPG(verbose=False,
        homedir='./tests')
    pubkeys = gpg.list_keys()
    for gpgkey in pubkeys:
        for k, v in gpgkey.items():
            print ("%s: %s" % (k.capitalize(), v))

    f = open('tests/test.tgz', 'r')
    encrypted = gpg.encrypt(f,
        'C7B5AD893CDFEF33', passphrase='test', always_trust=True,
        output='tests/test.pgp')

def cmd_config(args):
    logging.info('configuring ...')

    home_dir = os.path.expanduser('~')
    config_dir = os.path.join(home_dir, CFG_DIRNAME)

    config = config_load(config_dir, args)
    gdrive_creds = gdrive_get_creds(config_dir, args)
    if not gdrive_creds or gdrive_creds.invalid:
        logging.error('No valid credentials found! Cannot continue.')

    gdrive_service = gdrive_get_service(gdrive_creds)
    results = gdrive_service.files().list(
        pageSize=10, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])
    if not items:
        print('No files found.')
    else:
        print('Files:')
        for item in items:
            print('{0} ({1})'.format(item['name'], item['id']))

def cmd_init(args):
    local_config = config_local_load(os.getcwd(), args)


def cmd_push():
    logging.info('pushing ...')

#
# Parse arguments
#
COMMANDS = ['config', 'init', 'push']

parser = argparse.ArgumentParser(
    description="Don't worry loves, cavalry's here!")

group = parser.add_argument_group(
    '[register] configure authentication')

group = parser.add_argument_group(
    '[config] global configurations')
group.add_argument('-cs', '--clientsecret',
    help='path to Google Drive client secret json file')
group.add_argument('-ac', '--authcode',
    help='Google Drive OAuth2 authorization code')
group.add_argument('-a', '--appname',
    help='name of Google Drive app to register (custom)')
group.add_argument('-t', '--temp',
    default=tempfile.gettempdir(),
    help='save temporary files to this path')

group = parser.add_argument_group(
    '[init] initializes a directory to be pushed to remote')
group.add_argument('-g', '--gnupg',
    help='GnuPG keystore path')
group.add_argument('-k', '--keyid',
    help='keypair ID to use to encrypt directory files')

group = parser.add_argument_group(
    '[push] pushes all unchanged files in the current directory')
group.add_argument('-f', '--force', action='store_true',
    help='skips file change verification')

parser.add_argument('command',
    help='command to execute')

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
