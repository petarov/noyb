# -*- coding: utf-8 -*-

"""
noyb.gdrive
------------------
Google Drive driver
"""

import httplib2
from mimetypes import guess_type
from apiclient import discovery
import apiclient
import oauth2client

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
