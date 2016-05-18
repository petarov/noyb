# NOYB

Encrypts and syncs local files with Google Drive. Because my files are _None Of Your Business_ Google.

# Requirements

  * Python `2.7`
  * [google-api-python-client](https://github.com/google/google-api-python-client)
  * [httplib2](https://pypi.python.org/pypi/httplib2)

On Archlinux

    pacman -S python2-httplib2
    pacman -S python2-google-api-python-client

# Usage

## Obtaining Google API credentials

This is a bit cumbersome, but the good news is that you only need to it once.

Follow the Google [Creating web application credentials](https://developers.google.com/api-client-library/python/auth/web-app#creatingcred) documentation.
You don't need to execute the `redirect URIs` step (Step 3).

To configure the authentication run the following:

    noyb.py config -cs cclient_secrets.json -a MyAppName

You will receive the following message on the console.

```
You need to generate a Google API access token.
Please open the following url: https://accounts.google.com/o/oauth2/auth?scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fdrive.metadata.readonly&redirect_uri=http%3A%2F%2Flocalhost&response_type=code&client_id=1234567890-jasjjekre890201291122.apps.googleusercontent.com&access_type=offline
and save
```

Copy and paste the url portion in your browser. You will get back an authorization token, e.g.,

      http://localhost/?code=4/8whoTOfwR2qIFqYsJQNhlcpv83H4_a7zLIe5g0v9drw#

Run the configuration command again and pass the token:

          noyb.py config -cs cclient_secrets.json -a MyAppName -ac '4/8whoTOfwR2qIFqYsJQNhlcpv83H4_a7zLIe5g0v9drw'

# License

[MIT License](LICENSE)
