try:
    from Crypto.Cipher import AES
except Exception, e:
    raise Exception("Error when trying to import pycrypto ( %s ), "
                    "if you're running on dev_appserver on GAE, "
                    "you will need to install the tar.gz version of PyCrypto "
                    "-- the pip version doesn't work with GAE" % e)
from hashlib import sha256
import json
from urllib import urlencode
import urllib2
import time
import logging


class WhiteGhost(object):

    # encryption key for blob data
    ENCRYPTION_KEY = 'M02cnQ51Ji97vwT4'

    # request token generator pattern
    PATTERN = '000111011110111000111101010111101'\
              '1010001001110011000110001000110'

    # current authentication token
    AUTH_TOKEN = None

    # initial static auth token used when logging in
    STATIC_TOKEN = 'm198sOkJEn37DjqZ32lpRu76xmw288xSQ9'

    # snapchat api host.
    API_HOST = 'https://feelinsonice.appspot.com'

    # Secret (used as a Salt for request tokens)
    SECRET = 'iEk21fuwZApXlz93750dmW22pw389dPwOk'

    # endpoints
    LOGIN_URI = "/bq/login"
    FRIEND_URI = "/ph/friend"
    BLOB_URI = "/bq/blob"
    UPLOAD_URI = '/ph/upload'
    SEND_URI = '/ph/send'

    # static headers for each and every request
    _headers = {
        'user-agent': 'CFNetwork/609.1.4 Darwin/13.0.0',
        'version': '5.0.0'
    }

    # authenticated.
    authenticated = False

    # AES instance
    _crypto = None

    username = None
    password = None

    # constants
    BLOB = 0x1
    JSON = 0x2

    def __init__(self, username=None, password=None, auth_token=None):
        self.username = username
        self.password = password

        # use auth_token authentication.
        if auth_token:
            self.AUTH_TOKEN = auth_token
            self.authenticated = True

    def login(self):
        '''
        Perform a snapchat login.
        '''

        code, result = self._request(self.LOGIN_URI,
                                     response_type=self.JSON,
                                     username=self.username,
                                     password=self.password)
        logging.info(result)
        if result and result.get('auth_token'):
            # successful login, set the auth token.
            self.AUTH_TOKEN = result['auth_token']

        return result

    def get_blob(self, id):
        '''
        Given a snap id, return the raw decrypted blob content of a
        jpeg image, or mp4 video.
        '''

        code, result = self._request(self.BLOB_URI,
                                     response_type=self.BLOB,
                                     id=id,
                                     username=self.username)

        return result

    def _get_crypto(self):
        '''
        Load up a local instance of the pycrypto cipher library.
        '''

        if self._crypto is None:
            # ECB is required due to a recent change in the Snapchat API
            self._crypto = AES.new(self.ENCRYPTION_KEY, AES.MODE_ECB)

        return self._crypto

    def _decrypt(self, data):
        '''
        Decrypt data.
        '''
        crypto = self._get_crypto()
        return crypto.decrypt(data)

    def _encrypt(self, data):
        '''
        Encrypt data.
        '''
        crypto = self._get_crypto()
        return crypto.encrypt(data)

    def _generate_request_token(self, auth_token, timestamp):
        '''
        Given an auth_token and a timestamp, generate a snapchat request token
        '''

        # salt the authtoken and timestamp
        auth_token = self.SECRET + auth_token
        timestamp = str(timestamp) + self.SECRET

        # hash the newly salted values.
        auth_token_hashed = sha256(auth_token).hexdigest()
        timestamp_hashed = sha256(timestamp).hexdigest()

        # the snapchat req_token is a blend between the hashed+salted
        # auth_token and the hashed+salted timestamp.
        # Random characters are taken from each (using PATTERN) and blended
        # together to form a "hash-like" string
        out = ''
        for i in range(0, len(self.PATTERN)):
            if self.PATTERN[i] == '0':
                out += auth_token_hashed[i]
            else:
                out += timestamp_hashed[i]
        return out

    def _is_blob(self, header):
        '''
        Determine if the passed-in string is actually a snapchat blob
        '''
        is_jpeg = header[0] == chr(00) and header[1] == chr(00)
        is_mp4 = header[0] == chr(0xFF) and header[1] == chr(0xD8)

        if is_jpeg or is_mp4:
            return True
        else:
            # unknown or encrypted blob.
            return False

    def _request(self, url, response_type=None, **params):
        '''
        Perform a snapchat api request.
        '''
        if response_type is None:
            response_type = self.JSON

        auth_token = self.AUTH_TOKEN or self.STATIC_TOKEN
        timestamp = round(time.time() * 1000)

        request_token = self._generate_request_token(auth_token=auth_token,
                                                     timestamp=timestamp)

        # attach additional params
        params['req_token'] = request_token
        params['version'] = self._headers['version']
        params['timestamp'] = timestamp

        # build the url
        url = self.API_HOST + url

        # make the request.
        request = urllib2.urlopen(urllib2.Request(url=url,
                                                  data=urlencode(params),
                                                  headers=self._headers))

        payload = request.read()

        if response_type is self.BLOB:
            # decode blob response.
            if self._is_blob(payload) is False:
                # the blob is encrypted
                payload = self._decrypt(payload)
        elif response_type is self.JSON:
            # json response, decode it.
            payload = json.loads(payload)

        return request.getcode(), payload
