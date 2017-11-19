# /usr/bin/env python
import time, hashlib


class Token(object):
    """Universal Token API for generating and validating access tokens.
    """

    def __init__(self, secret=''):
        self.secret = secret
        self.reset()



    @staticmethod
    def append(a, b):
        a = str(a)
        b = str(b)
        return a + ('' if a == '' else '_') + b



    def export(self, signed=True):
        """ Exports the token to a string
            Only signed token can be exported
            :return string: The token
        """
        token = Token.tokenize_data(self.data)
        token = Token.append(token, Token.timestamp_to_str(self.timestamp))
        if not signed:
            return token

        if self.signature is None:
            raise RuntimeError('Can\'t export unsigned token.')
        token = token + '.' + self.signature

        return token



    @staticmethod
    def gen_signature(data, timestamp, secret=''):
        """ Generates a signature
            :return string: the signature
        """
        token = ''
        token = Token.append(token, Token.tokenize_data(data))
        token = Token.append(token, Token.timestamp_to_str(timestamp))
        return hashlib.sha224(secret+token).hexdigest()



    def get_data(self):
        """ Returns token's data
            :return list: The data list
        """
        return self.data



    def get_data_at_index(self, i):
        """ Reads the token's data
            :param integer index: The index of token's data
            :return string: The data
        """
        data = self.get_data()
        return data[i]



    def parse(self, token):
        """ Parses string token
            :param string token:
        """
        try:
            token = str(token)
        except: raise ValueError('Token contains non-ASCII characters.')

        # Split data and signature
        parts_s = token.split('.')
        if len(parts_s) < 2:
            raise ValueError('Unrecognized token structure.')
        data = '.'.join(parts_s[:-1])
        self.signature = parts_s[-1]

        # Split custom data and timestamp
        parts_d = data.split('_')
        if len(parts_d) < 2:
            raise ValueError('Unrecognized token structure.')
        self.data = parts_d[:-1]
        self.timestamp = float(parts_d[-1])



    def push(self, data):
        """ Adds data to the token
        """
        self.data.append(str(data))



    def reset(self):
        """ Reset Token
        """
        self.data = []
        self.timestamp = None
        self.signature = None



    def sign(self):
        """ Generates and stores token signature
            If timestamp is not stored yet, it gets generated and stored too

        """
        if self.timestamp is None:
            self.set_timestamp()
        self.signature = Token.gen_signature(self.data, self.timestamp, self.secret)


    def set_timestamp(self, timestamp=None):
        """ Timestamp setter
            :param float timestamp: Optional timestamp (default time.time())
        """
        self.timestamp = timestamp if timestamp is not None else time.time()


    @staticmethod
    def timestamp_to_str(timestamp):
        """ Generates a timestamp string
            :param float timestamp:
        """
        return str('{0:.2f}'.format(timestamp))



    @staticmethod
    def tokenize_data(data=None):
        """ Implodes data to a string
            :param list data: the data array
            :return string: token string
        """
        token = ''
        for x in data:
            token = Token.append(token, x)
        return token



    def validate(self, max_age=1800.0):
        """ Validates the token
            :param float max_age: Maximum token age (default: 1800.0 = 30 minutes)
            :throws InvalidTokenException: if age exceeds max_age
            :throws TokenIntegrityException: if signature doesn't match expected value
        """

        # Validity
        if self.timestamp + max_age < time.time():
            raise InvalidTokenException()
        # Integrity
        if self.signature != Token.gen_signature(self.data, self.timestamp, self.secret):
            raise TokenIntegrityException()



# Exceptions

class InvalidTokenException(Exception):
    pass

class TokenIntegrityException(Exception):
    pass
