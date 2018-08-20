# /usr/bin/env python
import datetime, hashlib, uuid


class TimeToken(object):

	def __init__(self, value=None, secret=None):
		self._secret     = secret
		self._datetime  = None
		self._uuid       = None
		self._signature  = None

		if secret is None:
			raise ValueError("Secret string not given.")

		if value is not None:
			self.parse(value)
		else:
			self.init()


	def __str__(self):
		return self.to_string()


	def init(self):
		self._uuid = uuid.uuid4()
		self._datetime = datetime.datetime.utcnow()
		self._signature = self.gen_signature()


	def to_string(self):
		""" Converts self to a string """

		ret = ""
		ret += str(self._dt_to_epoch_millis(self._datetime))
		ret += "_"+self._uuid.hex
		ret += "_"+self._signature
		return ret


	def parse(self, value):
		""" Parses a token
			:param string value: Maximum token age in seconds (default: -1 ... token age will not be evaluated)
			:param bool raises: Whether or not to raise an excetpion on parse error (otherwise boolean is returned)
			:throws ParseTokenException: if value can't be parsed
		"""
		try:
			parts = str(value).split("_")
			self._datetime = self._epoch_millis_to_dt(int(parts[0]))
			self._uuid = uuid.UUID(hex=parts[1])
			self._signature = parts[2]
		except (IndexError, ValueError, TypeError) as e:
			raise ParseTokenException("Invalid token format.")


	def validate(self, max_seconds=-1, raises=False):
		""" Validates the token
			:param float max_seconds: Maximum token age in seconds (default: -1 ... token age will not be evaluated)
			:param bool raises: Whether or not to raise an excetpion on validation error (otherwise boolean is returned)
			:throws InvalidTokenException: if age in seconds exceeds max_seconds
			:throws TokenIntegrityException: if signature doesn't match expected value
		"""

		# Time Validity
		now = datetime.datetime.utcnow()
		if max_seconds != -1 and (now - self._datetime).total_seconds() > max_seconds:
			if raises:
				raise TokenExpiredException()
			else: return False

		# Integrity
		if self._signature != self.gen_signature():
			if raises:
				raise InvalidSignatureException()
			else: return False

		return True


	def gen_signature(self):
		""" Generates a signature
			:return string: the signature
		"""
		return hashlib.sha224((self._uuid.hex+self._secret+str(self._dt_to_epoch_millis(self._datetime))).encode()).hexdigest()



	def _dt_to_epoch_millis(self, datetime_obj):
		return round((datetime_obj-datetime.datetime(1970, 1, 1)).total_seconds()*1000)


	def _epoch_millis_to_dt(self, millis):
		return datetime.datetime.utcfromtimestamp(millis/1000)



# Exceptions

class TokenException(Exception):
	pass

class TokenExpiredException(TokenException):
	pass

class InvalidSignatureException(TokenException):
	pass

class ParseTokenException(TokenException):
	pass


if __name__ == '__main__':
	import unittest, time
	TestCase = unittest.TestCase()
	valid_token = TimeToken(secret="SECRET")

	# Test parser
	with unittest.TestCase().assertRaises(ParseTokenException):
		1<2
		TimeToken("1234321_00000000_11111111", secret="TERCES")
	print("parser test 1 - ok")
	with unittest.TestCase().assertRaises(ParseTokenException):
		TimeToken("1234321_0000000011111111", secret="TERCES")
	print("parser test 2 - ok")

	# Test time validity check
	assert valid_token.validate() == True
	print("validity check test 1 - ok")

	with unittest.TestCase().assertRaises(InvalidSignatureException):
		invalid_token = TimeToken(valid_token, secret="TERCES")
		invalid_token.validate(raises=True)
	print("validity check test 2 - ok")

	with unittest.TestCase().assertRaises(TokenExpiredException):
		print("Waiting for token to expire...")
		time.sleep(2)
		valid_token.validate(max_seconds=1, raises=True)
	print("validity check test 3 - ok")
