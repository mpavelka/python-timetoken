TimeToken (Python 3)
===

TimeToken for **Python 3.x** provides a simple API for creating and validating signed and time limited tokens.

## Install with pip

```
pip install -e git+https://github.com/mpavelka/python-timetoken#egg=timetoken
```

## Usage

To create a time token you need to provide a secret string. It will be used to sign the token:

```
from timetoken import TimeToken
token = TimeToken(secret="[SECRET_STRING]")
```

Parse previously created token `_token` (it can be an instance of TimeToken or a string):

```
> _token = TimeToken(secret="[SECRET_STRING]").to_string()
> token = TimeToken(_token, secret="[SECRET_STRING]")
> token.validate()
True
```

Validate token signature:

```
> _token = TimeToken(secret="[SECRET_STRING]").to_string()
> token = TimeToken(_token, secret="[DIFFERENT_SECRET_STRING]")
> token.validate()
False
```

Validate that token is not older than `max_seconds` and that signature is valid:

```
> _token = TimeToken(secret="[SECRET_STRING]").to_string()
> token = TimeToken(_token, secret="[SECRET_STRING]")
> time.sleep(2)
> token.validate(max_seconds=1)
False
```

## Exceptions

Generic TimeToken exception:

```
TimeTokenException
```

Exception raised when `validate(max_seconds=5)` fails due to token expiry: 

```
TimeTokenExpired
```

Exception raised when `validate()` fails due to invalid token signature:

```
InvalidTimeTokenSignature
```

Exception raised when initial value can't be parsed:

```
TimeTokenParseError
```