# import requests
# from requests.exceptions import ConnectionError, HTTPError, Timeout
from functools import wraps
from time import time
import logging

import requests
from requests.exceptions import ConnectionError, HTTPError, Timeout
# Ideally, fast, medium, slow would correlate with actually blocks out.
# Fast, really shoot for getting into the next block no matter what.
# Medium should get in within the next couple blocks, 90% certainty.
# Slow, in a few hours, 90% certainty.
# The default should be medium so you can go up/down from there.
DEFAULT_FEE_FAST = 4
DEFAULT_FEE_MEDIUM = 2
DEFAULT_FEE_SLOW = 1

# FIXME: Need to add in a fees API. Issue #1

FEE_SPEED_FAST = 'fast'
FEE_SPEED_MEDIUM = 'medium'
FEE_SPEED_SLOW = 'slow'

# Default fees last updated 2019-04-02
DEFAULT_FEE_FAST = 72
DEFAULT_FEE_HOUR = 62
DEFAULT_CACHE_TIME = 60 * 10
URL = 'https://bitcoinfees.earn.com/api/v1/fees/recommended'


# FIXME: Not sure if this is better, bools are better, or creating its
# own type is better.
def get_fee_bch(speed=FEE_SPEED_MEDIUM):
    """Gets the recommended satoshi per byte fee.

    :param speed: One of: 'fast', 'medium', 'slow'.
    :type speed: ``string``
    :rtype: ``int``
    """
    if speed == FEE_SPEED_FAST:
        return DEFAULT_FEE_FAST
    elif speed == FEE_SPEED_MEDIUM:
        return DEFAULT_FEE_MEDIUM
    elif speed == FEE_SPEED_SLOW:
        return DEFAULT_FEE_SLOW
    else:
        raise ValueError('Invalid speed argument.')


def set_fee_cache_time(seconds):
    global DEFAULT_CACHE_TIME
    DEFAULT_CACHE_TIME = seconds


def get_fee_btc(fast=True):
    """Gets the recommended satoshi per byte fee.
    :param fast: If ``True``, the fee returned will be "The lowest fee (in
                 satoshis per byte) that will currently result in the fastest
                 transaction confirmations (usually 0 to 1 block delay)".
                 Otherwise, the number returned will be "The lowest fee (in
                 satoshis per byte) that will confirm transactions within an
                 hour (with 90% probability)".
    :type fast: ``bool``
    :rtype: ``int``
    """
    return requests.get(URL).json()['fastestFee' if fast else 'hourFee']


def get_fee_local_cache(f):

    cached_fee_fast = None
    cached_fee_hour = None
    fast_last_update = time()
    hour_last_update = time()

    @wraps(f)
    def wrapper(fast=True):
        now = time()

        if fast:
            nonlocal cached_fee_fast
            nonlocal fast_last_update

            if not cached_fee_fast or now - fast_last_update > DEFAULT_CACHE_TIME:
                try:
                    request = requests.get(URL)
                    # If we have a non 2XX status code, raise HTTPError.
                    request.raise_for_status()
                    # Otherwise, try to parse json as normal.
                    cached_fee_fast = request.json()['fastestFee']
                    fast_last_update = now
                except (ConnectionError, HTTPError, Timeout):  # pragma: no cover
                    if cached_fee_fast is None:
                        logging.warning(
                            'Connection to fee API failed, returning default fee (fast) of {}'.format(DEFAULT_FEE_FAST)
                        )
                        return DEFAULT_FEE_FAST
                    else:
                        logging.warning('Connection to fee API failed, returning cached fee (fast).')
                        return cached_fee_fast

            return cached_fee_fast

        else:
            nonlocal cached_fee_hour
            nonlocal hour_last_update

            if not cached_fee_hour or now - hour_last_update > DEFAULT_CACHE_TIME:
                try:
                    request = requests.get(URL)
                    # If we have a non 2XX status code, raise HTTPError.
                    request.raise_for_status()
                    # Otherwise, try to parse json as normal.
                    cached_fee_hour = request.json()['hourFee']
                    hour_last_update = now
                except (ConnectionError, HTTPError, Timeout):  # pragma: no cover
                    if cached_fee_hour is None:
                        logging.warning(
                            'Connection to fee API failed, returning default fee (hour) of {}'.format(DEFAULT_FEE_HOUR)
                        )
                        return DEFAULT_FEE_HOUR
                    else:
                        logging.warning('Connection to fee API failed, returning cached fee (hour).')
                        return cached_fee_hour

            return cached_fee_hour

    return wrapper




@get_fee_local_cache
def get_fee_local_cached(fast):
    pass  # pragma: no cover

def get_fee_cached(fast=True):
    """Gets the recommended satoshi per byte fee. Results are cached using a
    decorator for 10 minutes by default. See :ref:`cache times`.
    :param fast: If ``True``, the fee returned will be "The lowest fee (in
                 satoshis per byte) that will currently result in the fastest
                 transaction confirmations (usually 0 to 1 block delay)".
                 Otherwise, the number returned will be "The lowest fee (in
                 satoshis per byte) that will confirm transactions within an
                 hour (with 90% probability)".
    :type fast: ``bool``
    :rtype: ``int``
    """
    return get_fee_local_cached(fast)


