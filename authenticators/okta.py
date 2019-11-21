#! /usr/bin/env python2
#
# Okta Authentication
# Ben Hecht <hechtb3@gmail.com>
#

import requests
import radiusd
import functools
import os

def _log(level, message, *args, **kwargs):
  if args or kwargs:
    message = message.format(*args, **kwargs)
  radiusd.radlog(level, "Okta Backend: {}".format(message))

def capture_error(func):
  def f(*args, **kwargs):
    _log(radiusd.L_DBG, "invoking {}: args={!r}, kwargs={!r}".format(func.__name__, args, kwargs))
    try:
      ret = func(*args, **kwargs)
      _log(radiusd.L_DBG, "invoking {}: result={}".format(func.__name__, ret))
      return ret
    except Exception as e:
      _log(radiusd.L_ERR, "{} threw an exception: {}".format(func.__name__, e))
      raise
  f.__name__ = func.__name__
  return f


class OktaAuthenticator:
  """
  Freeradius okta authenticator.
  """

  @classmethod
  @capture_error
  def from_env(cls, prefix=None):
    """Create an authenticator from environment variables

    :param env_prefix: If given, look for ${PREFIX}_OKTA.* variables.  If not given, just look for OKTA_.*
    """
    def f(key, prefix='{}_'.format(prefix) if prefix is not None else ''):
      key = '{}OKTA_{}'.format(prefix, key)
      try:
        return os.environ[key]
      except KeyError:
        raise KeyError("environment variable {} isn't defined, but is mandatory".format(key))
    return cls(domain=f('DOMAIN'), org=f('ORG'), apitoken=f('APITOKEN'))

  def __init__(self, domain, org, apitoken):
    self.domain = domain
    self.org = org
    self.apitoken = apitoken

  def debug_log(self, *args, **kwargs):
    return _log(radiusd.L_DBG, *args, **kwargs)

  def auth_log(self, *args, **kwargs):
    return _log(radiusd.L_AUTH, *args, **kwargs)

  def info_log(self, *args, **kwargs):
    return _log(radiusd.L_INFO, *args, **kwargs)

  @capture_error
  def authenticate(self, p):
    attributes = dict(p)
    username = attributes['User-Name']
    password = attributes['User-Password']

    if not username.endswith('@{}'.format(self.domain)):
      username = username + '@{}'.format(self.domain)

    self.auth_log('Authenticating: {}', username)

    url = 'https://{}/api/v1/authn'.format(self.org)
    headers = {'Authorization': 'SSWS {}'.format(self.apitoken)}
    payload = {'username': username, 'password': password}
    r = requests.post(url, json=payload, headers=headers)

    result = radiusd.RLM_MODULE_OK if r.status_code == 200 else radiusd.RLM_MODULE_REJECT
    self.debug_log('Authentication result: status={}, result={}', r.status_code, result)
    return result

  @capture_error
  def authorize(self, p):
    self.auth_log('Authorize: {}', dict(p)['User-Name'])
    return radiusd.RLM_MODULE_OK

  @capture_error
  def post_auth(self, p):
    if hasattr(self, 'post_auth_hook'):
      self.debug_log("has post_auth_hook: deferring to it")
      return capture_error(self.post_auth_hook)(p)
    return radiusd.RLM_MODULE_OK


# compatibility shims for people directly using this module.
def authenticate(p):
  return OktaAuthenticator.from_env().authenticate(p)

def authorize(p):
  return OktaAuthenticator.from_env().authorize(p)

def post_auth(p):
  return OktaAuthenticator.from_env().post_auth(p)
