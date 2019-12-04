#! /usr/bin/env python2
#
# Okta Authentication
# Ben Hecht <hechtb3@gmail.com>
#

import requests
import radiusd
import functools
import os
import re

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
    prefix = '' if prefix is None else '{}_'.format(prefix)
    def f(key, required=True, default=None):
      key = '{}OKTA_{}'.format(prefix, key)
      try:
        return os.environ[key]
      except KeyError:
        if required:
          raise KeyError("environment variable {} isn't defined, but is mandatory".format(key))
      return default

    return cls(
        default_email_domain=f('DEFAULT_EMAIL_DOMAIN', False),
        org=f('ORG'),
        apitoken=f('APITOKEN'),
        module_name=f('MODULE_NAME', False, __name__),
    )

  def __init__(self, org, apitoken, default_email_domain=None, module_name='okta'):
    self.default_email_domain = default_email_domain
    self.org = org
    self.apitoken = apitoken
    self.module_name = module_name

  def debug_log(self, *args, **kwargs):
    return _log(radiusd.L_DBG, *args, **kwargs)

  def auth_log(self, *args, **kwargs):
    return _log(radiusd.L_AUTH, *args, **kwargs)

  def info_log(self, *args, **kwargs):
    return _log(radiusd.L_INFO, *args, **kwargs)

  def auth_headers(self):
    return {'Authorization': 'SSWS {}'.format(self.apitoken)}

  @capture_error
  def authenticate(self, p):
    attributes = dict(p)
    username = attributes['User-Name']
    password = attributes['User-Password']

    self.auth_log('Authenticating: {}', username)

    url = 'https://{}/api/v1/authn'.format(self.org)
    payload = {'username': username, 'password': password}
    r = requests.post(url, json=payload, headers=self.auth_headers())

    result = radiusd.RLM_MODULE_OK if r.status_code == 200 else radiusd.RLM_MODULE_REJECT
    self.debug_log('Authentication result: status={}, result={}', r.status_code, result)
    return result

  @capture_error
  def authorize(self, p):
    attributes = dict(p)
    username = attributes.get('User-Name')
    if username is not None:
      if re.match('^\w+([\+\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$', username):
        return _radius_response(radiusd.RLM_MODULE_OK, config={'Auth-Type': self.module_name})
      if self.default_email_domain:
        # it's not an email address and we have a default, so enforce ours and claim this auth for ourselves.
        self.debug_log('Authorizing: {} user lacks an email domain, applying the default of {}'.format(username, self.default_email_domain))
        username += '@{}'.format(self.default_email_domain)
        return _radius_response(radiusd.RLM_MODULE_OK, config={'Auth-Type': self.module_name, 'User-Name': username})
      self.debug_log("Authorize: {} we don't know what to do with", username)
      return _radius_response(radiusd.RLM_MODULE_NOOP)
    self.debug_log("Authorize: no user name provided")
    return _radius_response(radiusd.RLM_MODULE_NOOP)

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
