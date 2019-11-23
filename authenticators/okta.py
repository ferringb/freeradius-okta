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


def _radius_response(value, reply=(), config=()):
  """helper function for creating a properly formatted rlm_python response"""
  if isinstance(reply, dict):
    reply = reply.iteritems()
  reply = tuple((str(k), str(v)) for k,v in reply)
  if isinstance(config, dict):
    config = config.iteritems()
  config = tuple((str(k), str(v)) for k,v in config)
  return (value, reply, config)


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
        user_id_attr=f('USER_ID_ATTR', False, None),
    )

  def __init__(self, org, apitoken, default_email_domain=None, module_name='okta',
               user_id_attr=None):
    self.default_email_domain = default_email_domain
    self.org = org
    self.apitoken = apitoken
    self.module_name = module_name
    self.user_id_attr = user_id_attr

  def debug_log(self, *args, **kwargs):
    return _log(radiusd.L_DBG, *args, **kwargs)

  def auth_log(self, *args, **kwargs):
    return _log(radiusd.L_AUTH, *args, **kwargs)

  def info_log(self, *args, **kwargs):
    return _log(radiusd.L_INFO, *args, **kwargs)

  @property
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
    r = requests.post(url, json=payload, headers=self.auth_headers)

    self.debug_log('Authentication result: status={}', r.status_code)
    data = r.json()
    if r.status_code == 200:
      # if we can save the user-id in attr, do so- that saves an API roundtrip if they're doing MFA.
      if self.user_id_attr:
        return _radius_response(radiusd.RLM_MODULE_OK, config={self.user_id_attr: data['_embedded']['user']['id']})
      return _radius_response(radiusd.RLM_MODULE_OK)
    return _radius_response(radiusd.RLM_MODULE_REJECT)

  @capture_error
  def authenticate_mfa(self, p):
    attributes = dict(p)
    username = attributes['User-Name']
    password = attributes['User-Password']
    user_id = attributes.get(self.user_id_attr)

    if user_id is None:
      self.debug_log("MFA Authentication: querying user id for user {}.  Consider enabling OKTA_USER_ID_ATTR to optimize this away", username)
      response = requests.get('https://{}/api/v1/users/{}'.format(self.org, username), headers=self.auth_headers)
      if response.status_code != 200:
        self.auth_log("MFA Authentication: user {} is unknown to okta", username)
      user_id = response.json()['id']
      self.debug_log("MFA Authentication: user {} is user-id {}", username, user_id)

    # get the factors allowed.
    response = requests.get('https://{}/api/v1/users/{}/factors'.format(self.org, user_id), headers=self.auth_headers)
    # this is a list of factors
    if response.status_code == 404:
      self.info_log("MFA Authentication: user {} not found", username)
      return (radiusd.RLM_MODULE_REJECT, (('Reply-Message', 'user not found'),),)
    elif response.status_code != 200:
      self.warn_log("MFA Authentication: unexpected status code: {}, user-id {}", response.status_code, username)
    factors = response.json()
    self.debug_log("MFA Authentication: {} factors usable", len(factors))
    for factor in factors:
      self.debug_log("MFA Authentication: trying factor {!r}", factor)
      if not factor['status'] == 'ACTIVE':
        self.debug_log("ignoring factorId {} since it's inactive", factor['id'])
        continue
      elif factor['factorType'] not in ("token:software:totp", "token:hardware"):
        self.debug_log("ignoring factorId {} since it's not token based", factor['id'])
        continue
      r = requests.post(factor['_links']['verify']['href'], headers=self.auth_headers, json=dict(passCode=password))
      if r.status_code == 200:
        # body is: {"factorResult": "SUCCESS"}
        self.info_log("MFA Authentication: validated {} token type {}", username, factor['factorType'])
        return radiusd.RLM_MODULE_OK
      else:
        self.debug_log("MFA Authentication: factor auth failed: {!r}", r.json())
        self.auth_log("MFA Authentication: user {}, factor type {} failed auth; may be innocuous", username, factor["factorType"])
        # status 403
        # this can be: errorCode E0000082 (errorSummary holds details to log)
        # this occurs when the passcode was reused and they need to try again in a bit.
        #
        # also can be:
        # status 403:
        # errorCode E0000068; errorSummary: "Invalid Passcode/Answer".  Can also use errorCauses:
        #     "errorCauses": [
        # {
        #    "errorSummary": "Your passcode doesn't match our records. Please try again."
        # }
        # finally, can also log errorId for traceability (should in general)
    self.debug_log("MFA Authentication: user {} exhausted all factor options", username)
    return _radius_response(radiusd.RLM_MODULE_REJECT, {'Reply-Message':'no factor could be verified'})

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

def authenticate_mfa(p):
  return OktaAuthenticator.from_env().authenticate_mfa(p)

def authorize(p):
  return OktaAuthenticator.from_env().authorize(p)

def post_auth(p):
  return OktaAuthenticator.from_env().post_auth(p)
