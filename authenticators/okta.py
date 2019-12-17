#! /usr/bin/env python2
#
# Okta Authentication
# Ben Hecht <hechtb3@gmail.com>
# Brian Harring <ferringb@gmail.com>
#

import requests
import functools
import os
import re

# if OKTA_DEVELOPMENT_MODE is in the env, then we're being invoked outside of
# freeradius- provide compatibility mock's to make development simpler.
if os.environ.get("OKTA_DEVELOPMENT_MODE"):
  class RadiusdMock:

    def __getattr__(self, key):
      return key

    @staticmethod
    def radlog(level, message):
      print("radlog({!r}, {!r})".format(level, message))

  radiusd = RadiusdMock()
else:
  import radiusd


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
  def from_env(cls, prefix=None, **kwargs):
    """Create an authenticator from environment variables

    :param env_prefix: If given, look for ${PREFIX}_OKTA.* variables.  If not given, just look for OKTA_.*
    """
    prefix = '' if prefix is None else '{}_'.format(prefix)
    def f(key, required=True, default=None, overrides=kwargs):
      if key.lower() in overrides:
        return overrides[key.lower()]
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
        auth_type=f('AUTH_TYPE', False, 'okta'),
        user_id_attr=f('USER_ID_ATTR', False, None),
    )

  def __init__(self, org, apitoken, default_email_domain=None, auth_type='okta',
               user_id_attr=None):
    self.default_email_domain = default_email_domain
    self.org = org
    self.apitoken = apitoken
    self.auth_type = auth_type
    self.user_id_attr = user_id_attr

  @staticmethod
  def radius_response(value, reply=(), config=()):
    """helper function for creating a properly formatted rlm_python response"""
    if isinstance(reply, dict):
      reply = reply.iteritems()
    reply = tuple((str(k), str(v)) for k,v in reply)
    if isinstance(config, dict):
      config = config.iteritems()
    config = tuple((str(k), str(v)) for k,v in config)
    return (value, reply, config)

  def debug_log(self, *args, **kwargs):
    return _log(radiusd.L_DBG, *args, **kwargs)

  def auth_log(self, *args, **kwargs):
    return _log(radiusd.L_AUTH, *args, **kwargs)

  def info_log(self, *args, **kwargs):
    return _log(radiusd.L_INFO, *args, **kwargs)

  def warn_log(self, *args, **kwargs):
    return _log(radiusd.L_WARN, *args, **kwargs)

  def okta_request(self, method_type, uri, *args, **kwargs):
    headers = kwargs['headers'] = kwargs.get('headers', {}).copy()
    headers.update(self.auth_headers)
    func = getattr(requests, method_type.lower())
    return func('https://{}/{}'.format(self.org, uri.lstrip('/')), *args, **kwargs)

  @property
  def auth_headers(self):
    return {'Authorization': 'SSWS {}'.format(self.apitoken)}

  def authenticate(self, p):
    attributes = dict(p)
    username = attributes['User-Name']
    password = attributes['User-Password']

    self.auth_log('Authenticating: {}', username)

    payload = {'username': username, 'password': password}
    r = self.okta_request('post', '/api/v1/authn', json=dict(username=username, password=password))

    self.debug_log('Authentication result: status={}', r.status_code)
    data = r.json()
    if r.status_code == 200:
      # if we can save the user-id in attr, do so- that saves an API roundtrip if they're doing MFA.
      if self.user_id_attr:
        return self.radius_response(radiusd.RLM_MODULE_OK, config={self.user_id_attr: data['_embedded']['user']['id']})
      return self.radius_response(radiusd.RLM_MODULE_OK)
    self.warn_log("Authenticate: got {} status code received for user {}", r.status_code, username)
    return self.radius_response(radiusd.RLM_MODULE_REJECT)

  def fetch_user_id(self, username):
    self.debug_log("querying user id for user {}.  Consider enabling OKTA_USER_ID_ATTR to optimize this away", username)
    response = self.okta_request('get', '/api/v1/users/{}'.format(username))
    if response.status_code != 200:
      # log the actual error via non debug at some point.
      self.debug_log("non 200 status code: {!r}", response.json())
      self.auth_log("user {} is unknown to okta", username)
      return None

    user_id = response.json()['id']
    self.debug_log("user {} is user-id {}", username, user_id)
    return user_id

  def authenticate_mfa(self, p):
    attributes = dict(p)
    username = attributes['User-Name']
    password = attributes['User-Password']
    user_id = attributes.get(self.user_id_attr)

    if user_id is None:
      user_id = self.fetch_user_id(username)
      if user_id is None:
        self.auth_log("MFA Authentication: user {} is unknown to okta", username)
        return self.radius_response(radiusd.RLM_MODULE_REJECT)

    # get the factors allowed.
    response = self.okta_request('get', '/api/v1/users/{}/factors'.format(user_id))
    # this is a list of factors
    if response.status_code == 404:
      self.info_log("MFA Authentication: user {} not found", username)
      return self.radius_response(radiusd.RLM_MODULE_REJECT, {'Reply-Message': 'user not found'})

    elif response.status_code != 200:
      self.warn_log("MFA Authentication: unexpected status code: {}, user-id {}", response.status_code, username)
      return self.radius_response(radiusd.RLM_MODULE_REJECT)

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
        data = r.json()
        if data['factorResult'] != 'SUCCESS':
          self.auth_log("MFA Authentication: token type {} accepted for {}, but issued factorResult {}; this is unusable", factor['factorType'], username, data['factorResult'])
          continue
        self.info_log("MFA Authentication: validated {} token type {}", username, factor['factorType'])
        return radiusd.RLM_MODULE_OK
      else:
        data = r.json()
        self.debug_log("MFA Authentication: factor auth failed: {!r}", data)
        if data['errorCode'] == 'E0000082':
          self.auth_log(
              "MFA Authentication: user {}'s token was used too recently: {}",
              username, data['errorSummary'])
          return self.radius_response(radiusd.RLM_MODULE_REJECT, {'Reply-Message': data['errorSummary']})
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
    return self.radius_response(radiusd.RLM_MODULE_REJECT, {'Reply-Message':'no factor could be verified'})

  def authorize(self, p):
    attributes = dict(p)
    username = attributes.get('User-Name')
    if not attributes.get('User-Password'):
      self.debug_log("Authorize: {!r} provided no password", username)
      return self.radius_response(radiusd.RLM_MODULE_NOOP)
    if username is not None:
      if re.match('^\w+([\+\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$', username):
        return self.radius_response(radiusd.RLM_MODULE_OK, config={'Auth-Type': self.auth_type})
      if self.default_email_domain:
        # it's not an email address and we have a default, so enforce ours and claim this auth for ourselves.
        self.debug_log('Authorizing: {} user lacks an email domain, applying the default of {}'.format(username, self.default_email_domain))
        username += '@{}'.format(self.default_email_domain)
        return self.radius_response(radiusd.RLM_MODULE_OK, config={'Auth-Type': self.auth_type, 'User-Name': username})
      self.debug_log("Authorize: {} we don't know what to do with", username)
      return self.radius_response(radiusd.RLM_MODULE_NOOP)
    self.debug_log("Authorize: no user name provided")
    return self.radius_response(radiusd.RLM_MODULE_NOOP)


# This is the known hooks that Rlm_python can invoke; this list should be kept in sync
# with https://github.com/FreeRADIUS/freeradius-server/blob/master/src/modules/rlm_python/rlm_python.c
KNOWN_HOOKS = frozenset([
    'authorize', 'authenticate', 'instantiate', 'preacct', 'accounting',
    'pre_proxy', 'post_proxy', 'post_auth', 'recv_coa', 'send_coa', 'detach'
])

def inject_hooks(variable_scope, object, force=()):
  """Mutate the given variable scope, adding shims so that rlm_python can invoke it.

  Said another way, if the object (or module) passed in has an 'authenticate'- then add
  a redirect in variable_scope that invokes this.
  """
  for hook in KNOWN_HOOKS.intersection(dir(object)).union(force):
    variable_scope[hook] = capture_error(getattr(object, hook))


def inject_hooks_lazy(variable_scope, invokable, hooks, force=()):
  """Mutate the given variable scope, adding shims so that rlm_python can invoke it.

  This is akin to inject_hooks, but allows lazy instantiation of the object.  This
  is primarily useful for the raw okta module- we need to delay env parsing until
  invocation since the end user may not be using env variables (they may just be using
  a mod-config instantiation directly).
  """
  for hook in KNOWN_HOOKS.intersection(hooks).union(force):
    def shim(p, hook=hook):
      return getattr(invokable(), hook)(p)
    shim.__name__ = hook
    variable_scope[hook] = capture_error(shim)


# compatibility shims for people directly using this module directly.
inject_hooks_lazy(
    locals(),
    OktaAuthenticator.from_env,
    KNOWN_HOOKS.intersection(dir(OktaAuthenticator)),
    force=['authenticate_mfa'],
)
