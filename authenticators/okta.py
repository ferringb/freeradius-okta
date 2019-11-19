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
  radiusd.radlog(level, "Okta Authenticate: {}".format(message.format(*args, **kwargs)))

debug_log = functools.partial(_log, radiusd.L_DBG)
auth_log = functools.partial(_log, radiusd.L_AUTH)
info_log = functools.partial(_log, radiusd.L_INFO)


def authenticate(p):
  debug_log('Authenticate: parameters: {}', p)
  attributes = dict(p)
  username = attributes['User-Name']
  password = attributes['User-Password']

  if not username.endswith('@{}'.format(os.environ['OKTA_DOMAIN'])):
    username = username + '@{}'.format(os.environ['OKTA_DOMAIN'])

  auth_log('Authenticating: {}', username)

  url = 'https://{}/api/v1/authn'.format(os.environ['OKTA_ORG'])
  headers = {'Authorization': 'SSWS {}'.format(os.environ['OKTA_APITOKEN'])}
  payload = {'username': username, 'password': password}
  r = requests.post(url, json=payload, headers=headers)

  result = radiusd.RLM_MODULE_OK if r.status_code == 200 else radiusd.RLM_MODULE_REJECT
  debug_log('Authentication result: status={}, result={}', r.status_code, result)
  return result


def authorize(p):
  debug_log('Authorize: {}', p)
  auth_log('Authorize: {}', dict(p)['User-Name'])
  return radiusd.RLM_MODULE_OK


def post_auth(p):
  debug_log('Post Authentication: parameters: {}', p)
  params = dict(i for i in p)
  user = params['User-Name']

  if params['EAP-Type'] == 'TLS':
    info_log('Post Authentication: user {}: Processing EAP TLS client certificate', user)
    return radiusd.RLM_MODULE_OK

  elif params['EAP-Type'] == 'GTC':
    info_log('Post Authentication: user {}: Processing EAP GTC', user)
    # For dynamic VLAN...
    # if params['User-Name'] == 'ben.hecht':
    #   vlan = '1'
    # return (radiusd.RLM_MODULE_OK,
    #         (
    #           ('Tunnel-Private-Group-Id', vlan),
    #           ('Tunnel-Type', 'VLAN'),
    #           ('Tunnel-Medium-Type', 'IEEE-802'),
    #         ), ())
    return radiusd.RLM_MODULE_OK

  elif params['EAP-Type'] == 'PEAP' or params['EAP-Type'] == 'TTLS':
    info_log('Post Authentication: user {}: Processing EAP {}', user, params['EAP-Type'])
    return radiusd.RLM_MODULE_OK
