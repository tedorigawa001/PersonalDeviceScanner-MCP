"""Optional Manager API observations, never a verdict that vulnerability results are fresh."""
import base64
import json
import os
import re
import ssl
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler

from .core import ScannerError, NoRedirect, TrackedHTTPSHandler, fetch_bounded, check_cancel

KEYS = {'enabled', 'manager_url', 'ca_file', 'max_keepalive_age_seconds', 'max_os_record_age_seconds'}
STATES = {'recent', 'aged', 'unknown'}


def configure(scanner):
    settings = scanner.wazuh.get('freshness', {})
    if not isinstance(settings, dict):
        raise ScannerError('wazuh.freshness must be a table')
    scanner.freshness_settings = settings
    enabled = settings.get('enabled', False)
    if type(enabled) is not bool:
        raise ScannerError('wazuh.freshness.enabled must be a boolean')
    for key in settings:
        if key not in KEYS:
            scanner.config_warnings.append('Unknown setting wazuh.freshness.' + str(key)[:80] + ' is ignored' +
                ('; remove credentials from the file; use PC_SCANNER_WAZUH_MANAGER_USER and PC_SCANNER_WAZUH_MANAGER_PASSWORD'
                 if key in {'user', 'username', 'password', 'token'} else ''))
    for key, default in [('max_keepalive_age_seconds', 300), ('max_os_record_age_seconds', 7200)]:
        value = settings.get(key, default)
        if type(value) is not int or not 1 <= value <= 604800:
            raise ScannerError('Invalid wazuh.freshness time threshold (1..604800 seconds)')
    origin = settings.get('manager_url', '')
    ca = settings.get('ca_file', '')
    if not isinstance(origin, str) or not isinstance(ca, str):
        raise ScannerError('Manager URL and CA file must be strings')
    if ca and not Path(ca).is_absolute():
        raise ScannerError('Manager ca_file must be absolute')
    if origin or enabled:
        try:
            url = urlsplit(origin)
            valid = (url.scheme == 'https' and url.hostname and url.username is None and url.password is None
                     and not url.path and not url.query and not url.fragment and url.port != 0
                     and not re.search(r'[\x00-\x20\x7f\\?#]', origin))
        except ValueError:
            valid = False
        if not valid:
            raise ScannerError('Manager URL must be an HTTPS origin without a path or credentials')


def timestamp(value):
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        when = datetime.fromisoformat(value)
        return when.astimezone(timezone.utc) if when.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def observation(value, now, seconds):
    when = timestamp(value)
    if when is None:
        return {'state': 'unknown', 'at': None}, False
    age = now - when
    future = age < timedelta(0)
    state = ('unknown' if age < -timedelta(seconds=60) else
             'aged' if age > timedelta(seconds=seconds) else 'recent')
    return {'state': state, 'at': when.isoformat(timespec='microseconds')}, future


def project(value):
    """Only fixed states and normalized times may be retained in summary history."""
    if not isinstance(value, dict) or value.get('source') != 'wazuh_manager_api':
        return None
    when = timestamp(value.get('checked_at'))
    if when is None:
        return None
    kept = {'source': 'wazuh_manager_api', 'checked_at': when.isoformat(timespec='microseconds'),
            'assessment': 'vulnerability_freshness_unverified'}
    observed = timestamp(value.get('index_observed_at'))
    if observed is not None:
        kept['index_observed_at'] = observed.isoformat(timespec='microseconds')
    for key, field in [('agent_connection', 'last_keepalive_at'), ('os_record', 'recorded_at')]:
        item = value.get(key)
        if not isinstance(item, dict) or not isinstance(item.get('state'), str) or item['state'] not in STATES:
            return None
        at = timestamp(item.get(field))
        kept[key] = {'state': item['state'], field: at.isoformat(timespec='microseconds') if at else None}
        if at is None and item['state'] != 'unknown':
            return None
    return kept


class Unavailable(Exception):
    pass


def add(scanner, report, overall_deadline, cancel=None):
    """Retain indexed findings on every supplementary failure, including cancellation."""
    if not scanner.freshness_settings.get('enabled', False):
        return
    now = datetime.now(timezone.utc)
    evidence = {'source': 'wazuh_manager_api', 'checked_at': now.isoformat(timespec='microseconds'),
                'agent_connection': {'state': 'unknown', 'last_keepalive_at': None},
                'os_record': {'state': 'unknown', 'recorded_at': None},
                'assessment': 'vulnerability_freshness_unverified'}
    indexed = timestamp(report.get('observed_at'))
    if indexed is not None:
        evidence['index_observed_at'] = indexed.isoformat(timespec='microseconds')
    settings = scanner.freshness_settings
    deadline = min(overall_deadline, time.monotonic() + 5)
    warnings = []
    try:
        check_cancel(cancel)
        if deadline <= time.monotonic():
            raise Unavailable('time budget exhausted')
        user, password = (os.environ.get('PC_SCANNER_WAZUH_MANAGER_' + key, '') for key in ('USER', 'PASSWORD'))
        if not user or not password or ':' in user:
            raise Unavailable('Manager credentials unavailable')
        context = ssl.create_default_context(cafile=settings.get('ca_file') or None)
        handler = TrackedHTTPSHandler(context)
        opener = build_opener(ProxyHandler({}), handler, NoRedirect('Wazuh Manager'))
        origin = settings['manager_url']

        def request(path, *, auth, method='GET', limit=262144):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Unavailable('time budget exhausted')
            raw = fetch_bounded(opener, handler, Request(origin + path, method=method,
                                headers={'Authorization': auth}), remaining, min(scanner.limit, limit),
                                cancel, service='Wazuh Manager')
            return raw

        basic = base64.b64encode((user + ':' + password).encode()).decode()
        token = request('/security/user/authenticate?raw=true', auth='Basic ' + basic,
                        method='POST', limit=16384).decode('ascii')
        if not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token):
            raise Unavailable('invalid authentication response')

        def item(path):
            payload = json.loads(request(path, auth='Bearer ' + token))
            data = payload['data']
            items = data['affected_items']
            if (type(payload.get('error')) is not int or payload['error'] != 0
                    or type(data.get('total_failed_items')) is not int or data['total_failed_items'] != 0
                    or data.get('failed_items') != [] or type(data.get('total_affected_items')) is not int
                    or data['total_affected_items'] != 1 or not isinstance(items, list) or len(items) != 1
                    or not isinstance(items[0], dict)):
                raise Unavailable('incomplete Manager response')
            return items[0]

        agent = item('/agents?agents_list=' + scanner.agent_id + '&select=id,name,status,lastKeepAlive&limit=1')
        if agent.get('id') != scanner.agent_id:
            raise Unavailable('Manager target mismatch')
        name = agent.get('name')
        if not isinstance(name, str) or not name.strip() or scanner.device_identity({name})[0] != 'matched':
            raise Unavailable('Manager target mismatch')
        indexed_names = report['data']['device']['agent_names']
        if indexed_names and any(n.casefold() != name.casefold() for n in indexed_names):
            raise Unavailable('Manager target mismatch')
        os_record = item('/syscollector/' + scanner.agent_id + '/os?select=scan.id,scan.time')
        if os_record.get('agent_id') != scanner.agent_id:
            raise Unavailable('Manager target mismatch')
        # Evaluate all observations against one time after receiving both responses.
        now = datetime.now(timezone.utc)
        evidence['checked_at'] = now.isoformat(timespec='microseconds')
        connection, future1 = observation(agent.get('lastKeepAlive'), now,
                                          settings.get('max_keepalive_age_seconds', 300))
        status = agent.get('status')
        if status in {'disconnected', 'never_connected', 'pending'}:
            connection['state'] = 'aged' if connection['state'] != 'unknown' else 'unknown'
        elif status != 'active':
            connection['state'] = 'unknown'
        os_info = os_record.get('scan')
        record, future2 = observation(os_info.get('time') if isinstance(os_info, dict) else None, now,
                                     settings.get('max_os_record_age_seconds', 7200))
        evidence['agent_connection'] = {'state': connection['state'], 'last_keepalive_at': connection['at']}
        evidence['os_record'] = {'state': record['state'], 'recorded_at': record['at']}
        if future1 or future2:
            warnings.append('Manager timestamps are in the future; clock skew may affect these observations')
        if record['state'] == 'aged':
            warnings.append('The OS record timestamp is old; this does not prove collection has stopped')
    except Unavailable as exc:
        warnings.append('Wazuh freshness evidence unavailable (' + str(exc) + ')')
    except Exception as exc:
        # Exceptions and remote error bodies can quote URLs, passwords or tokens: never return them.
        close = getattr(exc, 'close', None)
        if close:
            close()
        warnings.append('Wazuh freshness evidence unavailable (' +
                        ('cancelled' if cancel is not None and cancel.is_set() else 'request or response failed') + ')')
    report['data']['freshness_evidence'] = evidence
    if any(evidence[key]['state'] != 'recent' for key in ('agent_connection', 'os_record')):
        if report['status'] == 'completed':
            report['status'] = 'partial'
        warnings.append('Connection or OS record observations are old or unverified; vulnerability freshness remains unverified')
    report['warnings'] += warnings
