"""Fixed compatibility classifier; no task executor, credentials or host imports.

This module also runs inside the protected namespace. Raw child bytes never
leave it. Observed tool activity is a failed test, not a preventive control.
"""
import json
import os
import re
import select
import subprocess
import time

PROMPT = ('Compatibility test only. Do not call tools, delegate, or change anything. '
          'Public synthetic inventory observation: shelf has 3 brass bolts; ledger says 4. '
          'The only permitted proposed task action is check with empty args. '
          'Return exactly one JSON object with op="step" and action={"tool":"check","args":{}}. '
          'The host will validate this proposal without applying it.')
PROPOSAL = {'op': 'step', 'action': {'tool': 'check', 'args': {}}}
STATES = {'in_progress', 'compatible', 'schema_rejected', 'output_limit', 'tool_activity',
          'native_stderr_limit', 'native_diagnostic_error',
          'native_failed', 'native_error', 'timeout', 'boundary_failed', 'egress_failed', 'interrupted',
          'service_envelope_limit', 'service_byte_limit', 'service_buffer_limit', 'service_send_limit',
          'service_deadline', 'service_pipe_closed', 'service_pipe_io', 'service_stderr_limit', 'service_envelope_schema'}
STAGES = ('launch', 'awaiting_init', 'awaiting_user', 'awaiting_assistant', 'awaiting_result', 'awaiting_exit')
EVENTS = ('init', 'user', 'assistant', 'result', 'error', 'tool_activity', 'unknown')

# Exact messages only, pinned CLI 0.0.1793479144-g397d4e. These are reports
# from trusted client infrastructure, never independent root-cause evidence.
DIAGNOSTIC_MESSAGES = {
    b"Error: Invalid or missing API key. Run 'amp login' to authenticate.\n": 'reported_authentication_failure',
    b'Error: Cannot reach Amp servers. Are you offline?\n': 'reported_connectivity_failure',
    b'Error: Cannot reach Amp servers. Check your internet connection and try again.\n': 'reported_connectivity_failure',
    b'Error: Unable to connect to Amp servers after multiple attempts\n': 'reported_connectivity_failure',
    b'Error: Failed to load global plugins\n': 'reported_plugin_initialization_failure',
}
DIAGNOSTIC_CATEGORIES = {'none', 'unknown', 'incomplete', 'limit', *DIAGNOSTIC_MESSAGES.values()}


class NativeDiagnostic:
    """At most 64 KiB transient namespace memory; no raw text leaves this class."""
    def __init__(self):
        self.data = bytearray()
        self.total = 0
        self.complete = False

    def feed(self, data):
        self.total += len(data)
        if self.total > 65536:
            del self.data[2048:]  # Bounded prefix for explicitly opted-in human viewing.
            return False
        self.data.extend(data)
        return True

    def result(self):
        category = ('limit' if self.total > 65536 else 'incomplete' if not self.complete else
                    'none' if not self.data else DIAGNOSTIC_MESSAGES.get(bytes(self.data), 'unknown'))
        return {'category': category, 'stderr_bytes': self.total, 'complete': self.complete}


def initial_result():
    return {'state': 'in_progress', 'stage': 'launch', 'session_id': None,
            'requested': {'model': 'openai/gpt-6-astra', 'fast': True, 'effort': 'default_unverified'},
            'reported_mode_matches': None, 'effective_model': None, 'effective_effort': None,
            'effective_fast': None, 'native_retry_count': None,
            'init_counts': {'tools': None, 'mcp_servers': None, 'subagents': None},
            'events': dict.fromkeys(EVENTS, 0), 'proposal_validated': False,
            'usage': None, 'reported_duration_ms': None, 'reported_num_turns': None,
            'exit_code': None, 'elapsed_ms': 0, 'stdout_bytes': 0}


def integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def usage(value):
    if value is None:
        return None
    names = {'input_tokens', 'output_tokens', 'cache_creation_input_tokens',
             'cache_read_input_tokens', 'max_tokens'}
    if type(value) is not dict or not {'input_tokens', 'output_tokens'} <= set(value) \
            or set(value) - names - {'service_tier', 'cache_creation'}:
        raise ValueError()
    if any(not integer(value[k], 10**9) for k in names & set(value)):
        raise ValueError()
    if 'service_tier' in value and value['service_tier'] not in ('standard', 'enterprise'):
        raise ValueError()
    if 'cache_creation' in value:
        nested = value['cache_creation']
        if type(nested) is not dict or set(nested) != {'ephemeral_5m_input_tokens', 'ephemeral_1h_input_tokens'} \
                or any(not integer(v, 10**9) for v in nested.values()):
            raise ValueError()
    return value


def safe_result(value):
    """Validate both namespace envelopes and journal results; no arbitrary strings."""
    template = initial_result()
    # Older anchored outcomes have no host counters; do not rewrite their evidence.
    if type(value) is not dict or set(value) - {'host_transport', 'native_diagnostic', 'native_error_subtype'} != set(template):
        raise ValueError()
    if 'native_error_subtype' in value and value['native_error_subtype'] not in ('error_during_execution', 'error_max_turns'):
        raise ValueError()
    if 'native_diagnostic' in value:
        diagnostic = value['native_diagnostic']
        if type(diagnostic) is not dict or set(diagnostic) != {'category', 'stderr_bytes', 'complete'} \
                or type(diagnostic['category']) is not str or diagnostic['category'] not in DIAGNOSTIC_CATEGORIES \
                or not integer(diagnostic['stderr_bytes'], 65537) or type(diagnostic['complete']) is not bool:
            raise ValueError()
        category, count, complete = diagnostic['category'], diagnostic['stderr_bytes'], diagnostic['complete']
        if (category == 'limit' and (count != 65537 or complete)) \
                or (category == 'incomplete' and (complete or count > 65536)) \
                or (category not in ('limit', 'incomplete') and (not complete or count > 65536)) \
                or (category == 'none' and count != 0) \
                or (category not in ('none', 'incomplete', 'limit') and count == 0) \
                or (value['state'] == 'compatible' and category != 'none'):
            raise ValueError()
    if 'host_transport' in value:
        counters = value['host_transport']
        if type(counters) is not dict or set(counters) != {'received_envelopes', 'wire_bytes',
                'egress_opens', 'transfer_envelopes', 'idle_polls', 'sent_bytes', 'received_bytes', 'elapsed_ms'} \
                or any(not integer(v, 10**9) for v in counters.values()):
            raise ValueError()
    if value['state'] not in STATES or value['stage'] not in STAGES:
        raise ValueError()
    session = value['session_id']
    if session is not None and (type(session) is not str or not re.fullmatch(
            r'T-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', session)):
        raise ValueError()
    for key in ('requested', 'effective_model', 'effective_effort', 'effective_fast', 'native_retry_count'):
        if value[key] != template[key]:
            raise ValueError()
    if value['reported_mode_matches'] is not None and type(value['reported_mode_matches']) is not bool:
        raise ValueError()
    for key, names in (('events', set(EVENTS)), ('init_counts', {'tools', 'mcp_servers', 'subagents'})):
        counts = value[key]
        if type(counts) is not dict or set(counts) != names or any(
                not (key == 'init_counts' and v is None) and not integer(v, 1024) for v in counts.values()):
            raise ValueError()
    if type(value['proposal_validated']) is not bool:
        raise ValueError()
    usage(value['usage'])
    for key, maximum in (('reported_duration_ms', 10**9), ('reported_num_turns', 1024)):
        if value[key] is not None and not integer(value[key], maximum):
            raise ValueError()
    if value['exit_code'] is not None and (type(value['exit_code']) is not int or not -255 <= value['exit_code'] <= 255):
        raise ValueError()
    if not integer(value['elapsed_ms'], 40000) or not integer(value['stdout_bytes'], 262145):
        raise ValueError()
    if value['state'] == 'compatible' and (value['stage'] != 'awaiting_exit'
            or value['exit_code'] != 0 or not value['proposal_validated'] or session is None
            or value['reported_num_turns'] != 1 or value['events'] != dict(zip(EVENTS, (1, 1, 1, 1, 0, 0, 0)))):
        raise ValueError()
    return value


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError()
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


class SmokeStream:
    def __init__(self):
        self.result = initial_result()
        self.result['stage'] = 'awaiting_init'

    def accept(self, data):
        r = self.result
        try:
            event = parse(data)
            if type(event) is not dict:
                raise ValueError()
            kind = event.get('type')
            message = event.get('message', {})
            blocks = message.get('content', []) if type(message) is dict else []
            activity = kind in ('approval', 'tool_use', 'tool_result') or event.get('subtype') == 'subagent_finished' \
                or event.get('parent_tool_use_id') is not None or event.get('subagent_tool_use_id') is not None \
                or (type(blocks) is list and any(type(b) is dict and b.get('type') in
                    ('tool_use', 'tool_result') for b in blocks)) or bool(event.get('permission_denials'))
            if activity:
                r['events']['tool_activity'] += 1
                r['state'] = 'tool_activity'
                return False
            if kind in ('system', 'result') and event.get('subtype') in ('error_during_execution', 'error_max_turns'):
                r['events']['error'] += 1
                r['state'] = 'native_error'
                r['native_error_subtype'] = event['subtype']
                return False
            label = 'init' if kind == 'system' and event.get('subtype') == 'init' else kind
            r['events'][label if label in EVENTS else 'unknown'] += 1
            if r['stage'] == 'awaiting_init':
                required = {'type', 'subtype', 'cwd', 'session_id', 'tools', 'mcp_servers'}
                if label != 'init' or not required <= set(event) or set(event) - required - {'subagents', 'agent_mode'}:
                    raise ValueError()
                if event['session_id'] is None or type(event['cwd']) is not str \
                        or any(type(event[name]) is not list for name in ('tools', 'mcp_servers')):
                    raise ValueError()
                for name in r['init_counts']:
                    values = event.get(name)
                    if values is not None:
                        if type(values) is not list or len(values) > 1024:
                            raise ValueError()
                        r['init_counts'][name] = len(values)
                r['session_id'] = event['session_id']
                if 'agent_mode' in event:
                    r['reported_mode_matches'] = event['agent_mode'] == r['requested']['model']
                safe_result(r)
                r['stage'] = 'awaiting_user'
                return True
            if event.get('session_id') != r['session_id']:
                raise ValueError()
            if r['stage'] == 'awaiting_user':
                if event != {'type': 'user', 'session_id': r['session_id'], 'parent_tool_use_id': None,
                             'message': {'role': 'user', 'content': [{'type': 'text', 'text': PROMPT}]}}:
                    raise ValueError()
                r['stage'] = 'awaiting_assistant'
            elif r['stage'] == 'awaiting_assistant':
                if kind != 'assistant' or set(event) != {'type', 'message', 'session_id', 'parent_tool_use_id'} \
                        or type(message) is not dict or not {'type', 'role', 'content', 'stop_reason'} <= set(message) \
                        or set(message) - {'type', 'role', 'content', 'stop_reason', 'usage'} \
                        or message['type'] != 'message' or message['role'] != 'assistant' or message['stop_reason'] != 'end_turn' \
                        or type(blocks) is not list or len(blocks) != 1 or type(blocks[0]) is not dict \
                        or set(blocks[0]) != {'type', 'text'} or blocks[0]['type'] != 'text' \
                        or parse(blocks[0]['text']) != PROPOSAL:
                    raise ValueError()
                r['usage'] = usage(message.get('usage'))
                r['proposal_validated'] = True
                r['stage'] = 'awaiting_result'
            elif r['stage'] == 'awaiting_result':
                required = {'type', 'subtype', 'session_id', 'duration_ms', 'num_turns', 'result', 'is_error'}
                if kind != 'result' or not required <= set(event) or set(event) - required - {
                        'duration_api_ms', 'usage', 'permission_denials'} or event['subtype'] != 'success' \
                        or event['is_error'] is not False or type(event['num_turns']) is not int or event['num_turns'] != 1 \
                        or not integer(event['duration_ms'], 10**9) or parse(event['result']) != PROPOSAL:
                    raise ValueError()
                if 'usage' in event:
                    r['usage'] = usage(event['usage'])
                r['reported_duration_ms'] = event['duration_ms']
                r['reported_num_turns'] = event['num_turns']
                r['stage'] = 'awaiting_exit'
            else:
                raise ValueError()
            return True
        except (ValueError, TypeError, KeyError, RecursionError):
            # Discard even partially copied metadata if it fails the allowlist.
            r['state'] = 'schema_rejected'
            try:
                safe_result(r)
            except (ValueError, TypeError):
                stage = r['stage']
                self.result = initial_result()
                self.result.update(state='schema_rejected', stage=stage)
            return False


def run_smoke(command, env, progress, operator_display=None):
    stream = SmokeStream()
    diagnostic = NativeDiagnostic()
    def snapshot():
        stream.result['native_diagnostic'] = diagnostic.result()
        return safe_result(stream.result)
    def finish():
        value = snapshot()
        if operator_display is not None:
            operator_display(bytes(diagnostic.data[:2048]).hex(), diagnostic.total > 2048)
        return value
    started = time.monotonic()
    deadline = started + 30
    pending = bytearray()
    child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    os.set_blocking(child.stdout.fileno(), False)
    os.set_blocking(child.stderr.fileno(), False)
    progress(snapshot())
    eof = False
    while time.monotonic() < deadline:
        r = stream.result
        r['elapsed_ms'] = int((time.monotonic() - started) * 1000)
        if eof and diagnostic.complete:
            code = child.poll()
            if code is not None:
                r['exit_code'] = code
                r['state'] = ('native_failed' if code != 0 else 'compatible'
                              if r['stage'] == 'awaiting_exit' and not pending else 'schema_rejected')
                if r['state'] == 'compatible' and diagnostic.total:
                    r['state'] = 'native_diagnostic_error'
                return finish()
            time.sleep(.01)
            continue
        pipes = ([] if eof else [child.stdout]) + ([] if diagnostic.complete else [child.stderr])
        ready, _, _ = select.select(pipes, [], [], min(.05, max(0, deadline - time.monotonic())))
        if not ready:
            continue
        if child.stderr in ready:
            data = os.read(child.stderr.fileno(), min(4096, 65537-diagnostic.total))
            if not data:
                diagnostic.complete = True
            elif not diagnostic.feed(data):
                r['state'] = 'native_stderr_limit'
                return finish()
        if child.stdout not in ready:
            continue
        data = os.read(child.stdout.fileno(), min(4096, 262145 - r['stdout_bytes']))
        if not data:
            eof = True
            continue
        r['stdout_bytes'] += len(data)
        if r['stdout_bytes'] > 262144:
            r['state'] = 'output_limit'
            return finish()
        pending.extend(data)
        while b'\n' in pending:
            line, _, rest = pending.partition(b'\n')
            pending = bytearray(rest)
            if len(line) > 65536:
                r['state'] = 'output_limit'
                return finish()
            if not stream.accept(line):
                return finish()
            progress(snapshot())
        if len(pending) > 65536:
            r['state'] = 'output_limit'
            return finish()
    stream.result.update(state='timeout', elapsed_ms=30000)
    # Parent receives the result and kills the entire service cgroup, including
    # this child and descendants. No retry or separate child cleanup allowance.
    return finish()
