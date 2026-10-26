"""Reproduce an incident using invented devices; no network access."""
from copy import deepcopy

from sonosdoctor.checks import run_checks
from sonosdoctor.stp import parse_showstp

SPEAKER = '02:00:00:00:00:01'
SWITCH = '02:00:00:00:00:10'


def healthy_snapshot():
    return {'devices': [{
        'room': 'Demo speaker', 'ip': '192.0.2.10', 'mac': SPEAKER,
        'radio_mac': '02:00:00:00:00:02', 'tcp_1400_open': True,
        'ping': {'loss_pct': 0, 'min_ms': 1, 'max_ms': 3,
                 'avg_ms': 2, 'jitter_ms': 1},
        'boot_seq': 10, 'unifi': {'uptime': 1000},
        'stp': parse_showstp('bridge id 8000.020000000001\n'
                             'designated root 1000.020000000010\n'
                             'root port 1 path cost 10\n'),
    }], 'matrix': [], 'unifi': {'available': False}}


def scenarios():
    healthy = healthy_snapshot()
    root = deepcopy(healthy)
    root['devices'][0]['stp'].update(root_mac=SPEAKER, root_prio=32768)
    tail = deepcopy(healthy)
    tail['devices'][0]['ping'].update(max_ms=120, jitter_ms=40)
    loss = deepcopy(tail)
    loss['devices'][0]['ping']['loss_pct'] = 30
    return [('Healthy baseline', healthy), ('Speaker wins root election', root),
            ('Clean floor, long latency tail', tail), ('Actual packet loss', loss)]


if __name__ == '__main__':
    print('SYNTHETIC DEMO — no devices contacted\n')
    for title, snapshot in scenarios():
        print(title)
        findings = run_checks(snapshot)
        if not findings:
            print('  No findings in the supplied observations.')
        for finding in findings:
            print(f"  {finding['severity'].upper()} {finding['code']}")
        print()
