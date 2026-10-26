from copy import deepcopy
import unittest

from demo import healthy_snapshot, scenarios, SPEAKER
from sonosdoctor.checks import run_checks
from sonosdoctor.stp import parse_showstp


def codes(snapshot, **kwargs):
    return {f['code'] for f in run_checks(snapshot, **kwargs)}


class DiagnosticsTests(unittest.TestCase):
    def test_healthy_observations_have_no_findings(self):
        self.assertEqual(run_checks(healthy_snapshot()), [])

    def test_speaker_root_is_critical(self):
        findings = run_checks(scenarios()[1][1])
        self.assertTrue(any(f['code'] == 'stp-root-is-sonos' and
                            f['severity'] == 'crit' for f in findings))

    def test_tail_replaces_generic_jitter(self):
        result = codes(scenarios()[2][1])
        self.assertIn('tail-only-latency', result)
        self.assertNotIn('high-jitter', result)

    def test_loss_prevents_clean_tail_diagnosis(self):
        result = codes(scenarios()[3][1])
        self.assertIn('packet-loss', result)
        self.assertIn('high-jitter', result)
        self.assertNotIn('tail-only-latency', result)

    def test_controller_evidence_deduplicates_dead_port(self):
        snap = healthy_snapshot()
        snap['devices'][0]['tcp_1400_open'] = False
        self.assertIn('link-up-but-dead', codes(snap))
        self.assertNotIn('port-1400-closed', codes(snap))
        snap['devices'][0].pop('unifi')
        self.assertIn('port-1400-closed', codes(snap))

    def test_boot_sequence_alone_does_not_prove_reboot(self):
        previous = healthy_snapshot()
        current = deepcopy(previous)
        current['devices'][0]['boot_seq'] += 1
        current['devices'][0]['unifi']['uptime'] += 60
        self.assertIn('bootseq-advanced', codes(current, previous=previous))
        self.assertNotIn('reboot-detected', codes(current, previous=previous))
        current['devices'][0]['unifi']['uptime'] = 30
        self.assertIn('reboot-detected', codes(current, previous=previous))

    def test_missing_device_remains_visible_without_previous_snapshot(self):
        known = {SPEAKER: {'room': 'Demo speaker', 'ip': '192.0.2.10',
                           'missing_for': 3}}
        findings = run_checks({'devices': []}, known=known)
        self.assertEqual(findings[0]['code'], 'device-missing')
        self.assertIn('3 consecutive', findings[0]['message'])

    def test_root_disagreement(self):
        snap = healthy_snapshot()
        second = deepcopy(snap['devices'][0])
        second.update(mac='02:00:00:00:00:03', ip='192.0.2.11')
        second['stp']['root_mac'] = '02:00:00:00:00:20'
        snap['devices'].append(second)
        self.assertIn('stp-root-disagreement', codes(snap))

    def test_parser_recovers_root_and_port_state(self):
        parsed = parse_showstp('bridge id 8000.020000000001\n'
                              'designated root 1000.020000000010\n'
                              'root port 1 path cost 20\n'
                              'ath0 (1)\nstate forwarding\npath cost 20\n')
        self.assertEqual(parsed['root_prio'], 4096)
        self.assertEqual(parsed['root_path_cost'], 20)
        self.assertEqual(parsed['ports'][0]['state'], 'forwarding')

    def test_empty_parser_input_does_not_invent_root(self):
        self.assertEqual(parse_showstp(''), {'ports': []})


if __name__ == '__main__':
    unittest.main()
