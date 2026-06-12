"""
Unit tests for the pod-stack orchestrator (scripts/pod_stack.py):
  - the stdlib YAML-subset parser (block + flow, comments, scalars),
  - JSON fallback,
  - depends_on topological ordering + cycle detection,
  - per-service argv construction (ports/env/volumes/restart/health/aliases),
  - validation errors.

No services are launched; only the pure parsing/planning layer is exercised.
"""

import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stderr

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ps = _load_module('pod_stack', ROOT / 'scripts' / 'pod_stack.py')


def expect_die(fn):
    """Run fn(); return the SystemExit it raises (pod_stack.die -> sys.exit)."""
    buf = io.StringIO()
    try:
        with redirect_stderr(buf):
            fn()
    except SystemExit as e:
        return e.code, buf.getvalue()
    raise AssertionError("expected SystemExit, none raised")


class TestYamlSubset(unittest.TestCase):
    def test_block_mapping_and_scalars(self):
        d = ps.parse_stack_text(
            "name: demo\n"
            "net: host\n"
            "services:\n"
            "  db:\n"
            "    binary: /bin/echo\n"
            "    restart: unless-stopped\n")
        self.assertEqual(d['name'], 'demo')
        self.assertEqual(d['services']['db']['binary'], '/bin/echo')

    def test_flow_list_and_block_list(self):
        d = ps.parse_stack_text(
            "services:\n"
            "  a:\n"
            "    binary: /bin/echo\n"
            "    ports: [\"80:80\", \"443:443\"]\n"
            "    depends_on:\n"
            "      - b\n"
            "  b: { binary: /bin/echo }\n")
        self.assertEqual(d['services']['a']['ports'], ['80:80', '443:443'])
        self.assertEqual(d['services']['a']['depends_on'], ['b'])

    def test_flow_map_with_nested_list(self):
        d = ps.parse_stack_text(
            "services:\n"
            "  a: { binary: /bin/echo, command: [\"/bin/sh\", \"-c\", \"x\"] }\n")
        self.assertEqual(d['services']['a']['command'],
                         ['/bin/sh', '-c', 'x'])

    def test_comments_and_blanks_ignored(self):
        d = ps.parse_stack_text(
            "# a comment\n"
            "name: c   # trailing comment\n"
            "\n"
            "services:\n"
            "  s: { binary: /bin/echo }\n")
        self.assertEqual(d['name'], 'c')

    def test_bool_and_int_scalars(self):
        d = ps.parse_stack_text(
            "services:\n"
            "  s:\n"
            "    binary: /bin/echo\n"
            "    health: true\n")
        self.assertIs(d['services']['s']['health'], True)

    def test_json_fallback(self):
        d = ps.parse_stack_text(
            '{"name":"j","services":{"a":{"binary":"/bin/echo"}}}')
        self.assertEqual(d['name'], 'j')

    def test_tabs_rejected(self):
        code, msg = expect_die(
            lambda: ps.parse_stack_text("services:\n\t a: x\n"))
        self.assertNotEqual(code, 0)
        self.assertIn('tab', msg.lower())


class TestTopoSort(unittest.TestCase):
    def _stack(self, deps):
        services = {}
        for name, d in deps.items():
            services[name] = {'binary': '/bin/echo', 'depends_on': d}
        return ps.Stack({'services': services})

    def test_dependency_before_dependent(self):
        s = self._stack({'app': ['db'], 'db': [], 'proxy': ['app']})
        self.assertLess(s.order.index('db'), s.order.index('app'))
        self.assertLess(s.order.index('app'), s.order.index('proxy'))

    def test_cycle_detected(self):
        code, msg = expect_die(
            lambda: self._stack({'x': ['y'], 'y': ['x']}))
        self.assertNotEqual(code, 0)
        self.assertIn('cycle', msg.lower())

    def test_unknown_dependency(self):
        code, msg = expect_die(
            lambda: self._stack({'x': ['ghost']}))
        self.assertNotEqual(code, 0)
        self.assertIn('ghost', msg)

    def test_self_dependency_rejected(self):
        code, _ = expect_die(lambda: self._stack({'x': ['x']}))
        self.assertNotEqual(code, 0)


class TestServiceArgv(unittest.TestCase):
    def _stack(self):
        return ps.Stack({
            'name': 't', 'net': 'host',
            'services': {
                'db': {'binary': '/bin/echo'},
                'app': {
                    'binary': '/bin/echo',
                    'depends_on': ['db'],
                    'ports': ['8080:80'],
                    'env': {'B': '2', 'A': '1'},
                    'volumes': ['/h:/c'],
                    'restart': 'on-failure:3',
                    'health': True,
                    'command': ['/app', '--flag'],
                },
            }})

    def test_argv_contains_all_flags_in_order(self):
        s = self._stack()
        argv = ps.service_argv(s, s.services['app'], None)
        self.assertEqual(argv[0], '/bin/echo')
        # service-name DNS aliases for every service
        self.assertIn('--add-host', argv)
        self.assertIn('db:127.0.0.1', argv)
        self.assertIn('app:127.0.0.1', argv)
        # env sorted deterministically
        self.assertEqual(argv[argv.index('-e') + 1], 'A=1')
        self.assertIn('8080:80', argv)
        self.assertIn('/h:/c', argv)
        self.assertEqual(argv[argv.index('--restart') + 1], 'on-failure:3')
        self.assertIn('--health', argv)
        # command override is last
        self.assertEqual(argv[-2:], ['/app', '--flag'])

    def test_shared_net_joins_pause(self):
        s = ps.Stack({'net': 'shared', 'ipc': 'shared',
                      'services': {'a': {'binary': '/bin/echo'}}})
        argv = ps.service_argv(s, s.services['a'], 4242)
        self.assertIn('container:4242', argv)
        self.assertEqual(argv[argv.index('--ipc') + 1], 'container:4242')


class TestValidation(unittest.TestCase):
    def test_missing_binary(self):
        code, msg = expect_die(
            lambda: ps.Stack({'services': {'a': {}}}))
        self.assertNotEqual(code, 0)
        self.assertIn('binary', msg)

    def test_bad_restart(self):
        code, msg = expect_die(lambda: ps.Stack(
            {'services': {'a': {'binary': '/bin/echo',
                                'restart': 'sometimes'}}}))
        self.assertNotEqual(code, 0)
        self.assertIn('restart', msg)

    def test_bad_net(self):
        code, _ = expect_die(lambda: ps.Stack(
            {'net': 'bridge', 'services': {'a': {'binary': '/bin/echo'}}}))
        self.assertNotEqual(code, 0)

    def test_invalid_service_name(self):
        code, _ = expect_die(lambda: ps.Stack(
            {'services': {'../evil': {'binary': '/bin/echo'}}}))
        self.assertNotEqual(code, 0)

    def test_empty_services(self):
        code, _ = expect_die(lambda: ps.Stack({'services': {}}))
        self.assertNotEqual(code, 0)


if __name__ == '__main__':
    unittest.main()
