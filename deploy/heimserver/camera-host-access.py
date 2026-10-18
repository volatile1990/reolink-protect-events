"""Reach this host's six macvlan bridges without routing through the gateway."""
import json
import subprocess
import sys

INTERFACE = 'camera-host'
PARENT = 'enp1s0.30'
ADDRESS = '192.168.30.217/32'
MAC = '02:42:c0:a8:1e:d9'
BRIDGES = ['192.168.30.' + str(i) for i in range(210, 216)]


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    links = json.loads(run('ip', '-j', '-d', 'link', 'show'))
    existing = next((link for link in links if link['ifname'] == INTERFACE), None)
    if '--stop' in sys.argv:
        if existing:
            assert existing['address'] == MAC and existing.get('linkinfo', {}).get('info_kind') == 'macvlan'
            run('ip', 'link', 'delete', INTERFACE)
        return
    if not existing:
        run('ip', 'link', 'add', 'link', PARENT, 'name', INTERFACE, 'address', MAC,
            'type', 'macvlan', 'mode', 'bridge')
    else:
        assert existing['address'] == MAC and existing.get('linkinfo', {}).get('info_kind') == 'macvlan'
    run('ip', 'address', 'replace', ADDRESS, 'dev', INTERFACE)
    run('ip', 'link', 'set', INTERFACE, 'up')
    for bridge in BRIDGES:
        run('ip', 'route', 'replace', bridge + '/32', 'dev', INTERFACE,
            'src', ADDRESS.split('/')[0])


if __name__ == '__main__':
    main()
