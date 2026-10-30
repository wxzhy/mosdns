# !/usr/bin/env python3
import argparse
import logging
import os
import subprocess
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument("-upx", action="store_true")
parser.add_argument("-i", type=int)
parser.add_argument("--amd64-only", action="store_true",
                    help="Build only Windows and Linux AMD64 (v1, v2, v3)")
parser.add_argument("--list-targets", action="store_true",
                    help="Print the selected release targets without building")
args = parser.parse_args()

PROJECT_NAME = 'mosdns'
RELEASE_DIR = './release'

logger = logging.getLogger(__name__)

# more info: https://golang.org/doc/install/source
# [(env : value),(env : value)]
envs = [
    [['GOOS', 'darwin'], ['GOARCH', 'amd64']],
    [['GOOS', 'darwin'], ['GOARCH', 'arm64']],
    # [['GOOS', 'linux'], ['GOARCH', '386']],
    [['GOOS', 'linux'], ['GOARCH', 'amd64']],

    [['GOOS', 'linux'], ['GOARCH', 'arm'], ['GOARM', '5']],
    [['GOOS', 'linux'], ['GOARCH', 'arm'], ['GOARM', '6']],
    [['GOOS', 'linux'], ['GOARCH', 'arm'], ['GOARM', '7']],
    [['GOOS', 'linux'], ['GOARCH', 'arm64']],

    # [['GOOS', 'linux'], ['GOARCH', 'mips'], ['GOMIPS', 'hardfloat']],
    # [['GOOS', 'linux'], ['GOARCH', 'mips'], ['GOMIPS', 'softfloat']],
    # [['GOOS', 'linux'], ['GOARCH', 'mipsle'], ['GOMIPS', 'hardfloat']],
    [['GOOS', 'linux'], ['GOARCH', 'mipsle'], ['GOMIPS', 'softfloat']],

    # [['GOOS', 'linux'], ['GOARCH', 'mips64'], ['GOMIPS64', 'hardfloat']],
    # [['GOOS', 'linux'], ['GOARCH', 'mips64'], ['GOMIPS64', 'softfloat']],
    [['GOOS', 'linux'], ['GOARCH', 'mips64le'], ['GOMIPS64', 'hardfloat']],
    # [['GOOS', 'linux'], ['GOARCH', 'mips64le'], ['GOMIPS64', 'softfloat']],

    [['GOOS', 'linux'], ['GOARCH', 'ppc64le']],

    # [['GOOS', 'freebsd'], ['GOARCH', '386']],
    [['GOOS', 'freebsd'], ['GOARCH', 'amd64']],

    # [['GOOS', 'windows'], ['GOARCH', '386']],
    [['GOOS', 'windows'], ['GOARCH', 'amd64']],
    [['GOOS', 'linux'], ['GOARCH', 'amd64'], ['GOAMD64', 'v2']],
    [['GOOS', 'linux'], ['GOARCH', 'amd64'], ['GOAMD64', 'v3']],
    [['GOOS', 'windows'], ['GOARCH', 'amd64'], ['GOAMD64', 'v2']],
    [['GOOS', 'windows'], ['GOARCH', 'amd64'], ['GOAMD64', 'v3']],
]


def target_name(env):
    return '-'.join([PROJECT_NAME] + [value for _, value in env])


def selected_targets():
    targets = envs
    if args.amd64_only:
        targets = [target for target in targets
                   if ['GOARCH', 'amd64'] in target
                   and any(pair in target for pair in
                           (['GOOS', 'windows'], ['GOOS', 'linux']))]
    if args.i is not None:
        targets = [targets[args.i]]
    return targets


def go_build():
    logger.info(f'building {PROJECT_NAME}')

    targets = selected_targets()
    if args.list_targets:
        for target in targets:
            print(target_name(target))
        return

    VERSION = 'dev/unknown'
    try:
        VERSION = subprocess.check_output('git describe --tags --long --always', shell=True).decode().rstrip()
    except subprocess.CalledProcessError as e:
        logger.error(f'get git tag failed: {e.args}')

    try:
        subprocess.check_call('go run ../ config gen config.yaml', shell=True, env=os.environ)
    except Exception:
        logger.exception('failed to generate config template')
        raise

    failures = []
    for env in targets:
        os_env = os.environ.copy()  # new env
        os_env['CGO_ENABLED'] = '0'

        s = target_name(env)
        for pairs in env:
            os_env[pairs[0]] = pairs[1]  # add env
        if os_env.get('GOARCH') == 'amd64' and not any(
                pair[0] == 'GOAMD64' for pair in env):
            # The unqualified AMD64 archive is always the v1 baseline.
            os_env['GOAMD64'] = 'v1'
        zip_filename = s + '.zip'

        suffix = '.exe' if os_env['GOOS'] == 'windows' else ''
        bin_filename = PROJECT_NAME + suffix

        logger.info(f'building {zip_filename}')
        try:
            subprocess.check_call(
                f'go build -ldflags "-s -w -X main.version={VERSION}" -trimpath -o {bin_filename} ../', shell=True,
                env=os_env)

            if args.upx:
                try:
                    subprocess.check_call(f'upx -9 -q {bin_filename}', shell=True, stderr=subprocess.DEVNULL,
                                          stdout=subprocess.DEVNULL)
                except subprocess.CalledProcessError as e:
                    logger.error(f'upx failed: {e.args}')

            with zipfile.ZipFile(zip_filename, mode='w', compression=zipfile.ZIP_DEFLATED,
                                 compresslevel=5) as zf:
                zf.write(bin_filename)
                zf.write('../README.md', 'README.md')
                zf.write('./config.yaml', 'config.yaml')
                zf.write('../LICENSE', 'LICENSE')

        except subprocess.CalledProcessError as e:
            logger.error(f'build {zip_filename} failed: {e.args}')
            failures.append(zip_filename)
        except Exception:
            logger.exception('unknown err')
            failures.append(zip_filename)
    if failures:
        raise RuntimeError('release builds failed: ' + ', '.join(failures))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    if not args.list_targets and len(RELEASE_DIR) != 0:
        if not os.path.exists(RELEASE_DIR):
            os.mkdir(RELEASE_DIR)
        os.chdir(RELEASE_DIR)

    go_build()
