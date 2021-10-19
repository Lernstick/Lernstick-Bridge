#!/bin/env python3
'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer

Extracts the necessary information from a Lernstick ISO for generating a very simple IMA policy
Needs the following tools installed
 - unmkinitramfs
'''
import glob
import json
import os
import argparse
import shutil
import subprocess
import hashlib

from tempfile import TemporaryDirectory


def mount(iso, mount_dir):
    os.mkdir(mount_dir)
    res = subprocess.run(["mount", "-o", "loop", iso, mount_dir], capture_output=True)
    if res.returncode != 0:
        raise Exception(f"Creating ISO failed: {res.stderr}")


def unmount(mount_dir):
    res = subprocess.run(["umount", mount_dir], capture_output=True)
    if res.returncode != 0:
        raise Exception(f"Failed to unmount ISO: {res.stderr}")


def hash_files(dir):
    output = {}
    for file in glob.glob(f"{dir}/**/*", recursive=True):
        if not os.path.isfile(file):
            continue

        # Only hash executables, kernel modules and shared libraries
        if (not os.access(file, os.X_OK)) and not(".so" in file or file.endswith(".ko")):
            continue

        with open(file, 'rb') as f:
            hash = hashlib.sha256(f.read()).hexdigest()
        name = f'/{os.path.relpath(file, dir)}'
        output[name] = [hash]
    return output


def hash_initramfs(initfs, dest_dir):
    subprocess.run(["unmkinitramfs", initfs, dest_dir])

    return {**hash_files(f'{dest_dir}/main'), **hash_files(f'{dest_dir}/early')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("lernstickISO")
    args = parser.parse_args()

    if os.getuid() != 0:
            exit("This script mus be run as root!")

    policy = {}
    with TemporaryDirectory() as tempdir:
        try:
            iso_dir = f'{tempdir}/iso'
            squash_dir = f'{tempdir}/squash'
            init_dir = f'{tempdir}/init'
            mount(args.lernstickISO, iso_dir)
            mount(f'{iso_dir}/live/filesystem.squashfs', squash_dir)
            policy.update(hash_files(squash_dir))
            for key, value in hash_initramfs(f'{iso_dir}/live/initrd.img', init_dir).items():
                if key in policy:
                    policy[key].extend(value)
                else:
                    policy[key] = value

            unmount(squash_dir)
            unmount(iso_dir)

        except Exception as e:
            unmount(iso_dir)
            print(f"Something failed: {e.with_traceback()}")
            exit(1)

    print(json.dumps({
        "meta": {
            "version": 2,
        },
        "hashes": policy
    }))
    exit(0)


if __name__ == "__main__":
    main()
