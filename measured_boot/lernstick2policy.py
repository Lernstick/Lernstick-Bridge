#!/bin/env python3
'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer

Extracts the necessary information from a Lernstick ISO for generating a UEFI event log policy
Needs the following tools installed
 - mount
 - sbattach
 - hash-to-efi-sig-list
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


def extract_grub_files(mount_dir):
    output = {}
    for file in glob.glob(f"{mount_dir}/boot/grub/**/*", recursive=True):
        # We exclude all modules because they are never loaded if SecureBoot is enabled
        if os.path.isdir(file) or file.endswith(".mod"):
            continue
        name = os.path.relpath(file, mount_dir)
        with open(file, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        output[name] = {'sha256': file_hash}
    return output


def extract_kernel_hashes(mount_dir):
    files = {'vmlinuz': f'{mount_dir}/live/vmlinuz', 'initrd': f"{mount_dir}/live/initrd.img"}
    output = {}
    for name, path in files.items():
        with open(path, 'rb')as f:
            output[name] = {'sha256': hashlib.sha256(f.read()).hexdigest()}
    return output


def extract_boot_hashes(files):
    output = {}
    for file in files:
        with TemporaryDirectory() as temp_dir:
            name = os.path.basename(file)
            new_file = os.path.join(temp_dir, name)
            shutil.copy2(file, new_file)

            # First remove signature because otherwise the other command will fail
            subprocess.run(["sbattach", "--remove", new_file])

            # Not all sections are included in the hash. For more see: PE/COFF Specification 8.0 Appendix A
            # hash-to-efi-sig-list produces the correct hashes
            res = subprocess.run(["hash-to-efi-sig-list", new_file, "/dev/null"], capture_output=True)
            if res.returncode != 0:
                raise Exception("Generating PE hash failed")
            output[name] = {"sha256": res.stdout.decode().split()[2]}

    return output


def extract_dm_verity_data(mount_dir):
    pass


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
            efi_img_dir = f'{tempdir}/efi_img'
            mount(args.lernstickISO, iso_dir)
            mount(f'{iso_dir}/boot/grub/efi.img', efi_img_dir)
            policy['grub_files'] = extract_grub_files(iso_dir)
            policy['kernel'] = extract_kernel_hashes(iso_dir)
            policy['boot'] = extract_boot_hashes(list(glob.glob(f"{efi_img_dir}/EFI/boot/*") + [f"{iso_dir}/live/vmlinuz"]))

            unmount(efi_img_dir)
            unmount(iso_dir)

        except Exception as e:
            unmount(efi_img_dir)
            unmount(iso_dir)
            print(f"Something failed: {e.with_traceback()}")
            exit(1)

    print(json.dumps(policy))
    exit(0)


if __name__ == "__main__":
    main()
