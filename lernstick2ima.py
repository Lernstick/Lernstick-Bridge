#!/bin/env python3
'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2022 Thore Sommer

Extracts the necessary information from a Lernstick ISO for generating a very simple IMA policy
Needs the following tools installed
 - unmkinitramfs
'''
import base64
import glob
import json
import os
import argparse
import subprocess
import hashlib

from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, ExtensionNotFound, oid


def mount(iso, mount_dir):
    os.mkdir(mount_dir)
    res = subprocess.run(["mount", "-o", "loop", iso, mount_dir], capture_output=True)
    if res.returncode != 0:
        raise Exception(f"Creating ISO failed: {res.stderr}")


def unmount(mount_dir):
    res = subprocess.run(["umount", mount_dir], capture_output=True)
    if res.returncode != 0:
        raise Exception(f"Failed to unmount ISO: {res.stderr}")


def hash_files(dir, rel_dir=None):
    if not rel_dir:
        rel_dir = dir
    output = {}
    for file in glob.glob(f"{dir}/**/*", recursive=True) + [dir]:
        if not os.path.isfile(file):
            continue

        # Only hash executables, kernel modules and shared libraries
        if (not os.access(file, os.X_OK)) and not(".so" in file or file.endswith(".ko")):
            continue

        with open(file, 'rb') as f:
            data = f.read()
            hash_sha1 = hashlib.sha1(data).hexdigest()
            hash_sha256 = hashlib.sha256(data).hexdigest()
        name = f'/{os.path.relpath(file, rel_dir)}'
        output[name] = [hash_sha1, hash_sha256]
    return output


def hash_initramfs(initfs, dest_dir):
    subprocess.run(["unmkinitramfs", initfs, dest_dir])

    return {**hash_files(f'{dest_dir}/main'), **hash_files(f'{dest_dir}/early')}


def encode_pub_key(key):
    fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    pubbytes = key.public_bytes(encoding=serialization.Encoding.DER, format=fmt)
    return base64.b64encode(pubbytes).decode("ascii")


def get_keyidv2_from_cert(cert):
    """Get the keyidv2 from the cert's Subject Key Identifier (SKID) if available."""
    if cert.extensions:
        try:
            skid = cert.extensions.get_extension_for_oid(oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if skid and skid.value and len(skid.value.digest) >= 4:
                keyidv2 = int.from_bytes(skid.value.digest[-4:], "big")
                return keyidv2
        except ExtensionNotFound:
            pass
    return None


def parse_keys(keys):
    key_ids = []
    pubkeys = []

    for key_path in keys:
        with open(key_path, "rb") as f:
            filedata = f.read()
            cert = load_pem_x509_certificate(filedata)
            pubkey = encode_pub_key(cert.public_key())
            keyid = get_keyidv2_from_cert(cert)
            pubkeys.append(pubkey)
            key_ids.append(keyid)
    return {
        "keyids": key_ids,
        "pubkeys":  pubkeys
    }

def merge_dict(from_dict, to_dict):
    for key, value in from_dict.items():
        if key in to_dict:
            to_dict[key].extend(value)
        else:
            to_dict[key] = value

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", "-k", action="append", help="Use IMA keys instead of generated hash list. "
                                                                      "Has better performance. Needs to be PEM encoded.")
    parser.add_argument("--exclude", "-e", action='append', help="List of regexes to exclude")
    parser.add_argument("--exclude-initramfs", "-i", action="store_true")
    parser.add_argument("lernstickISO")
    args = parser.parse_args()

    if os.getuid() != 0:
            exit("This script mus be run as root!")

    hash_list = {}
    with TemporaryDirectory() as tempdir:
        try:
            iso_dir = f'{tempdir}/iso'
            squash_dir = f'{tempdir}/squash'
            init_dir = f'{tempdir}/init'
            mount(args.lernstickISO, iso_dir)
            mount(f'{iso_dir}/live/filesystem.squashfs', squash_dir)
            if not args.exclude_initramfs:
                initrmafs_hashes = hash_initramfs(f'{iso_dir}/live/initrd.img', init_dir)
                merge_dict(initrmafs_hashes, hash_list)
            if args.key:
                # Only add files to the hash list also included in the initramfs.
                # We need to do this because hashes in the allowlist take higher priority
                # TODO: Check if this is actually required
                for file_path in list(hash_list.keys()):
                    path = os.path.join(squash_dir, file_path[1:])
                    hashes = hash_files(path, rel_dir=squash_dir)
                    merge_dict(hashes, hash_list)
            else:
                # Add all files to the hash list
                hashes = hash_files(squash_dir)
                merge_dict(hashes, hash_list)
            unmount(squash_dir)
            unmount(iso_dir)

        except Exception as e:
            unmount(iso_dir)
            print(f"Something failed: {e.with_traceback()}")
            exit(1)

    ima_policy = {
        "meta": {
            "version": 2,
        },
        "hashes": hash_list
    }
    excllist = ["boot_aggregate"]
    if args.exclude:
        excllist.extend(args.exclude)

    ima_policy_bundle = {
        "ima_policy": base64.b64encode(json.dumps(ima_policy).encode()).decode(),
        "excllist": excllist,
        "checksum": "",
    }
    if args.key:
        # Note that this is not the official Keylime format, but we use it for the Bridge
        ima_policy_bundle["keyring"] = parse_keys(args.key)

    print(json.dumps(ima_policy_bundle))
    exit(0)


if __name__ == "__main__":
    main()
