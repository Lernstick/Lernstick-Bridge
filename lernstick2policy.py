#!/bin/env python3
'''
SPDX-License-Identifier: AGPL-3.0-only
Copyright 2021 Thore Sommer

Extracts the necessary information from a Lernstick ISO for generating a UEFI event log policy and IMA policy
Needs the following tools installed
 - mount
 - sbattach
 - hash-to-efi-sig-list
 - unmkinitramfs
'''
import base64
import glob
import json
import os
import argparse
import shutil
import subprocess
import hashlib

from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate, ExtensionNotFound, oid



def mount(iso, mount_dir):
    os.mkdir(mount_dir)
    res = subprocess.run(["mount", "-o", "loop", iso, mount_dir], capture_output=True)
    if res.returncode != 0:
        raise Exception(f"Creating ISO failed: {res.stderr}")


def unmount(mount_dir, error = True):
    res = subprocess.run(["umount", mount_dir], capture_output=True)
    if error and res.returncode != 0:
        raise Exception(f"Failed to unmount ISO: {res.stderr}")


def extract_grub_files(mount_dir):
    output = {}
    for file in glob.glob(f"{mount_dir}/boot/grub/**/*", recursive=True):
        # We still include .mod files because even when they fail to load, they are still measured
        if os.path.isdir(file):
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

def parse_keys(keys):
    key_ids = []
    pubkeys = []

    for key_path in keys:
        with open(key_path, "rb") as f:
            filedata = f.read()
            try:
                cert = load_pem_x509_certificate(filedata)
            except ValueError:
                cert = load_der_x509_certificate(filedata)
            pubkey = encode_pub_key(cert.public_key())
            keyid = get_keyidv2_from_cert(cert)
            pubkeys.append(pubkey)
            key_ids.append(keyid)
    return key_ids, pubkeys
    return

def merge_dict(from_dict, to_dict):
    for key, value in from_dict.items():
        if key in to_dict:
            to_dict[key].extend(value)
        else:
            to_dict[key] = value

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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", "-k", action="append", help="Use IMA keys instead of generated hash list. "
                                                             "Has better performance. Needs to be PEM encoded.")
    parser.add_argument("--exclude", "-e", action='append', help="List of regexes to exclude")
    parser.add_argument("--include-initramfs", action="store_true", help="Include hashes for IMA from initramfs")
    parser.add_argument("--include-squashfs", action="store_true", help="Include hashes for IMA from squashfs")
    parser.add_argument("lernstickISO")
    parser.add_argument("output", help="Path for the policy to store")
    args = parser.parse_args()

    if os.getuid() != 0:
            exit("This script mus be run as root!")

    policy = {}
    hash_list = {}
    keys = {
        "keyids": [],
        "pubkeys":  []
    }
    with TemporaryDirectory() as tempdir:
        try:
            iso_dir = f'{tempdir}/iso'
            squash_dir = f'{tempdir}/squash'
            init_dir = f'{tempdir}/init'
            efi_img_dir = f'{tempdir}/efi_img'
            mount(args.lernstickISO, iso_dir)
            mount(f'{iso_dir}/boot/grub/efi.img', efi_img_dir)
            mount(f'{iso_dir}/live/filesystem.squashfs', squash_dir)

            if args.include_initramfs:
                initrmafs_hashes = hash_initramfs(f'{iso_dir}/live/initrd.img', init_dir)
                merge_dict(initrmafs_hashes, hash_list)

            root_hash_path = f'{iso_dir}/live/filesystem.squashfs.roothash.orig'
            if os.path.exists(root_hash_path):
                with open(f'{iso_dir}/live/filesystem.squashfs.roothash.orig', 'r', encoding="utf-8") as f:
                    policy['roothash'] = f.read()

            policy['grub_files'] = extract_grub_files(iso_dir)
            policy['kernel'] = extract_kernel_hashes(iso_dir)
            policy['boot'] = extract_boot_hashes(list(glob.glob(f"{efi_img_dir}/EFI/boot/*") + [f"{iso_dir}/live/vmlinuz"]))

            # Add all files to the hash list
            if args.include_squashfs:
                hashes = hash_files(squash_dir)
                merge_dict(hashes, hash_list)

            # Get ephemeral IMA key
            key_path = os.path.join(squash_dir, "etc/keys/x509_evm.der")
            if os.path.exists(key_path):
                keyids, pubkeys = parse_keys([key_path])
                keys["keyids"].extend(keyids)
                keys["pubkeys"].extend(pubkeys)

            unmount(efi_img_dir)
            unmount(squash_dir)
            if args.include_initramfs:
                unmount(init_dir, False)
            unmount(iso_dir)

        except Exception as e:
            unmount(efi_img_dir, False)
            if args.include_initramfs:
                unmount(init_dir, False)
            unmount(squash_dir, False)
            unmount(iso_dir, False)
            print(f"Something failed: {e}")
            exit(1)

    runtime_policy = {
        "meta": {
            "version": 1,
            "generator": 0,
        },
        "release": 0,
        "digests": {},
        "excludes": [],
        "keyrings": {},
        "ima": {"ignored_keyrings": [], "log_hash_alg": "sha1", "dm_policy": None},
        "ima-buf": {},
        "verification-keys": "",
    }

    runtime_policy["excludes"].append("boot_aggregate")
    if args.exclude:
        runtime_policy["excludes"].extend(args.exclude)

    if args.key:
        keyids, pubkeys = parse_keys(args.key)
        keys["keyids"].extend(keyids)
        keys["pubkeys"].extend(pubkeys)

    if keys["keyids"]:
        runtime_policy["verification-keys"] = json.dumps(keys)

    # Generate policy format for the bridge, with an empty IMA runtime policy
    bridge_policy = {
        "runtime_policy": runtime_policy,
        "mb_refstate": policy
    }

    with open(args.output, 'w', encoding="utf-8") as f:
        json.dump(bridge_policy, f)
    exit(0)


if __name__ == "__main__":
    main()
