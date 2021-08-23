#!/bin/env python3

from keylime import ca_util

CA_DIR = "/cv_ca"
DEFAULT_PW = "default"

ca_util.setpassword(DEFAULT_PW)
ca_util.cmd_init(CA_DIR)
ca_util.cmd_mkcert(CA_DIR, 'server')
ca_util.cmd_mkcert(CA_DIR, 'client')
