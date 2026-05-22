# Copyright (c) 2024 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Connects to the first FIDO device found which supports the PRF extension,
creates a new credential for it with the extension enabled, and uses it to
derive two separate secrets.
"""

import sys

from exampleutils import get_client

from fido2 import cbor
from fido2.cose import EcsdsaBls12_381_Sha256, CoseKey
from fido2.ctap2.extensions import PreviewSignExtension
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_decode, websafe_encode

uv = "discouraged"

# Locate a suitable FIDO authenticator
client, info = get_client(
    lambda info: PreviewSignExtension.NAME in info.extensions,
    extensions=[PreviewSignExtension()],
)

server = Fido2Server({"id": "example.com", "name": "Example RP"}, attestation="none")
user = {"id": b"user_id", "name": "A. User"}


# Prepare a message to sign
credential_id_b64u = "ASfqmj2gEJ7zV6FeqEmFZJNh02guZeUZTKb6PuuW60lqUfx7ehjpXbk_BXvPS6cdTPjCo4i7gEukEiUSh3G9E8DbjYd7w901muQh8_iLs-c0yPwzZ5QpcvrckUwjP3k5xAHBA2KVTN28LoeGIrUFWqV-vTzORxRFMO-3UKPLca67PLUE5d5g2pV-bHKD6f4saPm7ag8q9NMw0a9Hy46I4bwmDkwZCSQ-CExwqIWh3gXqvqoayYxi-kVK367c9NSGHRhFKwfVnc4dUgnwtzLUeoDbDJDmrY3n5uearaQtWZfmp0UMjbhDmxhCw1APGVdI8w";
key_handle_b64u = "glggkRfaK84xyQZuslkJ7yyl6m98cZKLn3h3kWg_RobtwANYKYM6AAEARAFYIK-5qyOVNgvIRVb5UV53TSK6hq4xIGC3cW27P9YjFXVv";
tbs = bytes.fromhex("8129444781a011cf17ead139e0b308c68accadbdd557a46815f6b4fc4cd2b576ae260c4b461b4e72aa131088e128aed448656c6c6f2c20576f726c6421")


# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin([
    { "id": websafe_decode(credential_id_b64u), "type": 'public-key' }
], user_verification=uv)


# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        # Add extension outputs. We have only 1 credential in allowCredentials
        "extensions": {
            PreviewSignExtension.NAME: {
                "signByCredential": {
                    credential_id_b64u: {
                        "keyHandle": websafe_decode(key_handle_b64u),
                        "tbs": tbs,
                    },
                },
            }
        },
    }
)

# Only one cred in allowCredentials, only one response.
result = result.get_response(0)

sign_result = result.client_extension_results[PreviewSignExtension.NAME]
print("GET sign result", sign_result)

# Response contains a signature over tbs
signature_b64 = sign_result.get("signature")
signature = websafe_decode(signature_b64)

# print("Test verify signature", signature_b64)
# pk.verify(tbs, signature)
# print("Signature verified!")

print(f'const smsg = fromHex("{signature.hex()}");')
