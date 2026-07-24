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
from fido2.cose import CoseKey, EcsdsaBls12_381_Sha256, EcsdsaBls12_381_BP1_Sha256_SEC1
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

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key_requirement="discouraged",
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

# Create a credential
result = client.make_credential(
    {
        **create_options["publicKey"],
        "extensions": {
            PreviewSignExtension.NAME: {
                "generateKey": {"algorithms": [EcsdsaBls12_381_BP1_Sha256_SEC1.ALGORITHM]}
            }
        },
    }
)

# Complete registration
auth_data = server.register_complete(state, result)
credential = auth_data.credential_data
print("New credential created, with the sign extension.")

# PRF result:
sign_result = result.client_extension_results.previewSign
print("CREATE sign result", sign_result)
sign_key = sign_result.generated_key
if not sign_key:
    print(
        "Failed to create credential with sign extension",
        result.client_extension_results,
    )
    sys.exit(1)
pk_bin = websafe_decode(sign_key["publicKey"])

# Extension output contains master public key
pk = cbor.decode(pk_bin)
print("public key", pk)
print(f'const dpk_rfc8235 = G1.Point.fromHex("{pk[-2].hex()}");')
print(f'pk = cbor.decode(bytes.fromhex("{pk_bin.hex()}"));')
print(f'credential_id_b64u = "{websafe_encode(credential.credential_id)}";')
print(f'key_handle_b64u = "{sign_key["keyHandle"]}";')






# Prepare a message to sign
tbs = bytes.fromhex("8129444781a011cf17ead139e0b308c68accadbdd557a46815f6b4fc4cd2b576ae260c4b461b4e72aa131088e128aed448656c6c6f2c20576f726c6421")


# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin([
    { "id": credential.credential_id, "type": 'public-key' }
], user_verification=uv)


# Authenticate the credential
result = client.get_assertion(
    {
        **request_options["publicKey"],
        # Add extension outputs. We have only 1 credential in allowCredentials
        "extensions": {
            PreviewSignExtension.NAME: {
                "signByCredential": {
                    websafe_encode(credential.credential_id): {
                        "keyHandle": sign_key["keyHandle"],
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

print("Test verify signature", signature_b64)
pk_cose = CoseKey.parse(pk)
pk_cose.verify(tbs, signature)
print("Signature verified!")

print(f'const smsg = fromHex("{signature.hex()}");')
