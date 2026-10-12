import os
from collections.abc import Callable
from enum import IntEnum
from typing import Mapping, cast

import cryptography.exceptions
import pytest
from fido2 import cbor
from fido2.cose import ESP256_SPLIT_ARKG_PLACEHOLDER, CoseKey
from fido2.ctap import CtapError
from fido2.ctap2.extensions import PreviewSign5Extension, _Sign5SupportedAlgorithm
from fido2.ctap2.pin import ClientPin
from fido2.utils import sha256
from fido2.webauthn import AttestationObject

from . import TEST_PIN


class AuthenticatorInput(IntEnum):
    KH = 2
    ALG = 3
    FLAGS = 4
    TBS = 6
    ARGS = 7
    SUPPORT = 8


class AuthenticatorOutput(IntEnum):
    ERROR_CODE = -1
    ALG = 3
    FLAGS = 4
    SIG = 6
    ATT_OBJ = 7
    SUPPORT = 8


class PreviewSign5ErrorCode(IntEnum):
    UNSUPPORTED_ASSERTION_OPERATION = 1
    UNSUPPORTED_ALGORITHM = 2
    UNSUPPORTED_ALGORITHM_COMBINATION = 3
    INVALID_KEY_HANDLE = 4
    COSE_SIGN_ARGS_INVALID = 5
    COSE_SIGN_ARGS_ALG_MISMATCH = 6
    COSE_SIGN_ARGS_MISSING_PARAM = 7
    COSE_SIGN_ARGS_UNKNOWN_PARAM = 8


EMPTY_JSON_HASH = sha256(b"{}")
RP = {"id": "example.com", "name": "Example RP"}
USER = {"id": b"user_id", "name": "A. User"}
"""Not truly _all_ algorithms, but all we have prototyped"""
ALL_ALGORITHMS = [
    -9,  # ESP256
    -7,  # ES256
    -300,  # Requested assignment for ESP256-split https://www.ietf.org/archive/id/draft-lundberg-cose-two-party-signing-algs-06.html#name-ecdsa
    -70009,  # Placeholder value for ESP256-split used by some prototypes
    ESP256_SPLIT_ARKG_PLACEHOLDER,  # Placeholder for ESP256-split-ARKG https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-10.html#name-cose-algorithms
]
PREHASH_ALGS = [
    ESP256_SPLIT_ARKG_PLACEHOLDER,
    -300,
    -70009,  # Placeholder value for ESP256-split used by some prototypes
]


# These tests use only the raw authenticator inputs/outputs so the
# python-fido2 library doesn't need to maintain backwards compatibility of
# the client layer of the extension.


@pytest.fixture(autouse=True, scope="module")
def preconditions(dev_manager):
    if PreviewSign5Extension.NAME not in dev_manager.info.extensions:
        pytest.skip("previewSign5 not supported by authenticator")


def generate_key_inputs(algorithms, flags=0b000):
    return {
        AuthenticatorInput.ALG: algorithms,
        AuthenticatorInput.FLAGS: flags,
    }


def parse_generate_key_outputs(response):
    exts = response.auth_data.extensions or {}
    if (
        PreviewSign5Extension.NAME in exts
        and AuthenticatorOutput.ALG in exts[PreviewSign5Extension.NAME]
    ):
        algorithm = exts[PreviewSign5Extension.NAME][AuthenticatorOutput.ALG]
        assert PreviewSign5Extension.NAME in response.unsigned_extension_outputs
        unsigned_outputs = response.unsigned_extension_outputs[
            PreviewSign5Extension.NAME
        ]

        assert AuthenticatorOutput.ATT_OBJ in unsigned_outputs
        att_obj_cbor = cast(
            Mapping, cbor.decode(unsigned_outputs[AuthenticatorOutput.ATT_OBJ])
        )
        att_obj = AttestationObject.create(
            att_obj_cbor[1], att_obj_cbor[2], att_obj_cbor[3]
        )

        key_handle = att_obj.auth_data.credential_data.credential_id
        public_key = att_obj.auth_data.credential_data.public_key
        return algorithm, key_handle, public_key, att_obj

    else:
        return None


def sign_inputs(cred, tbs, additional_args=None):
    sign_inputs = {
        AuthenticatorInput.KH: cred.key_handle,
        AuthenticatorInput.TBS: sha256(tbs) if cred.algorithm in PREHASH_ALGS else tbs,
    }
    if additional_args is not None:
        sign_inputs[AuthenticatorInput.ARGS] = cbor.encode(additional_args)
    return sign_inputs


def parse_sign_outputs(response):
    exts = response.auth_data.extensions
    if (
        PreviewSign5Extension.NAME in exts
        and AuthenticatorOutput.SIG in exts[PreviewSign5Extension.NAME]
    ):
        signature = exts[PreviewSign5Extension.NAME][AuthenticatorOutput.SIG]
        return signature

    else:
        return None


def support_inputs():
    support_inputs = {AuthenticatorInput.SUPPORT: True}
    return support_inputs


def parse_error_outputs(response):
    exts = response.auth_data.extensions or {}
    if (
        PreviewSign5Extension.NAME in exts
        and AuthenticatorOutput.ERROR_CODE in exts[PreviewSign5Extension.NAME]
    ):
        return exts[PreviewSign5Extension.NAME][AuthenticatorOutput.ERROR_CODE]

    else:
        return None


def parse_support_outputs(response):
    exts = response.auth_data.extensions or {}
    if (
        PreviewSign5Extension.NAME in exts
        and AuthenticatorOutput.SUPPORT in exts[PreviewSign5Extension.NAME]
    ):
        return PreviewSign5Extension.parse_support_list(
            exts[PreviewSign5Extension.NAME][AuthenticatorOutput.SUPPORT]
        )

    else:
        return None


class Credential:
    def __init__(
        self,
        response,
        flags: int | None,
        options,
        extensions,
        generated_key: tuple[int, bytes, CoseKey, AttestationObject],
        error_code: int | None = None,
        support: list[_Sign5SupportedAlgorithm] | None = None,
    ):
        self.response = response
        self.flags = flags
        self.options = options
        self.extensions = extensions
        algorithm, key_handle, public_key, att_obj = generated_key or [None] * 4
        self.algorithm = algorithm
        self.key_handle = key_handle
        self.public_key = public_key
        self.att_obj = att_obj
        self.error_code = error_code
        self.support = support

    def __repr__(self):
        return repr(
            (
                self.response,
                self.flags,
                self.options,
                self.extensions,
                self.algorithm,
                self.key_handle,
                self.public_key,
                self.att_obj,
                self.error_code,
                self.support,
            )
        )


class CredentialCache:
    def __init__(self, generate_key):
        self.generate_key = generate_key
        self.cache = []

    def make_cred(
        self,
        cache_filter: Callable[[Credential], bool],
        algorithms: list[int],
        flags=0b000,
        options=None,
        extensions={},
    ) -> Credential | None:
        existing = next((cred for cred in self.cache if cache_filter(cred)), None)
        if existing is not None:
            return existing
        else:
            cred = self.generate_key(
                algorithms, flags, options=options, extensions=extensions
            )
            self.cache.append(cred)
            return cred

    def make_cred_or_skip(self, cache_filter, algorithms, *args, **kwargs):
        try:
            return self.make_cred(cache_filter, algorithms, *args, **kwargs)
        except CtapError as e:
            if e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM:
                pytest.skip(f"Algorithms {algorithms} not supported")
            raise e


@pytest.fixture(scope="module")
def credential_cache(generate_key):
    return CredentialCache(generate_key)


@pytest.fixture(scope="module")
def make_credential(dev_manager):
    def make_cred(
        ext_inputs=None,
        options=None,
    ) -> Credential:
        pin_protocol = None
        pin_uv_param = None
        if options is not None and options["rk"]:
            client_pin = ClientPin(dev_manager.ctap2)
            pin_protocol = client_pin.protocol.VERSION
            pin_token = client_pin.get_pin_token(TEST_PIN)
            pin_uv_param = client_pin.protocol.authenticate(pin_token, EMPTY_JSON_HASH)

        extensions = (
            {PreviewSign5Extension.NAME: ext_inputs} if ext_inputs is not None else None
        )
        response = dev_manager.ctap2.make_credential(
            EMPTY_JSON_HASH,
            RP,
            USER,
            [{"type": "public-key", "alg": -7}],
            options=options,
            extensions=extensions,
            pin_uv_param=pin_uv_param,
            pin_uv_protocol=pin_protocol,
            on_keepalive=dev_manager.on_keepalive,
        )
        return Credential(
            response,
            ext_inputs.get(AuthenticatorInput.FLAGS, None) if ext_inputs else None,
            options,
            extensions,
            parse_generate_key_outputs(response),
            parse_error_outputs(response),
            parse_support_outputs(response),
        )

    return make_cred


@pytest.fixture(scope="module")
def generate_key(make_credential):
    def generate_key(
        algorithms: list[int],
        flags=0b000,
        options=None,
        extensions={},
    ) -> Credential:
        return make_credential(
            ext_inputs=generate_key_inputs(algorithms, flags), options=options
        )

    return generate_key


@pytest.fixture(scope="module")
def get_assertion(dev_manager):
    def get_assertion(
        cred: Credential,
        ext_inputs=None,
        up=False,
    ):
        response = dev_manager.ctap2.get_assertion(
            RP["id"],
            EMPTY_JSON_HASH,
            allow_list=[
                {
                    "type": "public-key",
                    "id": cred.response.auth_data.credential_data.credential_id,
                }
            ],
            options={"up": up},
            extensions={PreviewSign5Extension.NAME: ext_inputs}
            if ext_inputs is not None
            else None,
            on_keepalive=dev_manager.on_keepalive,
        )
        return (
            response,
            parse_generate_key_outputs(response),
            parse_sign_outputs(response),
            parse_error_outputs(response),
            parse_support_outputs(response),
        )

    return get_assertion


@pytest.fixture(scope="module")
def sign(get_assertion):
    def sign(
        cred: Credential,
        tbs,
        additional_args=None,
        up=False,
    ):
        response, generated_key, signature, error_code, support_list = get_assertion(
            cred, sign_inputs(cred, tbs, additional_args), up=up
        )
        return response, signature, error_code

    return sign


def if_arkg(algorithm, public_key):
    if algorithm == -65539:
        arkg_pub_seed = public_key
        assert arkg_pub_seed[3] == -65700, "Expected alg: ARKG-P256"
        assert arkg_pub_seed[-3] == -9, "Expected dkalg: ESP256"
        arkg_ikm = os.urandom(32)
        arkg_ctx = b"python-fido2.test_sign_extension_v5"
        return arkg_pub_seed.derive_public_key(arkg_ikm, arkg_ctx)
    else:
        return public_key, None


def test_register_multiple_extensions(credential_cache):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: len(cred.response.auth_data.extensions) > 1,
        ALL_ALGORITHMS,
        extensions={"hmac-secret": True, "credProtect": 1},
    )
    ext_ids = list(cred.response.auth_data.extensions.keys())
    sorted_ext_ids = sorted(ext_ids, key=lambda id: (len(id), id))
    assert ext_ids == sorted_ext_ids


def test_esp256_split(credential_cache, sign):
    algorithms = [
        -300,  # Requested assignment for ESP256-split https://www.ietf.org/archive/id/draft-lundberg-cose-two-party-signing-algs-06.html#name-ecdsa
        -70009,  # Placeholder value used by some prototypes
    ]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    tbs = os.urandom(32)
    response, signature, error_code = sign(cred, tbs)
    assert signature is not None
    assert error_code is None

    cred.public_key.verify(tbs, signature)


def test_esp256(credential_cache, sign):
    algorithms = [-9]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    tbs = os.urandom(32)
    response, signature, error_code = sign(cred, tbs)
    assert signature is not None
    assert error_code is None

    cred.public_key.verify(tbs, signature)


def test_es256(credential_cache, sign):
    algorithms = [-7]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    tbs = os.urandom(32)
    response, signature, error_code = sign(cred, tbs)
    assert signature is not None
    assert error_code is None

    cred.public_key.verify(tbs, signature)


def test_esp256_split_arkg(credential_cache, sign):
    algorithms = [
        -65539,  # Placeholder for ESP256-split-ARKG https://www.ietf.org/archive/id/draft-bradleylundberg-cfrg-arkg-10.html#name-cose-algorithms
    ]
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    tbs = os.urandom(32)
    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert signature is not None
    assert error_code is None

    public_key.verify(tbs, signature)


def test_two_keys_same_alg(credential_cache, sign):
    algorithms = ALL_ALGORITHMS
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    algorithms2 = [cred.algorithm]
    cred2 = credential_cache.make_cred_or_skip(
        lambda cred2: (
            cred2.algorithm == cred.algorithm
            and cred2.flags == 0b000
            and cred2.response.auth_data.credential_data.credential_id
            != cred.response.auth_data.credential_data.credential_id
        ),
        algorithms2,
    )
    assert cred2 is not None

    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    tbs = os.urandom(32)
    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert signature is not None
    assert error_code is None

    public_key.verify(tbs, signature)

    public_key2, _ = if_arkg(cred2.algorithm, cred2.public_key)

    assert cred2.algorithm in algorithms2
    assert cred2.algorithm == cred.algorithm
    assert cred2.key_handle != cred.key_handle
    assert cred2.public_key != cred.public_key
    assert cred2.att_obj != cred.att_obj

    with pytest.raises(cryptography.exceptions.InvalidSignature):
        public_key2.verify(tbs, signature)


def test_two_keys_different_alg(credential_cache, sign):
    algorithms = ALL_ALGORITHMS
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.algorithm in algorithms and cred.flags == 0b000,
        algorithms,
    )
    assert cred.algorithm in algorithms

    algorithms2 = [alg for alg in algorithms if alg != cred.algorithm]
    cred2 = credential_cache.make_cred_or_skip(
        lambda cred2: (
            cred2.algorithm in algorithms2
            and cred2.flags == 0b000
            and cred2.response.auth_data.credential_data.credential_id
            != cred.response.auth_data.credential_data.credential_id
            and cred2.algorithm != cred.algorithm
        ),
        algorithms2,
    )
    assert cred2 is not None

    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    tbs = os.urandom(32)
    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert signature is not None
    assert error_code is None

    public_key.verify(tbs, signature)

    public_key2, _ = if_arkg(cred2.algorithm, cred2.public_key)

    assert cred2.algorithm in algorithms2
    assert cred2.key_handle != cred.key_handle
    assert cred2.public_key != cred.public_key
    assert cred2.att_obj != cred.att_obj

    with pytest.raises(cryptography.exceptions.InvalidSignature):
        public_key2.verify(tbs, signature)


def test_register_unsupported_alg(generate_key):
    algorithms = [
        -18,  # SHAKE128, nonsensical value in this context
    ]
    cred = generate_key(algorithms)
    assert cred.error_code in [
        PreviewSign5ErrorCode.UNSUPPORTED_ALGORITHM,
        PreviewSign5ErrorCode.UNSUPPORTED_ALGORITHM_COMBINATION,
    ]
    assert cred.support is None or len(cred.support) > 0


def test_register_invalid_type_empty_input(make_credential):
    with pytest.raises(CtapError) as excinfo:
        make_credential({})
    assert excinfo.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


@pytest.mark.parametrize("flags", range(0, 256))
def test_register_invalid_type_invalid_flags(generate_key, flags):
    if flags in [0b000, 0b001, 0b100, 0b101]:
        generate_key(ALL_ALGORITHMS, flags=flags)
    else:
        with pytest.raises(CtapError) as exc_info:
            generate_key(ALL_ALGORITHMS, flags=flags)
        assert exc_info.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


def test_register_invalid_type_support_false(make_credential):
    cred = make_credential({AuthenticatorInput.SUPPORT: True})
    assert cred is not None
    with pytest.raises(CtapError) as excinfo:
        make_credential({AuthenticatorInput.SUPPORT: False})
    assert excinfo.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


def test_register_invalid_option_sign_inputs(credential_cache, make_credential):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b000, ALL_ALGORITHMS
    )
    tbs = os.urandom(32)
    with pytest.raises(CtapError) as excinfo:
        cred = make_credential(sign_inputs(cred, tbs))
    assert excinfo.value.code == CtapError.ERR.INVALID_OPTION


def test_assert_invalid_type_sign_and_generate(credential_cache, get_assertion):
    algorithms = ALL_ALGORITHMS
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b000, algorithms
    )
    tbs = os.urandom(32)

    response, generated_key, signature, error_code, support_list = get_assertion(
        cred,
        {
            **generate_key_inputs(algorithms),
        },
    )
    assert response is not None
    assert generate_key is not None
    assert signature is None
    assert error_code is None
    assert support_list is None

    response, generated_key, signature, error_code, support_list = get_assertion(
        cred,
        {
            **sign_inputs(cred, tbs),
        },
    )
    assert response is not None
    assert generated_key is None
    assert signature is not None
    assert error_code is None
    assert support_list is None

    with pytest.raises(CtapError) as excinfo:
        response, generated_key, signature, error_code, support_list = get_assertion(
            cred,
            {
                **generate_key_inputs(algorithms),
                **sign_inputs(cred, tbs),
            },
        )
    assert excinfo.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


def test_assert_invalid_type_support_false(credential_cache, get_assertion):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b000, ALL_ALGORITHMS
    )
    response, generated_key, signature, error_code, support_list = get_assertion(
        cred, {AuthenticatorInput.SUPPORT: True}
    )
    with pytest.raises(CtapError) as excinfo:
        response, generated_key, signature, error_code, support_list = get_assertion(
            cred, {AuthenticatorInput.SUPPORT: False}
        )
    assert excinfo.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


@pytest.mark.parametrize("missing_key", [AuthenticatorInput.KH, AuthenticatorInput.TBS])
def test_assert_missing_required_parameter(
    credential_cache, get_assertion, missing_key
):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b000, ALL_ALGORITHMS
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    ext_inputs = sign_inputs(cred, tbs, additional_args=args)

    response1 = get_assertion(cred, ext_inputs)
    assert response1 is not None

    mod_ext_inputs = {**ext_inputs}
    del mod_ext_inputs[missing_key]
    with pytest.raises(CtapError) as exc_info:
        get_assertion(cred, mod_ext_inputs)
    assert exc_info.value.code == CtapError.ERR.CBOR_UNEXPECTED_TYPE


def test_assert_invalid_key_handle(credential_cache, get_assertion):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b000, ALL_ALGORITHMS
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    ext_inputs = sign_inputs(cred, tbs, additional_args=args)
    response, generated_key, signature, error_code, support_list = get_assertion(
        cred, ext_inputs
    )
    assert response is not None
    assert signature is not None
    assert error_code is None

    key_handle = ext_inputs[AuthenticatorInput.KH]
    ext_inputs[AuthenticatorInput.KH] = bytes([key_handle[0] ^ 0x01]) + key_handle[1:]
    response, generated_key, signature, error_code, support_list = get_assertion(
        cred, ext_inputs
    )
    assert response is not None
    assert signature is None
    assert error_code == PreviewSign5ErrorCode.INVALID_KEY_HANDLE


def test_assert_missing_args_alg(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")

    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert response is not None
    assert signature is not None
    assert error_code is None

    del args[AuthenticatorInput.ALG]
    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert response is not None
    assert signature is None
    assert error_code == PreviewSign5ErrorCode.COSE_SIGN_ARGS_ALG_MISMATCH


def test_assert_incorrect_args_alg(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")

    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert response is not None
    assert signature is not None
    assert error_code is None

    args[AuthenticatorInput.ALG] += 1
    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert response is not None
    assert signature is None
    assert error_code == PreviewSign5ErrorCode.COSE_SIGN_ARGS_ALG_MISMATCH


def test_assert_missing_args(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")
    sign_inputs(cred, tbs, additional_args=args)

    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert response is not None
    assert signature is not None
    assert error_code is None

    response, signature, error_code = sign(cred, tbs, additional_args=None)
    assert response is not None
    assert signature is None
    assert error_code == PreviewSign5ErrorCode.COSE_SIGN_ARGS_MISSING_PARAM


def test_assert_unknown_args(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")

    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert response is not None
    assert signature is not None
    assert error_code is None

    response, signature, error_code = sign(
        cred, tbs, additional_args={**args, 42: 1337}
    )
    assert response is not None
    assert signature is None
    assert error_code == PreviewSign5ErrorCode.COSE_SIGN_ARGS_UNKNOWN_PARAM


def test_assert_invalid_cose_sign_args(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: (
            cred.algorithm == ESP256_SPLIT_ARKG_PLACEHOLDER and cred.flags == 0b000
        ),
        [ESP256_SPLIT_ARKG_PLACEHOLDER],
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)
    if args is None:
        pytest.skip("Algorithm does not use additional arguments")

    response, signature, error_code = sign(cred, tbs, additional_args=args)
    assert response is not None
    assert signature is not None
    assert error_code is None

    response, signature, error_code = sign(cred, tbs, additional_args=[])
    assert response is not None
    assert signature is None
    assert error_code == PreviewSign5ErrorCode.COSE_SIGN_ARGS_INVALID


def test_assert_up_required(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags & 0b001 == 0b001,
        ALL_ALGORITHMS,
        flags=0b001,
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    sign(cred, tbs, additional_args=args, up=True)
    with pytest.raises(CtapError) as exc_info:
        sign(cred, tbs, additional_args=args, up=False)
    assert exc_info.value.code == CtapError.ERR.UP_REQUIRED


def test_assert_uv_required(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b100,
        ALL_ALGORITHMS,
        flags=0b100,
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    with pytest.raises(CtapError) as exc_info:
        sign(cred, tbs, additional_args=args, up=False)
    assert exc_info.value.code == CtapError.ERR.PUAT_REQUIRED


def test_assert_up_uv_required(credential_cache, sign):
    cred = credential_cache.make_cred_or_skip(
        lambda cred: cred.flags == 0b101,
        ALL_ALGORITHMS,
        flags=0b101,
    )
    tbs = os.urandom(32)
    public_key, args = if_arkg(cred.algorithm, cred.public_key)

    with pytest.raises(CtapError) as exc_info:
        sign(cred, tbs, additional_args=args, up=False)
    assert exc_info.value.code == CtapError.ERR.UP_REQUIRED

    with pytest.raises(CtapError) as exc_info:
        sign(cred, tbs, additional_args=args, up=True)
    assert exc_info.value.code == CtapError.ERR.PUAT_REQUIRED
