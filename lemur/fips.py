import ctypes
import ctypes.util
import logging
import os
import sys
from types import SimpleNamespace


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class OpensslFipsStatus:
    # Represents OpenSSL version `3.0.0`, according to the format used by `OpenSSL_version_num`.
    # Because OpenSSL 3.x reworks FIPS mode significantly, we target only OpenSSL 3.x,
    # and our minimum permitted version is OpenSSL 3.0.0.
    _OPENSSL_MINIMUM_VERSION = 0x3_00_00_00_0

    def __init__(self) -> None:
        self._init_ffi()

    def _init_ffi(self) -> None:
        ffi_init = {
            "darwin": self._init_ffi_darwin,
            "linux": self._init_ffi_linux,
        }
        ffi_init[sys.platform]()

    def _init_ffi_darwin(self) -> None:
        """Initialize the FFI structure for darwin.

        Since we cannot currently enable FIPS mode on macOS,
        we stub out the structure we need so that the rest of the methods can work.
        """
        self._ffi = SimpleNamespace(
            types=SimpleNamespace(
                p_OSSL_LIB_CTX=None,
                p_OSSL_PROVIDER=None,
            ),
            functions=SimpleNamespace(
                EVP_default_properties_enable_fips=None,
                EVP_default_properties_is_fips_enabled=None,
                OSSL_PROVIDER_load=None,
                OpenSSL_version=None,
                OpenSSL_version_num=None,
            ),
            libraries=SimpleNamespace(
                libcrypto=None,
            ),
            constants=SimpleNamespace(
                OPENSSL_VERSION=None,
            ),
        )

    def _init_ffi_linux(self) -> None:
        self._ffi = SimpleNamespace()

        self._ffi.types = SimpleNamespace()
        # OSSL_LIB_CTX *
        # https://docs.openssl.org/3.4/man3/OSSL_LIB_CTX/#synopsis
        self._ffi.types.p_OSSL_LIB_CTX = ctypes.c_void_p
        # OSSL_PROVIDER *
        # https://docs.openssl.org/3.4/man3/OSSL_PROVIDER/#synopsis
        self._ffi.types.p_OSSL_PROVIDER = ctypes.c_void_p

        self._ffi.constants = SimpleNamespace()
        # https://github.com/openssl/openssl/blob/c262cc0c0444f617387adac3ed4cad9f05f9c526/include/openssl/crypto.h.in#L164
        self._ffi.constants.OPENSSL_VERSION = 0

        self._ffi.libraries = SimpleNamespace()

        try:
            self._ffi.libraries.libcrypto = ctypes.CDLL(
                ctypes.util.find_library("crypto")
            )
        except OSError:
            self._ffi.libraries.libcrypto = None

        self._ffi.functions = SimpleNamespace()

        if self._ffi.libraries.libcrypto is not None:
            try:
                # https://docs.openssl.org/3.4/man3/OpenSSL_version/#functions
                self._ffi.functions.OpenSSL_version_num = (
                    self._ffi.libraries.libcrypto.OpenSSL_version_num
                )
                self._ffi.functions.OpenSSL_version_num.argtypes = ()
                self._ffi.functions.OpenSSL_version_num.restype = ctypes.c_ulong
            except AttributeError:
                self._ffi.functions.OpenSSL_version_num = None

        if self._ffi.libraries.libcrypto is not None:
            try:
                # https://docs.openssl.org/3.4/man3/OpenSSL_version/#functions
                self._ffi.functions.OpenSSL_version = (
                    self._ffi.libraries.libcrypto.OpenSSL_version
                )
                self._ffi.functions.OpenSSL_version.argtypes = (ctypes.c_int,)
                self._ffi.functions.OpenSSL_version.restype = ctypes.c_char_p
            except AttributeError:
                self._ffi.functions.OpenSSL_version = None

        if self._ffi.libraries.libcrypto is not None:
            try:
                # https://docs.openssl.org/3.4/man3/OSSL_PROVIDER/#functions
                self._ffi.functions.OSSL_PROVIDER_load = (
                    self._ffi.libraries.libcrypto.OSSL_PROVIDER_load
                )
                self._ffi.functions.OSSL_PROVIDER_load.argtypes = (
                    self._ffi.types.p_OSSL_LIB_CTX,
                    ctypes.c_char_p,
                )
                self._ffi.functions.OSSL_PROVIDER_load.restype = (
                    self._ffi.types.p_OSSL_PROVIDER
                )
            except AttributeError:
                self._ffi.functions.OSSL_PROVIDER_load = None

        if self._ffi.libraries.libcrypto is not None:
            try:
                # https://docs.openssl.org/3.4/man3/EVP_set_default_properties/
                self._ffi.functions.EVP_default_properties_is_fips_enabled = (
                    self._ffi.libraries.libcrypto.EVP_default_properties_is_fips_enabled
                )
                self._ffi.functions.EVP_default_properties_is_fips_enabled.argtypes = (
                    self._ffi.types.p_OSSL_LIB_CTX,
                )
                self._ffi.functions.EVP_default_properties_is_fips_enabled.restype = (
                    ctypes.c_int
                )
            except AttributeError:
                self._ffi.functions.EVP_default_properties_is_fips_enabled = None

        if self._ffi.libraries.libcrypto is not None:
            try:
                self._ffi.functions.EVP_default_properties_enable_fips = (
                    self._ffi.libraries.libcrypto.EVP_default_properties_enable_fips
                )
                self._ffi.functions.EVP_default_properties_enable_fips.argtypes = (
                    self._ffi.types.p_OSSL_LIB_CTX,
                    ctypes.c_int,
                )
                self._ffi.functions.EVP_default_properties_enable_fips.restype = (
                    ctypes.c_int
                )
            except AttributeError:
                self._ffi.functions.EVP_default_properties_enable_fips = None

    def debug_openssl_version(self) -> dict[str, str]:
        result = {}
        if (
            self._ffi.libraries.libcrypto is not None
            and self._ffi.functions.OpenSSL_version is not None
        ):
            # Only `OPENSSL_VERSION` is guaranteed across both OpenSSL major versions 1 and 3.
            # This will ensure that, even on OpenSSL major version 1, we get a meaningful result.
            openssl_version = self._ffi.functions.OpenSSL_version(
                self._ffi.constants.OPENSSL_VERSION
            )
            result["openssl_version"] = openssl_version
        return result

    def check_openssl_version(self) -> bool:
        """Checks that the current OpenSSL version (as dynamically loaded by Python) is new enough for FIPS purposes."""
        if not (
            self._ffi.libraries.libcrypto is not None
            and self._ffi.functions.OpenSSL_version_num is not None
        ):
            return False
        return (
            self._ffi.functions.OpenSSL_version_num() >= self._OPENSSL_MINIMUM_VERSION
        )

    def debug_fips_status(self) -> dict[str, bool]:
        result = {}
        if (
            self._ffi.libraries.libcrypto is not None
            and self._ffi.functions.EVP_default_properties_is_fips_enabled is not None
        ):
            default_context_is_fips_enabled = (
                self._ffi.functions.EVP_default_properties_is_fips_enabled(None) == 1
            )
            result["default_context_is_fips_enabled"] = default_context_is_fips_enabled
        return result

    def check_fips_enabled(self) -> bool:
        """Checks that the current OpenSSL (as dynamically loaded by Python) is FIPS mode enabled."""
        if not (
            self.check_openssl_version()
            and self._ffi.libraries.libcrypto is not None
            and self._ffi.functions.EVP_default_properties_is_fips_enabled is not None
        ):
            return False
        return self._ffi.functions.EVP_default_properties_is_fips_enabled(None) == 1

    def _load_fips_provider(self) -> bool:
        if not (
            self._ffi.libraries.libcrypto is not None
            and self._ffi.functions.OSSL_PROVIDER_load is not None
        ):
            return False
        return self._ffi.functions.OSSL_PROVIDER_load(None, b"fips") is not None

    def _default_properties_enable_fips(self) -> bool:
        if not (
            self._ffi.libraries.libcrypto is not None
            and self._ffi.functions.EVP_default_properties_enable_fips is not None
        ):
            return False
        return self._ffi.functions.EVP_default_properties_enable_fips(None, 1) == 1

    def enable_fips(self) -> bool:
        """Enables FIPS mode for the current OpenSSL (as dynamically loaded by Python)."""
        return self._load_fips_provider() and self._default_properties_enable_fips()

    def must_enable_fips_if_needed(self) -> bool:
        """Enables FIPS mode for the current OpenSSL if FIPS_ENABLED env var is set to true."""
        logging.info("Enabling FIPS mode on OpenSSL if needed...")

        version_info_debug = self.debug_openssl_version()
        logging.info("openssl_version_info = [%s]", version_info_debug)

        fips_status_debug = self.debug_fips_status()
        logging.info("openssl_fips_status = [%s]", fips_status_debug)

        must_enable_fips = (
            os.environ.get("FIPS_ENABLED", "false").lower().strip() == "true"
        )
        if must_enable_fips:
            logging.info(
                "Detected that FIPS mode on OpenSSL is needed, attempting to enable..."
            )
            enable_fips_result = self.enable_fips()
            logging.info("enable_fips_result = [%s]", enable_fips_result)
            if enable_fips_result:
                logging.info("FIPS mode on OpenSSL successfully enabled")
                fips_status_debug = self.debug_fips_status()
                logging.info("openssl_fips_status = [%s]", fips_status_debug)
                return True
            logging.error(
                "Failed to enable FIPS mode on OpenSSL. Potentially unsafe and inconsistent state. Exiting."
            )
            sys.exit(1)
        else:
            logging.info(
                "FIPS mode on OpenSSL is NOT needed, it will NOT be enabled..."
            )
            return False


instance = OpensslFipsStatus()
