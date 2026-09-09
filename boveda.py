#!/usr/bin/env python3
import os
import sys
import json
import tarfile
import shutil
import subprocess
import secrets
import getpass
import time
import ctypes
import fcntl
import io
import stat

from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# BOVEDA V2
#
# Argon2id + AES-256-GCM
# RAM workspace: /dev/shm
#
# Transactional save:
#   nueva boveda -> fsync -> verificar -> replace atomico
#
# Los originales nunca se eliminan.
# ============================================================

MAGIC = b"BOVEDA-V2"
VERSION = 2

VAULT_DIR = Path.home() / ".boveda"
VAULT_FILE = VAULT_DIR / "boveda.svlt"
LOCK_FILE = VAULT_DIR / ".key.lock"

# ------------------------------------------------------------
# Argon2id policy
# ------------------------------------------------------------

MIN_MEMORY_KIB = 2 * 1024 * 1024       # 2 GiB
MAX_ADAPTIVE_KIB = 1024 * 1024 * 1024  # 1 TiB

TIME_COST = 3
PARALLELISM = 1

KEY_LEN = 32
SALT_LEN = 32
NONCE_LEN = 12

# AAD authenticates the complete header.
AAD_VERSION = b"BOVEDA-VLT-AAD-2"

MAX_HEADER = 1024 * 1024

# Archive safety limits.
MAX_FILES = 100000
MAX_MEMBER_SIZE = 1 << 40              # 1 TiB


# ============================================================
# General utilities
# ============================================================

def fail(msg):
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def ram_kib():
    """
    Physical RAM reported by the Linux kernel.
    """
    try:
        with open("/proc/meminfo", "r", encoding="ascii") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
    except Exception:
        pass

    fail("No se pudo determinar la memoria RAM.")


def calculate_memory_cost():
    """
    Adaptive Argon2id memory policy.

    The value is selected when the boveda is CREATED
    and may be increased automatically during OPEN.

    The selected value is stored inside the authenticated header.

    A normal OPEN never lowers the stored KDF cost.
    """

    total_gib = ram_kib() / (1024 * 1024)
    gib = 1024 * 1024

    if total_gib < 32:
        return 2 * gib

    if total_gib < 64:
        return 8 * gib

    if total_gib < 128:
        return 16 * gib

    if total_gib < 256:
        return 32 * gib

    if total_gib < 512:
        return 64 * gib

    if total_gib < 1024:
        return 128 * gib

    if total_gib < 2048:
        return 256 * gib

    if total_gib < 3072:
        return 512 * gib

    return MAX_ADAPTIVE_KIB


def derive_key(password, salt, memory_kib, time_cost, parallelism):
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def wipe(buf):
    """
    Best-effort wipe of mutable buffers.

    Python immutable bytes cannot be reliably wiped.
    """

    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0


def try_mlockall():
    """
    Best effort: prevent process memory from being swapped.

    This may fail if RLIMIT_MEMLOCK is too restrictive.
    """

    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.mlockall(1 | 2)
    except Exception:
        pass


def try_munlockall():
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.munlockall()
    except Exception:
        pass


def fsync_dir(path):
    fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )

    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def secure_remove_tree(path):
    """
    Best-effort destruction of the RAM workspace.

    /dev/shm is tmpfs, so deleting files removes them from the
    RAM-backed filesystem. This is not a forensic guarantee.
    """

    path = Path(path)

    if not path.exists():
        return

    for root, dirs, files in os.walk(
        path,
        topdown=False,
        followlinks=False
    ):
        for name in files:
            p = Path(root) / name

            try:
                st = p.lstat()

                if stat.S_ISREG(st.st_mode):
                    with open(p, "r+b", buffering=0) as f:
                        remaining = st.st_size
                        zero = b"\x00" * (1024 * 1024)

                        while remaining:
                            chunk = min(
                                len(zero),
                                remaining
                            )

                            f.write(zero[:chunk])
                            remaining -= chunk

                        f.flush()
                        os.fsync(f.fileno())

            except Exception:
                pass

            try:
                p.unlink()
            except Exception:
                pass

        for name in dirs:
            try:
                shutil.rmtree(
                    Path(root) / name
                )
            except Exception:
                pass

    try:
        shutil.rmtree(path)
    except Exception:
        pass


def validate_relative_name(name):
    if not isinstance(name, str):
        return False

    if not name:
        return False

    p = Path(name)

    if p.is_absolute():
        return False

    if ".." in p.parts:
        return False

    if str(p) in ("", "."):
        return False

    return True


# ============================================================
# Process lock
# ============================================================

def acquire_lock():
    """
    Prevent two boveda processes from modifying/opening the same boveda.
    """

    VAULT_DIR.mkdir(
        mode=0o700,
        parents=True,
        exist_ok=True
    )

    fd = os.open(
        LOCK_FILE,
        os.O_RDWR | os.O_CREAT,
        0o600
    )

    try:
        os.fchmod(fd, 0o600)

        fcntl.flock(
            fd,
            fcntl.LOCK_EX | fcntl.LOCK_NB
        )

    except OSError:
        os.close(fd)
        fail(
            "La boveda ya esta abierta o esta siendo modificada."
        )

    return fd


# ============================================================
# Safe archive creation
# ============================================================

def create_payload(source_dir):
    """
    Create a tar archive in memory.

    Supports directories and regular files.

    Rejects:
      - symlinks
      - special files
      - unsafe paths
    """

    source_dir = Path(source_dir)

    buf = io.BytesIO()

    file_count = 0

    with tarfile.open(
        fileobj=buf,
        mode="w"
    ) as tar:

        for root, dirs, files in os.walk(
            source_dir,
            topdown=True,
            followlinks=False
        ):
            root = Path(root)

            rel_root = root.relative_to(
                source_dir
            )

            # Directories
            if str(rel_root) != ".":
                if not validate_relative_name(
                    rel_root.as_posix()
                ):
                    fail(
                        "Nombre de carpeta no permitido."
                    )

                tar.add(
                    str(root),
                    arcname=rel_root.as_posix(),
                    recursive=False
                )

            # Validate directories
            for d in list(dirs):
                p = root / d

                if p.is_symlink():
                    fail(
                        f"No se permiten enlaces simbólicos: {p}"
                    )

                if not p.is_dir():
                    fail(
                        f"Tipo de archivo no permitido: {p}"
                    )

            # Files
            for name in sorted(files):
                p = root / name

                if p.is_symlink():
                    fail(
                        f"No se permiten enlaces simbólicos: {p}"
                    )

                st = p.stat()

                if not stat.S_ISREG(st.st_mode):
                    fail(
                        f"Tipo de archivo no permitido: {p}"
                    )

                rel = p.relative_to(
                    source_dir
                ).as_posix()

                if not validate_relative_name(rel):
                    fail(
                        "Nombre de archivo/ruta no permitido."
                    )

                file_count += 1

                if file_count > MAX_FILES:
                    fail(
                        "Demasiados archivos para esta boveda."
                    )

                tar.add(
                    str(p),
                    arcname=rel,
                    recursive=False
                )

    return buf.getvalue()


# ============================================================
# Safe archive extraction
# ============================================================

def extract_payload(payload, target_dir):
    """
    Extract only safe directories and regular files.

    Never uses tar.extractall().
    """

    target_dir = Path(target_dir).resolve()

    target_dir.mkdir(
        mode=0o700,
        parents=True,
        exist_ok=False
    )

    total_size = 0
    file_count = 0

    with tarfile.open(
        fileobj=io.BytesIO(payload),
        mode="r:"
    ) as tar:

        members = tar.getmembers()

        if len(members) > MAX_FILES * 2:
            fail(
                "Contenedor manipulado."
            )

        for member in members:

            if not validate_relative_name(
                member.name
            ):
                fail(
                    "Contenedor manipulado."
                )

            if (
                member.issym()
                or member.islnk()
                or member.isdev()
                or member.isfifo()
            ):
                fail(
                    "Contenedor manipulado."
                )

            if not (
                member.isdir()
                or member.isfile()
            ):
                fail(
                    "Contenedor manipulado."
                )

            if member.isfile():

                file_count += 1

                if file_count > MAX_FILES:
                    fail(
                        "Contenedor manipulado."
                    )

                if (
                    member.size < 0
                    or member.size > MAX_MEMBER_SIZE
                ):
                    fail(
                        "Contenedor manipulado."
                    )

                total_size += member.size

                if total_size > MAX_MEMBER_SIZE:
                    fail(
                        "Contenedor manipulado."
                    )

            dest = (
                target_dir / member.name
            ).resolve()

            try:
                dest.relative_to(target_dir)
            except ValueError:
                fail(
                    "Contenedor manipulado."
                )

            if member.isdir():

                dest.mkdir(
                    mode=0o700,
                    parents=True,
                    exist_ok=True
                )

                continue

            dest.parent.mkdir(
                mode=0o700,
                parents=True,
                exist_ok=True
            )

            if (
                dest.exists()
                or dest.is_symlink()
            ):
                fail(
                    "Contenedor manipulado."
                )

            src = tar.extractfile(member)

            if src is None:
                fail(
                    "Contenedor manipulado."
                )

            with open(dest, "xb") as out:
                shutil.copyfileobj(
                    src,
                    out,
                    length=1024 * 1024
                )

            try:
                os.chmod(
                    dest,
                    member.mode & 0o700
                )
            except Exception:
                pass


# ============================================================
# Header
# ============================================================

def make_header(
    memory_kib,
    time_cost,
    parallelism,
    salt,
    nonce,
    wrapped_nonce
):

    header = {
        "magic": MAGIC.decode("ascii"),
        "version": VERSION,
        "kdf": "argon2id",
        "memory_kib": int(memory_kib),
        "time_cost": int(time_cost),
        "parallelism": int(parallelism),
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "wrapped_key_nonce": wrapped_nonce.hex(),
        "cipher": "AES-256-GCM",
        "policy": "adaptive",
    }

    return json.dumps(
        header,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def parse_header(raw):

    try:
        h = json.loads(
            raw.decode("utf-8")
        )

        if (
            h["magic"] != MAGIC.decode("ascii")
            or h["version"] != VERSION
        ):
            fail(
                "Contenedor no válido."
            )

        if (
            h["kdf"] != "argon2id"
            or h["cipher"] != "AES-256-GCM"
        ):
            fail(
                "Contenedor no válido."
            )

        memory_kib = int(
            h["memory_kib"]
        )

        time_cost = int(
            h["time_cost"]
        )

        parallelism = int(
            h["parallelism"]
        )

        if (
            memory_kib < MIN_MEMORY_KIB
            or memory_kib > MAX_ADAPTIVE_KIB
        ):
            fail(
                "Contenedor manipulado."
            )

        if not (
            1 <= time_cost <= 20
        ):
            fail(
                "Contenedor manipulado."
            )

        if not (
            1 <= parallelism <= 16
        ):
            fail(
                "Contenedor manipulado."
            )

        salt = bytes.fromhex(
            h["salt"]
        )

        nonce = bytes.fromhex(
            h["nonce"]
        )

        wrapped_nonce = bytes.fromhex(
            h["wrapped_key_nonce"]
        )

        if len(salt) != SALT_LEN:
            fail(
                "Contenedor manipulado."
            )

        if len(nonce) != NONCE_LEN:
            fail(
                "Contenedor manipulado."
            )

        if len(wrapped_nonce) != NONCE_LEN:
            fail(
                "Contenedor manipulado."
            )

        return (
            h,
            memory_kib,
            time_cost,
            parallelism,
            salt,
            nonce,
            wrapped_nonce,
        )

    except (
        KeyError,
        ValueError,
        TypeError,
        UnicodeDecodeError,
    ):
        fail(
            "Contenedor manipulado."
        )


# ============================================================
# Container I/O
# ============================================================

def read_container(path=VAULT_FILE):

    path = Path(path)

    if (
        not path.exists()
        or not path.is_file()
    ):
        fail(
            "No existe la boveda."
        )

    if path.stat().st_mode & 0o077:
        fail(
            "Permisos inseguros en la boveda."
        )

    with open(path, "rb") as f:

        raw_len = f.read(2)

        if len(raw_len) != 2:
            fail(
                "Contenedor manipulado."
            )

        magic_len = int.from_bytes(
            raw_len,
            "big"
        )

        if (
            magic_len != len(MAGIC)
            or f.read(magic_len) != MAGIC
        ):
            fail(
                "Contenedor manipulado."
            )

        b = f.read(8)

        if len(b) != 8:
            fail(
                "Contenedor manipulado."
            )

        header_len = int.from_bytes(
            b,
            "big"
        )

        if not (
            1 <= header_len <= MAX_HEADER
        ):
            fail(
                "Contenedor manipulado."
            )

        header = f.read(
            header_len
        )

        if len(header) != header_len:
            fail(
                "Contenedor manipulado."
            )

        b = f.read(4)

        if len(b) != 4:
            fail(
                "Contenedor manipulado."
            )

        wrapped_len = int.from_bytes(
            b,
            "big"
        )

        if wrapped_len != 48:
            fail(
                "Contenedor manipulado."
            )

        wrapped = f.read(
            wrapped_len
        )

        ciphertext = f.read()

        if (
            len(wrapped) != wrapped_len
            or len(ciphertext) < 16
        ):
            fail(
                "Contenedor manipulado."
            )

    return (
        header,
        wrapped,
        ciphertext
    )


# ============================================================
# Decryption
# ============================================================

def decrypt_container(path, password):

    header, wrapped, ciphertext = read_container(
        path
    )

    (
        _,
        memory_kib,
        time_cost,
        parallelism,
        salt,
        nonce,
        wrapped_nonce,
    ) = parse_header(header)

    # --------------------------------------------------------
    # Local DoS protection.
    #
    # The header is unauthenticated until GCM verifies it.
    # Therefore an attacker could otherwise put a gigantic
    # memory value in the header and force the machine to try
    # allocating it.
    # --------------------------------------------------------

    local_ram = ram_kib()

    safe_local_cap = max(
        MIN_MEMORY_KIB,
        int(local_ram * 0.70)
    )

    if memory_kib > safe_local_cap:
        fail(
            "Este equipo no tiene suficiente RAM "
            "para abrir esta boveda con seguridad."
        )

    password_key = bytearray()
    data_key = bytearray()
    plaintext = bytearray()

    try:

        password_key.extend(
            derive_key(
                password,
                salt,
                memory_kib,
                time_cost,
                parallelism
            )
        )

        # ----------------------------------------------------
        # Recover random DEK.
        # ----------------------------------------------------

        try:

            data_key.extend(
                AESGCM(
                    bytes(password_key)
                ).decrypt(
                    wrapped_nonce,
                    wrapped,
                    AAD_VERSION + header
                )
            )

        except Exception:

            fail(
                "Contraseña incorrecta "
                "o contenedor manipulado."
            )

        if len(data_key) != KEY_LEN:
            fail(
                "Contenedor manipulado."
            )

        # ----------------------------------------------------
        # Decrypt payload.
        # ----------------------------------------------------

        try:

            plaintext.extend(
                AESGCM(
                    bytes(data_key)
                ).decrypt(
                    nonce,
                    ciphertext,
                    AAD_VERSION + header
                )
            )

        except Exception:

            fail(
                "Contraseña incorrecta "
                "o contenedor manipulado."
            )

        return (
            plaintext,
            memory_kib,
            time_cost,
            parallelism
        )

    finally:

        wipe(password_key)
        wipe(data_key)


# ============================================================
# Container creation
# ============================================================

def build_container(
    password,
    payload,
    memory_kib,
    time_cost=TIME_COST,
    parallelism=PARALLELISM
):

    # New salt on every save.
    salt = secrets.token_bytes(
        SALT_LEN
    )

    # New payload nonce.
    nonce = secrets.token_bytes(
        NONCE_LEN
    )

    # New nonce for DEK wrapping.
    wrapped_nonce = secrets.token_bytes(
        NONCE_LEN
    )

    # Fresh random DEK.
    data_key = bytearray(
        secrets.token_bytes(KEY_LEN)
    )

    password_key = bytearray()

    try:

        password_key.extend(
            derive_key(
                password,
                salt,
                memory_kib,
                time_cost,
                parallelism
            )
        )

        header = make_header(
            memory_kib,
            time_cost,
            parallelism,
            salt,
            nonce,
            wrapped_nonce
        )

        # ----------------------------------------------------
        # Wrap random DEK using password-derived KEK.
        # ----------------------------------------------------

        wrapped = AESGCM(
            bytes(password_key)
        ).encrypt(
            wrapped_nonce,
            bytes(data_key),
            AAD_VERSION + header
        )

        # ----------------------------------------------------
        # Encrypt actual payload with DEK.
        # ----------------------------------------------------

        ciphertext = AESGCM(
            bytes(data_key)
        ).encrypt(
            nonce,
            payload,
            AAD_VERSION + header
        )

        # ----------------------------------------------------
        # Container:
        #
        # [2 bytes magic length]
        # [MAGIC]
        # [8 bytes header length]
        # [header]
        # [4 bytes wrapped-key length]
        # [wrapped DEK]
        # [ciphertext]
        # ----------------------------------------------------

        out = bytearray()

        out.extend(
            len(MAGIC).to_bytes(
                2,
                "big"
            )
        )

        out.extend(MAGIC)

        out.extend(
            len(header).to_bytes(
                8,
                "big"
            )
        )

        out.extend(header)

        out.extend(
            len(wrapped).to_bytes(
                4,
                "big"
            )
        )

        out.extend(wrapped)
        out.extend(ciphertext)

        return bytes(out)

    finally:

        wipe(password_key)
        wipe(data_key)


# ============================================================
# Atomic writing
# ============================================================

def atomic_write_temp_and_verify(
    container,
    password,
    temp_path
):

    temp_path = Path(temp_path)

    try:

        with open(
            temp_path,
            "xb"
        ) as f:

            os.chmod(
                temp_path,
                0o600
            )

            f.write(container)

            f.flush()

            os.fsync(
                f.fileno()
            )

        # ----------------------------------------------------
        # IMPORTANT:
        # The newly-created container is independently opened
        # and verified before it can replace the old boveda.
        # ----------------------------------------------------

        verify_file(
            temp_path,
            password
        )

    except Exception:

        try:
            temp_path.unlink()
        except Exception:
            pass

        raise


# ============================================================
# Verification
# ============================================================

def verify_file(path, password):

    plaintext, _, _, _ = decrypt_container(
        path,
        password
    )

    try:

        with tarfile.open(
            fileobj=io.BytesIO(
                bytes(plaintext)
            ),
            mode="r:"
        ) as tar:

            members = tar.getmembers()

            if len(members) > MAX_FILES * 2:
                fail(
                    "Verificación fallida: "
                    "demasiados elementos."
                )

            total_size = 0

            for member in members:

                if not validate_relative_name(
                    member.name
                ):
                    fail(
                        "Verificación fallida: "
                        "ruta inválida."
                    )

                if (
                    member.issym()
                    or member.islnk()
                    or member.isdev()
                    or member.isfifo()
                ):
                    fail(
                        "Verificación fallida: "
                        "tipo no permitido."
                    )

                if not (
                    member.isdir()
                    or member.isfile()
                ):
                    fail(
                        "Verificación fallida: "
                        "tipo no permitido."
                    )

                if member.isfile():

                    if (
                        member.size < 0
                        or member.size > MAX_MEMBER_SIZE
                    ):
                        fail(
                            "Verificación fallida: "
                            "tamaño inválido."
                        )

                    total_size += member.size

                    if total_size > MAX_MEMBER_SIZE:
                        fail(
                            "Verificación fallida: "
                            "tamaño total inválido."
                        )

    finally:

        wipe(plaintext)


# ============================================================
# Password
# ============================================================

def prompt_password(confirm=False):

    if confirm:

        p1 = getpass.getpass(
            "Nueva contraseña: "
        )

        p2 = getpass.getpass(
            "Repetir contraseña: "
        )

        if p1 != p2:
            fail(
                "Las contraseñas no coinciden."
            )

    else:

        p1 = getpass.getpass(
            "Contraseña: "
        )

    if len(p1) < 16:
        fail(
            "La contraseña debe tener "
            "al menos 16 caracteres."
        )

    return p1.encode("utf-8")


# ============================================================
# create
# ============================================================

def create_vault():

    lock_fd = acquire_lock()

    password = None
    payload = bytearray()
    container = None

    try:

        # Comprobar DESPUÉS de adquirir el lock.
        if VAULT_FILE.exists():
            fail(
                "Ya existe la boveda."
            )

        print()
        print("======================================")
        print("        BOVEDA V2")
        print("======================================")
        print()
        print("Creando boveda...")
        print()

        password = prompt_password(
            confirm=True
        )

        print()
        print("Preparando datos...")

        # Crear un TAR vacío válido.
        with io.BytesIO() as empty_tar:

            with tarfile.open(
                fileobj=empty_tar,
                mode="w"
            ):
                pass

            payload.extend(
                empty_tar.getvalue()
            )

        memory_kib = calculate_memory_cost()

        print(
            f"Argon2id: "
            f"{memory_kib / (1024 * 1024):.1f} GiB "
            f"de RAM, "
            f"t={TIME_COST}, "
            f"lanes={PARALLELISM}"
        )

        print(
            "Cifrando..."
        )

        container = build_container(
            password,
            bytes(payload),
            memory_kib
        )

        tmp = (
            VAULT_DIR
            / ".boveda.svlt.verify"
        )

        atomic_write_temp_and_verify(
            container,
            password,
            tmp
        )

        os.replace(
            tmp,
            VAULT_FILE
        )

        fsync_dir(
            VAULT_DIR
        )

        os.chmod(
            VAULT_FILE,
            0o600
        )

        print()
        print(
            "Boveda creada y verificada correctamente."
        )
        print()
        print(
            "Archivo:"
        )
        print(
            VAULT_FILE
        )
        print()

    finally:

        wipe(payload)

        if container is not None:
            del container

        if password is not None:
            del password

        try:
            fcntl.flock(
                lock_fd,
                fcntl.LOCK_UN
            )
        finally:
            os.close(lock_fd)

# ============================================================
# File manager
# ============================================================

def find_file_manager():

    candidates = [
        (
            "nautilus",
            ["nautilus", "--new-window"]
        ),
        (
            "dolphin",
            ["dolphin"]
        ),
        (
            "thunar",
            ["thunar"]
        ),
        (
            "pcmanfm",
            ["pcmanfm"]
        ),
        (
            "caja",
            ["caja"]
        ),
        (
            "nemo",
            ["nemo"]
        ),
    ]

    for binary, command in candidates:

        if shutil.which(binary):
            return command

    return None


def open_file_manager(workdir):

    command = find_file_manager()

    if command is None:
        fail(
            "No encontré un gestor de archivos compatible."
        )

    return subprocess.Popen(
        command + [str(workdir)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def wait_for_file_manager(proc):

    while proc.poll() is None:
        time.sleep(1)


# ============================================================
# Commit
# ============================================================

def commit_workspace(
    workdir,
    password,
    memory_kib,
    time_cost,
    parallelism
):

    print()
    print(
        "Guardando cambios..."
    )

    payload = bytearray()
    container = None

    tmp = (
        VAULT_DIR
        / (
            ".boveda.svlt.commit-"
            + secrets.token_hex(8)
        )
    )

    try:

        payload.extend(
            create_payload(workdir)
        )

        print(
            "Cifrando nueva boveda..."
        )

        container = build_container(
            password,
            bytes(payload),
            memory_kib,
            time_cost,
            parallelism
        )

        print(
            "Verificando nueva boveda..."
        )

        atomic_write_temp_and_verify(
            container,
            password,
            tmp
        )

        # ----------------------------------------------------
        # Atomic replacement.
        #
        # If anything before this point fails, the old boveda
        # remains untouched.
        # ----------------------------------------------------

        os.replace(
            tmp,
            VAULT_FILE
        )

        fsync_dir(
            VAULT_DIR
        )

        os.chmod(
            VAULT_FILE,
            0o600
        )

        print(
            "Cambios guardados correctamente."
        )

    finally:

        wipe(payload)

        if container is not None:
            del container

        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


# ============================================================
# OPEN
# ============================================================

def open_vault():

    if not VAULT_FILE.exists():
        fail(
            "No existe la boveda."
        )

    lock_fd = acquire_lock()

    workdir = (
        Path("/dev/shm")
        / (
            "boveda-vault-"
            + secrets.token_hex(16)
        )
    )

    proc = None
    password = None
    workspace_ready = False

    # Se inicializan antes del try para que una interrupción
    # temprana nunca provoque una referencia a variables inexistentes.
    memory_kib = None
    time_cost = None
    parallelism = None

    try:

        try_mlockall()

        password = prompt_password(
            confirm=False
        )

        print(
            "Desbloqueando la Boveda..."
        )

        (
            plaintext,
            memory_kib,
            time_cost,
            parallelism
        ) = decrypt_container(
            VAULT_FILE,
            password
        )

        # ----------------------------------------------------
        # AUTO-UPGRADE DE KDF
        #
        # Si esta máquina dispone de más RAM y la política
        # recomienda un coste Argon2id superior, la boveda se
        # actualiza automáticamente ANTES de abrirse.
        #
        # Si el upgrade falla, NO se abre la boveda.
        # ----------------------------------------------------

        recommended_memory = (
            calculate_memory_cost()
        )

        if recommended_memory > memory_kib:

            print()
            print(
                "Se detectó una configuración "
                "Argon2id más fuerte disponible."
            )

            print(
                f"Actual: "
                f"{memory_kib / (1024 * 1024):.1f} GiB"
            )

            print(
                f"Recomendada: "
                f"{recommended_memory / (1024 * 1024):.1f} GiB"
            )

            print()
            print(
                "Actualizando protección "
                "automáticamente..."
            )

            try:

                new_container = build_container(
                    password,
                    bytes(plaintext),
                    recommended_memory,
                    time_cost,
                    parallelism
                )

                upgrade_tmp = (
                    VAULT_DIR
                    / (
                        ".boveda.svlt.auto-upgrade-"
                        + secrets.token_hex(8)
                    )
                )

                try:

                    # Verificación independiente del nuevo
                    # contenedor antes de reemplazar el anterior.
                    atomic_write_temp_and_verify(
                        new_container,
                        password,
                        upgrade_tmp
                    )

                    # Reemplazo atómico.
                    os.replace(
                        upgrade_tmp,
                        VAULT_FILE
                    )

                    fsync_dir(
                        VAULT_DIR
                    )

                    os.chmod(
                        VAULT_FILE,
                        0o600
                    )

                finally:

                    try:
                        upgrade_tmp.unlink()
                    except FileNotFoundError:
                        pass

                    del new_container

                # Desde este momento la boveda ya utiliza
                # el nuevo coste.
                memory_kib = recommended_memory

                print(
                    "Protección Argon2id actualizada."
                )

            except Exception as e:

                print(
                    f"NO se pudo actualizar "
                    f"el KDF automáticamente: {e}",
                    file=sys.stderr
                )

                print(
                    "La boveda NO sera abierta.",
                    file=sys.stderr
                )

                raise SystemExit(1)

        try:

            # El contenido plaintext sigue siendo el mismo.
            # Solo cambió el contenedor/KDF.
            extract_payload(
                bytes(plaintext),
                workdir
            )

            workspace_ready = True

        finally:

            wipe(plaintext)

        print()
        print(
            "Boveda desbloqueada."
        )
        print()
        print(
            "Modificá los archivos normalmente."
        )
        print(
            "Al cerrar la ventana se guardarán "
            "y verificarán los cambios."
        )
        print()

        proc = open_file_manager(
            workdir
        )

        wait_for_file_manager(
            proc
        )

        if (
            workspace_ready
            and workdir.exists()
            and memory_kib is not None
            and time_cost is not None
            and parallelism is not None
        ):

            commit_workspace(
                workdir,
                password,
                memory_kib,
                time_cost,
                parallelism
            )

    except KeyboardInterrupt:

        print()
        print(
            "Interrupción detectada."
        )

        if (
            workspace_ready
            and workdir.exists()
            and password is not None
            and memory_kib is not None
            and time_cost is not None
            and parallelism is not None
        ):

            try:

                commit_workspace(
                    workdir,
                    password,
                    memory_kib,
                    time_cost,
                    parallelism
                )

            except Exception as e:

                print(
                    f"NO se pudieron guardar "
                    f"los cambios: {e}",
                    file=sys.stderr
                )

                print(
                    "La boveda anterior permanece intacta.",
                    file=sys.stderr
                )

    except SystemExit:

        raise

    except Exception as e:

        print(
            f"Error: {e}",
            file=sys.stderr
        )

        print(
            "La boveda permanente NO fue reemplazada.",
            file=sys.stderr
        )

        raise SystemExit(1)

    finally:

        if proc is not None:

            try:
                proc.terminate()
            except Exception:
                pass

        secure_remove_tree(
            workdir
        )

        try_munlockall()

        if password is not None:
            del password

        try:
            fcntl.flock(
                lock_fd,
                fcntl.LOCK_UN
            )
        finally:
            os.close(lock_fd)

        print()
        print(
            "Boveda bloqueada."
        )

# ============================================================
# VERIFY
# ============================================================

def verify_command():

    lock_fd = acquire_lock()
    password = None

    try:

        password = prompt_password(
            confirm=False
        )

        print()
        print(
            "Verificando boveda..."
        )

        verify_file(
            VAULT_FILE,
            password
        )

        print()
        print(
            "======================================"
        )
        print(
            "            BOVEDA OK"
        )
        print(
            "======================================"
        )
        print()
        print(
            "Contraseña válida."
        )
        print(
            "Argon2id válido."
        )
        print(
            "AES-256-GCM válido."
        )
        print(
            "Header autenticado."
        )
        print(
            "Payload autenticado."
        )
        print(
            "Estructura válida."
        )
        print()

    finally:

        if password is not None:
            del password

        fcntl.flock(
            lock_fd,
            fcntl.LOCK_UN
        )

        os.close(lock_fd)


# ============================================================
# MAIN
# ============================================================

def usage():

    print(
        """
BOVEDA V2

Uso:

  Crear Boveda:
    ./boveda.py create

  Abrir Boveda:
    ./boveda.py open

  Verificar integridad de la Boveda:
    ./boveda.py verify

Advertencia:

    Si olvidas la contraseña,
    perderas el acceso a los archivos.

    La contraseña NO se puede restablecer
    ni cambiar.

    Recordala.
"""
    )


def main():

    if os.geteuid() == 0:
        fail(
            "No ejecutes este programa como root."
        )

    if len(sys.argv) == 2:

        command = sys.argv[1]

    else:

        usage()
        return

    if command == "create":

        create_vault()

    elif command == "open":

        open_vault()

    elif command == "verify":

        verify_command()

    else:

        usage()


if __name__ == "__main__":
    main()
