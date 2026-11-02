"""Read-only WCDB key scanner, adapted from jiatj/wechatapi (Apache-2.0).
See THIRD_PARTY_NOTICES.md. Modified: isolated API; no cached keys; fixed HANDLE types.
"""
import ctypes,hashlib,hmac as hmac_mod,struct,re
from ctypes import wintypes
from typing import Dict,List,Optional
PAGE_SZ=4096
RESERVE_SZ=80
CONFIG_CIPHER_NAME=b"com.Tencent.WCDB.Config.Cipher"
CONFIG_XOR_MASK=bytes.fromhex("d2c7442458020000004889442450488b450048844c2448488944254048584c24")
HEX_LITERAL_RE=re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
class _MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("__alignment1", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("__alignment2", wintypes.DWORD),
    ]
_k32=ctypes.WinDLL("kernel32",use_last_error=True)
_k32.OpenProcess.restype=wintypes.HANDLE
_k32.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
_k32.CloseHandle.argtypes=[wintypes.HANDLE]
_k32.CloseHandle.restype=wintypes.BOOL
_k32.VirtualQueryEx.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.POINTER(_MBI),ctypes.c_size_t]
_k32.VirtualQueryEx.restype=ctypes.c_size_t
_k32.ReadProcessMemory.argtypes=[wintypes.HANDLE,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.POINTER(ctypes.c_size_t)]
_k32.ReadProcessMemory.restype=wintypes.BOOL
def _pbkdf2(passwd: bytes, salt: bytes, iters: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", passwd, salt, iters, dklen=32)
def _verify_enc_key(enc_key: bytes, page1: bytes, salt: Optional[bytes] = None) -> bool:
    """验证 enc_key 是否为 page1 的 SQLCipher 4 密钥。

    - enc_key 为 32 字节裸 key：默认用文件头前 16 字节作 salt（标准形式）；
    - enc_key 为 48 字节 key+salt：显式 salt 优先于文件头（明文头模式）；
    - 也允许单独传 salt 参数覆盖（供提取逻辑按 96hex 拆分尝试）。
    """
    if len(page1) < PAGE_SZ:
        return False
    if len(enc_key) == 48 and salt is None:
        enc_key, salt = enc_key[:32], enc_key[32:]
    if salt is None:
        salt = page1[:16]
    elif len(salt) != 16:
        return False
    mac_salt = bytes(b ^ 0x3A for b in salt)
    mac_key = _pbkdf2(enc_key, mac_salt, 2)
    hmac_data = page1[16: PAGE_SZ - RESERVE_SZ + 16]
    stored_hmac = page1[PAGE_SZ - 64: PAGE_SZ]
    hm = hmac_mod.new(mac_key, hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == stored_hmac

class KeyScanner:
    def __init__(self, files):
        self._db_files=files
    def extract_keys(self) -> Dict[str, bytes]:
            """从 Weixin.exe 进程内存扫描 Config.Cipher 对象，提取各库密钥"""
            pids = self._find_weixin_pids()
            if not pids:
                raise RuntimeError("未检测到 Weixin.exe，请先登录微信再运行")
            keys: Dict[str, bytes] = {}
            tested: set = set()
            for pid in pids:
                keys.update(self._extract_keys_pid(pid, tested))
                if len(keys) >= len(self._db_files):
                    break
            return keys
    def _find_weixin_pids(self) -> List[int]:
            import subprocess

            try:
                r = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except OSError:
                return []
            pids = []
            for line in r.stdout.strip().splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 2 and parts[1].isdigit():
                    pids.append(int(parts[1]))
            return pids
    def _extract_keys_pid(self, pid: int, tested: set) -> Dict[str, bytes]:
            h = _k32.OpenProcess(0x0010 | 0x0400, False, pid)
            if not h:
                return {}
            try:
                def read(addr: int, n: int):
                    buf = ctypes.create_string_buffer(n)
                    br = ctypes.c_size_t(0)
                    if _k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(br)) and br.value:
                        return buf.raw[: br.value]
                    return None

                needles = self._find_bytes(h, read, CONFIG_CIPHER_NAME)
                pairs = [
                    struct.pack("<Q", addr) + struct.pack("<Q", len(CONFIG_CIPHER_NAME))
                    for addr in needles
                ]
                keys: Dict[str, bytes] = {}
                for pair in pairs:
                    for qaddr in self._find_bytes(h, read, pair):
                        node = read(qaddr - 0x10, 0x50)
                        if not node or len(node) < 0x40:
                            continue
                        if struct.unpack_from("<Q", node, 0x10)[0] not in needles:
                            continue
                        if struct.unpack_from("<Q", node, 0x18)[0] != len(CONFIG_CIPHER_NAME):
                            continue
                        config_ptr = struct.unpack_from("<Q", node, 0x28)[0]
                        if not (0x10000 <= config_ptr < 0x800000000000):
                            continue
                        obj = read(config_ptr + 0x88, 0x28)
                        if not obj or len(obj) < 0x18:
                            continue
                        data_ptr = struct.unpack_from("<Q", obj, 0x8)[0]
                        data_len = struct.unpack_from("<Q", obj, 0x10)[0]
                        if not (0 < data_len <= 1024 and 0x10000 <= data_ptr < 0x800000000000):
                            continue
                        blob = read(data_ptr, int(data_len))
                        if not blob or len(blob) != data_len:
                            continue
                        decoded = bytes(
                            v ^ CONFIG_XOR_MASK[i % len(CONFIG_XOR_MASK)]
                            for i, v in enumerate(blob)
                        )
                        for m in HEX_LITERAL_RE.finditer(decoded):
                            run = m.group(1).decode().lower()
                            starts = [0]
                            if len(run) > 96:
                                starts += list(range(0, len(run) - 63, 32))
                                starts.append(len(run) - 64)
                            for s in dict.fromkeys(starts):
                                if s + 64 > len(run):
                                    continue
                                cand = bytes.fromhex(run[s:s + 64])
                                if cand in tested or not self._probable_key(cand):
                                    continue
                                tested.add(cand)
                                # 96hex 形式：后 32 hex 是显式 salt（Raw Key with
                                # Explicit Salt），与文件头 salt 都要尝试
                                explicit = None
                                if s + 96 <= len(run):
                                    explicit = bytes.fromhex(run[s + 64: s + 96])
                                salt_choices = [None]
                                if explicit:
                                    salt_choices.append(explicit)
                                for salt_opt in salt_choices:
                                    for rel, path, _ in self._db_files:
                                        if rel in keys:
                                            continue
                                        with open(path, "rb") as f:
                                            page1 = f.read(PAGE_SZ)
                                        if _verify_enc_key(cand, page1, salt=salt_opt):
                                            # 显式 salt 通过 → 存 key+salt（明文头模式）；
                                            # 文件头 salt 通过 → 存裸 key
                                            keys[rel] = cand + (salt_opt or b"")
                                            break
            finally:
                _k32.CloseHandle(h)
            return keys
    @staticmethod
    def _probable_key(b: bytes) -> bool:
            return (
                len(b) == 32
                and len(set(b)) >= 15
                and b not in {b"\x00" * 32, b"\xff" * 32}
            )
    @staticmethod
    def _find_bytes(h, read, needle: bytes) -> List[int]:
            hits = []
            addr = 0
            while True:
                mbi = _MBI()
                r = _k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if r == 0:
                    break
                if (
                    mbi.State == 0x1000
                    and (mbi.Protect & 0xFF) & 0xE6
                    and not (mbi.Protect & 0x100)
                    and 0 < mbi.RegionSize < 0x10000000
                ):
                    buf = read(mbi.BaseAddress or 0, mbi.RegionSize)
                    if buf:
                        base = mbi.BaseAddress or 0
                        pos = 0
                        while True:
                            pos = buf.find(needle, pos)
                            if pos < 0:
                                break
                            hits.append(base + pos)
                            pos += 1
                addr = (mbi.BaseAddress or 0) + mbi.RegionSize
            return hits
