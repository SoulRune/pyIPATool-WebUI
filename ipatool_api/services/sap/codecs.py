"""Apple's compression formats used inside the macOS restore image.

- LZFSE: the segments of Apple Encrypted Archives (AEA);
- LZVN: transparently compressed files (decmpfs type 8), e.g. CoreFP;
- LZBITMAP: decmpfs type 14, e.g. the dyld shared cache.

Native decoders are used when present - Apple's libcompression (macOS,
jailbroken iOS), or the ``lzfse`` / ``pyliblzfse`` packages (the reference
LZFSE implementation, which also decodes LZVN blocks). Everything else falls
back to the pure-Python decoders below (ports of go-compressions/lzfse and
deploymenttheory/go-macos-pkg lzbitmap, the decoders ipatool uses): correct,
just slower - only noticeable once, on the first asset download.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import logging
import struct
import sys
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CodecError(ValueError):
    pass


# ---------------------------------------------------------------------------
# LZVN (pure Python)
# ---------------------------------------------------------------------------


def _copy_match(out: bytearray, distance: int, length: int) -> None:
    start = len(out) - distance
    if distance <= 0 or start < 0:
        raise CodecError("lzvn: invalid match distance")
    if distance >= length:
        out += out[start:start + length]
        return
    pattern = out[start:]
    repeat, rest = divmod(length, distance)
    out += pattern * repeat + pattern[:rest]


def lzvn_decode_py(src: bytes, max_out: int) -> bytes:
    out = bytearray()
    pos, end = 0, len(src)
    previous = 0
    while pos < end:
        opc = src[pos]
        pos += 1
        if opc == 0x06:  # end of stream
            break
        if opc in (0x0E, 0x16):  # nop
            continue
        if opc >= 0xF0:  # match only
            if opc == 0xF0:
                length = src[pos] + 16
                pos += 1
            else:
                length = opc & 0x0F
            if not previous:
                raise CodecError("lzvn: match without distance")
            _copy_match(out, previous, length)
            continue
        if opc >= 0xE0:  # literal only
            if opc == 0xE0:
                length = src[pos] + 16
                pos += 1
            else:
                length = opc & 0x0F
            out += src[pos:pos + length]
            pos += length
            continue
        if 0xA0 <= opc < 0xC0:  # med_d
            b1, b2 = src[pos], src[pos + 1]
            pos += 2
            literal = (opc >> 3) & 0x03
            match = (((opc & 0x07) << 2) | (b1 & 0x03)) + 3
            distance = (b1 >> 2) | (b2 << 6)
        else:
            low = opc & 0x07
            literal = opc >> 6
            match = ((opc >> 3) & 0x07) + 3
            if low == 6:  # pre_d
                distance = previous
            elif low == 7:  # lrg_d
                distance = src[pos] | (src[pos + 1] << 8)
                pos += 2
            else:  # sml_d
                if opc >= 0xC0 and (opc & 0xF0) in (0xC0, 0xD0) and low > 5:
                    raise CodecError("lzvn: invalid opcode")
                distance = (low << 8) | src[pos]
                pos += 1
        if literal:
            out += src[pos:pos + literal]
            pos += literal
        if not distance:
            raise CodecError("lzvn: zero match distance")
        _copy_match(out, distance, match)
        previous = distance
        if len(out) > max_out:
            raise CodecError("lzvn: output overflow")
    if len(out) > max_out:
        raise CodecError("lzvn: output overflow")
    return bytes(out)


# ---------------------------------------------------------------------------
# LZFSE (pure Python)
# ---------------------------------------------------------------------------

_L_SYMBOLS, _M_SYMBOLS, _D_SYMBOLS, _LIT_SYMBOLS = 20, 20, 64, 256
_L_STATES, _M_STATES, _D_STATES, _LIT_STATES = 64, 64, 256, 1024
_L_EXTRA = (0,) * 16 + (2, 3, 5, 8)
_L_BASE = tuple(range(16)) + (16, 20, 28, 60)
_M_EXTRA = (0,) * 16 + (3, 5, 8, 11)
_M_BASE = tuple(range(16)) + (16, 24, 56, 312)
_D_EXTRA = tuple(i // 4 for i in range(64))
_D_BASE = (
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52,
    60, 76, 92, 108, 124, 156, 188, 220, 252, 316, 380, 444, 508, 636, 764, 892,
    1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092, 5116, 6140, 7164,
    8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148,
    57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
)
_FREQ_NBITS = (2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14) * 2
_FREQ_VALUE = (0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1, 0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1)


def _clz32(value: int) -> int:
    return 32 - value.bit_length()


def _decoder_table(freqs, nstates: int):
    """[(bits, symbol, delta)] per state (fse_init_decoder_table)."""
    table = [None] * nstates
    nclz = _clz32(nstates)
    offset = 0
    for symbol, freq in enumerate(freqs):
        if not freq:
            continue
        if offset + freq > nstates:
            raise CodecError("lzfse: invalid frequency table")
        k = _clz32(freq) - nclz
        j0 = ((2 * nstates) >> k) - freq
        for j in range(freq):
            if j < j0:
                table[offset + j] = (k, symbol, ((freq + j) << k) - nstates)
            else:
                table[offset + j] = (k - 1, symbol, (j - j0) << (k - 1))
        offset += freq
    return table


def _value_table(freqs, nstates: int, extra, base):
    """[(total_bits, value_bits, delta, value_base)] (fse_init_value_decoder_table)."""
    table = [None] * nstates
    nclz = _clz32(nstates)
    offset = 0
    for symbol, freq in enumerate(freqs):
        if not freq:
            continue
        if offset + freq > nstates:
            raise CodecError("lzfse: invalid frequency table")
        k = _clz32(freq) - nclz
        j0 = ((2 * nstates) >> k) - freq
        vb, vbase = extra[symbol], base[symbol]
        for j in range(freq):
            if j < j0:
                table[offset + j] = (k + vb, vb, ((freq + j) << k) - nstates, vbase)
            else:
                table[offset + j] = (k - 1 + vb, vb, (j - j0) << (k - 1), vbase)
        offset += freq
    return table


def _stream_init(payload: bytes, init_bits: int):
    """FSE input stream (read backwards from the payload's end): returns
    (accumulator, bit count, next byte position). The first load is the last
    8 bytes (7 if init_bits == 0); init_bits (<= 0) is the number of padding
    bits at the top of it, which must be zero."""
    end = len(payload)
    if init_bits != 0:
        if end < 8:
            raise CodecError("fse: stream too short")
        accum = int.from_bytes(payload[end - 8:end], "little")
        nbits = 64 + init_bits
        ptr = end - 8
    else:
        if end < 7:
            if end == 0:
                return 0, 0, 0
            raise CodecError("fse: stream too short")
        accum = int.from_bytes(payload[end - 7:end], "little")
        nbits = 56
        ptr = end - 7
    if accum >> nbits:
        raise CodecError("fse: invalid stream (non-zero padding)")
    return accum, nbits, ptr


def _lzfse_block(header, payload: bytes, out: bytearray) -> None:
    (n_raw, n_literals, n_matches, n_lit_payload, n_lmd_payload, literal_bits, literal_states,
     lmd_bits, l_state, m_state, d_state, l_freq, m_freq, d_freq, lit_freq) = header
    if n_lit_payload + n_lmd_payload > len(payload):
        raise CodecError("lzfse: payload too short")
    lit_table = _decoder_table(lit_freq, _LIT_STATES)
    l_table = _value_table(l_freq, _L_STATES, _L_EXTRA, _L_BASE)
    m_table = _value_table(m_freq, _M_STATES, _M_EXTRA, _M_BASE)
    d_table = _value_table(d_freq, _D_STATES, _D_EXTRA, _D_BASE)
    from_bytes = int.from_bytes

    # Literals: four interleaved FSE states over one backward bit stream.
    data = payload[:n_lit_payload]
    accum, nbits, ptr = _stream_init(data, literal_bits)
    s0, s1, s2, s3 = literal_states
    literals = bytearray(n_literals)
    table = lit_table
    for i in range(0, n_literals, 4):
        if nbits < 40 and ptr > 0:
            take = min(ptr, (63 - nbits) >> 3)
            accum = (accum << (8 * take)) | from_bytes(data[ptr - take:ptr], "little")
            nbits += 8 * take
            ptr -= take
        k, sym, delta = table[s0]
        nbits -= k
        s0 = delta + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i] = sym
        k, sym, delta = table[s1]
        nbits -= k
        s1 = delta + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i + 1] = sym
        k, sym, delta = table[s2]
        nbits -= k
        s2 = delta + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i + 2] = sym
        k, sym, delta = table[s3]
        nbits -= k
        s3 = delta + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i + 3] = sym

    data = payload[n_lit_payload:n_lit_payload + n_lmd_payload]
    accum, nbits, ptr = _stream_init(data, lmd_bits)
    block_start = len(out)
    lit_pos = 0
    distance = 0
    for _ in range(n_matches):
        if nbits < 56 and ptr > 0:
            take = min(ptr, (63 - nbits) >> 3)
            accum = (accum << (8 * take)) | from_bytes(data[ptr - take:ptr], "little")
            nbits += 8 * take
            ptr -= take
        total, vb, delta, vbase = l_table[l_state]
        nbits -= total
        bits = accum >> nbits
        accum &= (1 << nbits) - 1
        l_state = delta + (bits >> vb)
        literal = vbase + (bits & ((1 << vb) - 1))

        total, vb, delta, vbase = m_table[m_state]
        nbits -= total
        bits = accum >> nbits
        accum &= (1 << nbits) - 1
        m_state = delta + (bits >> vb)
        match = vbase + (bits & ((1 << vb) - 1))

        if nbits < 32 and ptr > 0:
            take = min(ptr, (63 - nbits) >> 3)
            accum = (accum << (8 * take)) | from_bytes(data[ptr - take:ptr], "little")
            nbits += 8 * take
            ptr -= take
        total, vb, delta, vbase = d_table[d_state]
        nbits -= total
        bits = accum >> nbits
        accum &= (1 << nbits) - 1
        d_state = delta + (bits >> vb)
        new_distance = vbase + (bits & ((1 << vb) - 1))
        if new_distance:
            distance = new_distance

        if literal:
            out += literals[lit_pos:lit_pos + literal]
            lit_pos += literal
        if match:
            start = len(out) - distance
            if distance <= 0 or start < 0:
                raise CodecError("lzfse: invalid match distance")
            if distance >= match:
                out += out[start:start + match]
            else:
                pattern = out[start:]
                repeat, rest = divmod(match, distance)
                out += pattern * repeat + pattern[:rest]
    if len(out) - block_start != n_raw:
        raise CodecError("lzfse: decoded block size mismatch")


def _v1_header(src: bytes, pos: int):
    fields = struct.unpack_from("<7Ii4HiHHH", src, pos)
    (_magic, n_raw, _n_payload, n_literals, n_matches, n_lit_payload, n_lmd_payload, literal_bits,
     s0, s1, s2, s3, lmd_bits, l_state, m_state, d_state) = fields
    freqs = struct.unpack_from("<360H", src, pos + 52)
    l_freq = freqs[:20]
    m_freq = freqs[20:40]
    d_freq = freqs[40:104]
    lit_freq = freqs[104:]
    header = (n_raw, n_literals, n_matches, n_lit_payload, n_lmd_payload, literal_bits, (s0, s1, s2, s3),
              lmd_bits, l_state, m_state, d_state, l_freq, m_freq, d_freq, lit_freq)
    return header, 772


def _v2_header(src: bytes, pos: int):
    n_raw = struct.unpack_from("<I", src, pos + 4)[0]
    v0, v1, v2 = struct.unpack_from("<3Q", src, pos + 8)
    n_literals = v0 & 0xFFFFF
    n_lit_payload = (v0 >> 20) & 0xFFFFF
    n_matches = (v0 >> 40) & 0xFFFFF
    literal_bits = ((v0 >> 60) & 7) - 7
    literal_states = tuple((v1 >> (i * 10)) & 0x3FF for i in range(4))
    n_lmd_payload = (v1 >> 40) & 0xFFFFF
    lmd_bits = ((v1 >> 60) & 7) - 7
    header_size = v2 & 0xFFFFFFFF
    l_state = (v2 >> 32) & 0x3FF
    m_state = (v2 >> 42) & 0x3FF
    d_state = (v2 >> 52) & 0x3FF
    if header_size < 32 or pos + header_size > len(src):
        raise CodecError("lzfse: invalid V2 header size")
    if l_state >= _L_STATES or m_state >= _M_STATES or d_state >= _D_STATES or n_literals & 3:
        raise CodecError("lzfse: invalid V2 header")
    data = src[pos + 32:pos + header_size]
    accum = int.from_bytes(data, "little")
    bits_left = len(data) * 8
    freqs: List[int] = []
    for _ in range(_L_SYMBOLS + _M_SYMBOLS + _D_SYMBOLS + _LIT_SYMBOLS):
        low = accum & 0x1F
        nbits = _FREQ_NBITS[low]
        if nbits > bits_left:
            raise CodecError("lzfse: truncated frequency table")
        if nbits == 8:
            freq = 8 + ((accum >> 4) & 0xF)
        elif nbits == 14:
            freq = 24 + ((accum >> 4) & 0x3FF)
        else:
            freq = _FREQ_VALUE[low]
        accum >>= nbits
        bits_left -= nbits
        freqs.append(freq)
    header = (n_raw, n_literals, n_matches, n_lit_payload, n_lmd_payload, literal_bits, literal_states,
              lmd_bits, l_state, m_state, d_state, freqs[:20], freqs[20:40], freqs[40:104], freqs[104:])
    return header, header_size


def lzfse_decode_py(src: bytes) -> bytes:
    out = bytearray()
    pos = 0
    while pos + 4 <= len(src):
        magic = src[pos:pos + 4]
        if magic == b"bvx$":
            return bytes(out)
        if magic == b"bvx-":
            size = struct.unpack_from("<I", src, pos + 4)[0]
            out += src[pos + 8:pos + 8 + size]
            pos += 8 + size
        elif magic in (b"bvx1", b"bvx2"):
            header, size = (_v1_header if magic == b"bvx1" else _v2_header)(src, pos)
            pos += size
            end = pos + header[3] + header[4]
            if end > len(src):
                raise CodecError("lzfse: block payload truncated")
            _lzfse_block(header, src[pos:end], out)
            pos = end
        elif magic == b"bvxn":
            n_raw, n_payload = struct.unpack_from("<II", src, pos + 4)
            pos += 12
            out += lzvn_decode_py(src[pos:pos + n_payload], n_raw)
            pos += n_payload
        else:
            raise CodecError("lzfse: unknown block magic")
    raise CodecError("lzfse: stream has no end marker")


# ---------------------------------------------------------------------------
# LZBITMAP (pure Python)
# ---------------------------------------------------------------------------


def lzbitmap_decode_py(src: bytes) -> bytes:
    if src[:4] != b"ZBM\x09":
        raise CodecError("lzbitmap: bad magic")
    out = bytearray()
    pos = 4
    while True:
        if pos + 6 > len(src):
            raise CodecError("lzbitmap: truncated chunk header")
        length = src[pos] | (src[pos + 1] << 8) | (src[pos + 2] << 16)
        decompressed = src[pos + 3] | (src[pos + 4] << 8) | (src[pos + 5] << 16)
        end = pos + length
        if length < 6 or end > len(src) or decompressed > 0x8000:
            raise CodecError("lzbitmap: invalid chunk")
        if decompressed == 0:
            return bytes(out)
        if length == decompressed + 6:
            out += src[pos + 6:end]
        else:
            _lzbitmap_chunk(src, pos, end, length, decompressed, out)
        pos = end


def _lzbitmap_chunk(src: bytes, pos: int, end: int, length: int, decompressed: int, out: bytearray) -> None:
    def u24(at):
        return src[at] | (src[at + 1] << 8) | (src[at + 2] << 16)

    if length < 15 or length < 17:
        raise CodecError("lzbitmap: chunk too short")
    data = pos + 15
    off1, off2, off3 = u24(pos + 6), u24(pos + 9), u24(pos + 12)
    if max(off1, off2, off3) >= length:
        raise CodecError("lzbitmap: metadata offset outside the chunk")
    meta1, meta2, meta3 = pos + off1, pos + off2, pos + off3
    tail = int.from_bytes(src[end - 17:end], "little")
    bitmaps = []
    for i in range(12):
        bits = (tail >> (10 * i)) & 0x3FF
        period_bytes = bits >> 8
        if period_bytes > 2:
            raise CodecError("lzbitmap: invalid bitmap descriptor")
        bitmaps.append((bits & 0xFF, period_bytes))

    nibbles = src[meta3:end]
    nib_index = 0  # index into the nibble sequence (low nibble first)
    written = 0
    period = 8
    chunk_start = len(out)

    def nibble(i):
        byte = nibbles[i >> 1]
        return (byte >> 4) if i & 1 else (byte & 0xF)

    while written < decompressed:
        number = nibble(nib_index)
        nib_index += 1
        repeat = 1
        if decompressed - written > 8:
            following = nibble(nib_index)
            if following == 0xF:
                nib_index += 1
                repeat = 4
                while following == 0xF:
                    following = nibble(nib_index)
                    nib_index += 1
                    repeat += following
        for _ in range(repeat):
            if number == 0xF:
                raise CodecError("lzbitmap: repetition marker used as a bitmap")
            if number > 2:
                bitmap, period_bytes = bitmaps[number - 3]
            else:
                bitmap, period_bytes = src[meta2], number
                meta2 += 1
            if period_bytes:
                period = int.from_bytes(src[meta1:meta1 + period_bytes], "little")
                meta1 += period_bytes
            if period == 0:
                raise CodecError("lzbitmap: zero period")
            count = min(8, decompressed - written)
            if bitmap == 0xFF and count == 8:
                out += src[data:data + 8]
                data += 8
            elif bitmap == 0 and period >= 8:
                start = len(out) - period
                if start < 0:
                    raise CodecError("lzbitmap: period reaches before the output")
                out += out[start:start + count]
            else:
                for i in range(count):
                    if bitmap & (1 << i):
                        out.append(src[data])
                        data += 1
                    else:
                        if len(out) < period:
                            raise CodecError("lzbitmap: period reaches before the output")
                        out.append(out[-period])
            written += count
    if len(out) - chunk_start != decompressed:
        raise CodecError("lzbitmap: chunk size mismatch")


# ---------------------------------------------------------------------------
# Native backends and the public API
# ---------------------------------------------------------------------------

_COMPRESSION_LZFSE = 0x801
_COMPRESSION_LZBITMAP = 0x702


def _libcompression():
    if sys.platform not in ("darwin", "ios"):
        return None
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("compression") or "/usr/lib/libcompression.dylib")
        function = lib.compression_decode_buffer
    except (OSError, AttributeError):
        return None
    function.restype = ctypes.c_size_t
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_int]

    def decode(data: bytes, size: int, algorithm: int) -> Optional[bytes]:
        buffer = ctypes.create_string_buffer(size + 1)
        produced = function(buffer, size + 1, data, len(data), None, algorithm)
        return buffer.raw[:produced] if produced == size else None

    return decode


def _lzfse_package() -> Optional[Callable[[bytes], bytes]]:
    for module_name in ("lzfse", "liblzfse"):
        try:
            module = __import__(module_name)
            decompress = module.decompress
        except Exception:  # noqa: BLE001 - not installed / broken build
            continue
        try:
            if decompress(b"bvx-\x03\x00\x00\x00abcbvx$") == b"abc":
                return decompress
        except Exception:  # noqa: BLE001
            continue
    return None


_NATIVE: Optional[Tuple[object, object]] = None


def _native():
    global _NATIVE
    if _NATIVE is None:
        _NATIVE = (_libcompression(), _lzfse_package())
        apple, package = _NATIVE
        if apple is None and package is None:
            logger.info("no native LZFSE decoder (install the 'lzfse' package for faster first-time setup)")
    return _NATIVE


def lzfse_decompress(data: bytes, expected_size: Optional[int] = None) -> bytes:
    apple, package = _native()
    if apple is not None and expected_size is not None:
        result = apple(data, expected_size, _COMPRESSION_LZFSE)
        if result is not None:
            return result
    if package is not None:
        try:
            return package(data)
        except Exception as exc:  # noqa: BLE001 - fall back to the Python decoder
            logger.debug("native LZFSE failed: %s", exc)
    return lzfse_decode_py(data)


def lzvn_decompress(data: bytes, max_size: int) -> bytes:
    apple, package = _native()
    if apple is not None or package is not None:
        # The LZFSE container has an LZVN block type: wrap and decode natively.
        wrapped = b"bvxn" + struct.pack("<II", max_size, len(data)) + data + b"bvx$"
        if package is not None:
            try:
                result = package(wrapped)
                if len(result) <= max_size:
                    return result
            except Exception as exc:  # noqa: BLE001
                logger.debug("native LZVN failed: %s", exc)
        elif apple is not None:
            result = apple(wrapped, max_size, _COMPRESSION_LZFSE)
            if result is not None:
                return result
    return lzvn_decode_py(data, max_size)


def lzbitmap_decompress(data: bytes, expected_size: int) -> bytes:
    apple, _ = _native()
    if apple is not None:
        result = apple(data, expected_size, _COMPRESSION_LZBITMAP)
        if result is not None:
            return result
    return lzbitmap_decode_py(data)
