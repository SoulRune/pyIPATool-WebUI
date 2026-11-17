"""Swift runtime services: strings, casts, metadata lookups, dictionaries,
hashing and structured concurrency.

Port of ipatool ``internal/store/emulator`` swift.go, dictionary.go,
hashing.go and async.go (ipatool 2.8, MIT). Mixed into ``runtime.Runtime``.
All allocations live until the VM closes, so Swift retains/releases are
no-ops.
"""
from __future__ import annotations

import re
import struct
import unicodedata
from typing import Dict, List

from .goutil import GoURL, canonical_header_key, url_join_path

U64 = (1 << 64) - 1
_MEMCPY = re.compile(r"^swift_memcpy(\d+)_(\d+)")


def _rotl(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (64 - bits))) & U64


def _sip_round(v: List[int]) -> None:
    v[0] = (v[0] + v[1]) & U64
    v[1] = _rotl(v[1], 13) ^ v[0]
    v[0] = _rotl(v[0], 32)
    v[2] = (v[2] + v[3]) & U64
    v[3] = _rotl(v[3], 16) ^ v[2]
    v[0] = (v[0] + v[3]) & U64
    v[3] = _rotl(v[3], 21) ^ v[0]
    v[2] = (v[2] + v[1]) & U64
    v[1] = _rotl(v[1], 17) ^ v[2]
    v[2] = _rotl(v[2], 32)


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _is_ascii(value: str) -> bool:
    return all(ord(c) < 0x80 for c in value)


class SwiftMixin:
    # -- strings ------------------------------------------------------------

    def return_swift_string(self, value: str) -> None:
        from .runtime import REG_X1

        encoded = value.encode("utf-8", "surrogateescape")
        if len(encoded) <= 15:
            words = bytearray(16)
            words[:len(encoded)] = encoded
            words[15] = 0xA0 | len(encoded)
            if _is_ascii(value):
                words[15] |= 0x40
            first, second = struct.unpack("<QQ", bytes(words))
            self.set(first)
            self.set_reg(REG_X1, second)
            return
        # Immortal native UTF-8: an address biased by the 32-byte header.
        pointer = self.alloc(len(encoded) + 33)
        self.mem_write(pointer + 32, encoded + b"\0")
        flags = len(encoded) | 0x3000000000000000
        if _is_ascii(value):
            flags |= 0xC000000000000000
        self.set(flags)
        self.set_reg(REG_X1, pointer | 0x8000000000000000)

    def swift_string(self, first: int, second: int) -> str:
        if second & (1 << 61):
            raw = struct.pack("<QQ", first & U64, second & U64)
            return raw[:(second >> 56) & 15].decode("utf-8", "surrogateescape")
        pointer = second & 0x0FFFFFFFFFFFFFFF
        if second & (1 << 60):
            return self.string(pointer)
        if not second & (1 << 63):
            self.panic("unsupported mortal Swift string")
        count = first & 0x0000FFFFFFFFFFFF
        if count > 1 << 20:
            self.panic("Swift string exceeds runtime limit")
        return self.mem_read(pointer + 32, count).decode("utf-8", "surrogateescape")

    def _value_size(self, metadata: int) -> int:
        return self.read64(self.read64(metadata - 8) + 64)

    def _copy(self, destination: int, source: int, size: int) -> None:
        if size:
            self.mem_write(destination, self.mem_read(source, size))

    def mutable_swift_request(self) -> int:
        from .runtime import REG_X20

        holder = self.reg(REG_X20)
        source = self.read64(holder)
        stored = self.objects.get(source)
        if stored is None:
            self.panic("invalid Swift request storage")
        copied = self.new(stored.cls, stored.value)
        description = self.classes.get(stored.cls)
        if description is not None:
            self._copy(copied, source, description.size)
        self.objects[copied].props.update(stored.props)
        fields = stored.props.get("allHTTPHeaderFields", 0)
        if fields:
            self.objects[copied].props["allHTTPHeaderFields"] = self.foundation_copy(fields, True)
        self.write64(holder, copied)
        return copied

    # -- swift.go swiftSymbol --------------------------------------------------

    def swift_symbol(self, name: str) -> bool:
        from .runtime import REG_X1, REG_X8, REG_X20

        if self.async_symbol(name):
            return True
        arg, sett = self.arg, self.set
        meta = self.profile.metadata
        symbols = meta.symbols
        string_type = symbols.get("$sSSN", 0)

        if name == "$ss27_stringCompareWithSmolCheck__9expectingSbs11_StringGutsV_ADs01_G16ComparisonResultOtF":
            left = _nfc(self.swift_string(arg(0), arg(1))).encode("utf-8", "surrogateescape")
            right = _nfc(self.swift_string(arg(2), arg(3))).encode("utf-8", "surrogateescape")
            if arg(4) == 0:
                sett(1 if left == right else 0)
            elif arg(4) == 1:
                sett(1 if left < right else 0)
            else:
                self.panic("unsupported Swift string comparison")
        elif name == "$ss18_DictionaryStorageC6resize8original8capacity4moveAByxq_Gs05__RawaB0C_SiSbtFZ":
            storage_type, capacity = arg(3), arg(1)
            metadata = 0
            for key, layout in meta.swift_dictionaries.items():
                if layout.get("Metadata") == storage_type:
                    metadata = int(key)
                    break
            if metadata == 0:
                self.panic(f"unprepared dictionary storage {storage_type:#x}")
            slot = self.alloc(8)
            self.write64(slot, symbols.get("_swiftEmptyDictionarySingleton", 0))
            self.ensure_unique_dictionary(slot, False, capacity, metadata)
            sett(self.read64(slot))
        elif name == "swift_dynamicCast":
            destination, source, source_type, target_type = arg(0), arg(1), arg(2), arg(3)
            if source_type == symbols.get("$ss11AnyHashableVN", 0) and target_type == string_type:
                if self.read64(source + 24) != meta.bridges.get("anyHashableStringMetadata", 0):
                    self.panic("unsupported AnyHashable cast box")
                source_type = target_type
            elif source_type == symbols.get("$sypN", 0) + 8:
                source_type = self.read64(source + 24)
            if source_type == target_type:
                size = self._value_size(source_type)
                if size > 24:
                    self.panic("unsupported Swift cast value size")
                self._copy(destination, source, size)
                sett(1)
            elif (target_type == string_type and source_type in (symbols.get("$sSiN", 0), symbols.get("$sSbN", 0),
                                                                    symbols.get("$sSdN", 0)) and arg(4) & 1 == 0):
                sett(0)
            else:
                self.panic(f"unsupported Swift cast metadata {source_type:#x} -> {target_type:#x} flags={arg(4)}")
        elif name in ("$ss17CodingUserInfoKeyVwCP", "$sSSwCP", "$sSSwcp", "$sSSwca"):
            # Shared with String: two words; the retain is subsumed by the VM lifetime.
            self._copy(arg(0), arg(1), 16)
        elif name in ("$ss11AnyHashableVwxx", "$sSSwxx"):
            pass
        elif name in ("$ss11AnyHashableVwcp", "$ss11AnyHashableVwca"):
            if self.read64(arg(1) + 24) != meta.bridges.get("anyHashableStringMetadata", 0):
                self.panic("unsupported AnyHashable copy layout")
            self._copy(arg(0), arg(1), 40)
        elif name == "$sSD10FoundationE36_unconditionallyBridgeFromObjectiveCySDyxq_GSo12NSDictionaryCSgFZ":
            if (arg(1) not in (string_type, symbols.get("$ss11AnyHashableVN", 0))
                    or arg(2) not in (symbols.get("$sypN", 0) + 8, string_type)):
                self.panic(f"unsupported dictionary bridge metadata {arg(1):#x}/{arg(2):#x}")
            sett(self.bridge_dictionary_to_swift(arg(0), arg(1), arg(2)))
        elif name == "$sSo13os_log_type_ta0A0E5errorABvgZ":
            sett(16)
        elif name == "$sSo13os_log_type_ta0A0E5faultABvgZ":
            sett(17)
        elif name == "$sSo13os_log_type_ta0A0E4infoABvgZ":
            sett(1)
        elif name == "$sSo13os_log_type_ta0A0E5debugABvgZ":
            sett(2)
        elif name == "$sSo13os_log_type_ta0A0E7defaultABvgZ":
            sett(0)
        elif name == "$sSS6appendyySSF":
            holder = self.reg(REG_X20)
            value = self.swift_string(self.read64(holder), self.read64(holder + 8)) + self.swift_string(arg(0), arg(1))
            self.return_swift_string(value)
            self.write64(holder, arg(0))
            self.write64(holder + 8, arg(1))
        elif name == "$ss9_typeName_9qualifiedSSypXp_SbtF":
            type_name = self.class_names.get(arg(0), "")
            if not type_name and self.read64(arg(0)) == 0x305:
                type_name = self.class_names.get(self.read64(arg(0) + 8), "")
            if not type_name:
                self.panic(f"unprepared Swift type name {arg(0):#x}")
            self.return_swift_string(type_name)
        elif name == "$ss9TaskLocalC12wrappedValueAByxGx_tcfc":
            from .runtime import Obj

            holder = self.reg(REG_X20)
            metadata = self.read64(holder)
            value_type = self.read64(metadata + 80)
            size = self._value_size(value_type)
            if size > self.allocations.get(holder, 0) - 16:
                self.panic("TaskLocal value exceeds allocation")
            self._copy(holder + 16, arg(0), size)
            self.objects[holder] = Obj("HostSwiftTaskLocal", None, {"valueSize": size, "defaultValue": holder + 16})
            sett(holder)
        elif name in ("$ss9TaskLocalC3getxyF", "$ss9TaskLocalC12wrappedValuexvg"):
            holder = self.reg(REG_X20)
            stored = self.objects.get(holder)
            if stored is None:
                self.panic("unknown TaskLocal")
            out = self.reg(REG_X8)
            source = self.task_local_value(holder) or stored.props.get("defaultValue", 0)
            self._copy(out, source, stored.props.get("valueSize", 0))
        elif name == "$sSo9OS_os_logC0B0E9subsystem8categoryABSS_SStcfC":
            sett(self.new("HostOSLog", None))
        elif name == "$s10Foundation10URLRequestV8setValue_18forHTTPHeaderFieldySSSg_SStF":
            copied = self.mutable_swift_request()
            stored = self.objects[copied]
            if stored.props.get("allHTTPHeaderFields", 0) == 0:
                stored.props["allHTTPHeaderFields"] = self.new("NSMutableDictionary", {})
            fields = self.dict_of(stored.props["allHTTPHeaderFields"])
            key = canonical_header_key(self.swift_string(arg(2), arg(3)))
            if arg(1) == 0:
                fields.pop(key, None)
            else:
                fields[key] = self.new("NSString", self.swift_string(arg(0), arg(1)))
        elif name in ("swift_initWithCopy_strong", "swift_initWithTake_strong", "swift_assignWithCopy_strong",
                      "swift_assignWithTake_strong"):
            self.write64(arg(0), self.read64(arg(1)))
        elif name == "$s10Foundation3URLV14absoluteStringSSvg":
            self.return_swift_string(self.string(self.read64(self.reg(REG_X20))))
        elif name == "$s10Foundation10URLRequestV3urlAA3URLVSgvg":
            holder = self.reg(REG_X20)
            stored = self.objects.get(self.read64(holder))
            if stored is None:
                self.panic("invalid Swift URLRequest value")
            out = self.reg(REG_X8)
            self.write64(out, stored.props.get("URL", 0))
            self.write64(out + 8, 0)
        elif name == "swift_getSingletonMetadata":
            value = meta.swift_singletons.get(str(arg(1)), 0)
            if value == 0:
                self.panic(f"unprepared singleton metadata {arg(1):#x}")
            sett(value)
            self.set_reg(REG_X1, 0)
        elif name == "$s10Foundation22_convertErrorToNSErrorySo0E0Cs0C0_pF":
            value = arg(0)
            for _ in range(16):
                stored = self.objects.get(value)
                if stored is None:
                    self.panic("unknown Swift error value")
                if self.kind_of(stored.cls, "NSError"):
                    sett(value)
                    return True
                if stored.cls != "HostSwiftError" or stored.props.get("metadata", 0) != meta.swift_types.get(str(0x1A2E1C7FA), 0):
                    self.panic(f"unsupported Swift error bridge {stored.cls} metadata {stored.props.get('metadata', 0):#x}")
                value = self.read64(stored.props.get("value", 0))
            self.panic("recursive Swift error box")
        elif name == "$ss38_bridgeAnythingNonVerbatimToObjectiveCyyXlxnlF":
            source, metadata = arg(0), arg(1)
            if metadata == string_type:
                sett(self.new("NSString", self.swift_string(self.read64(source), self.read64(source + 8))))
            elif metadata == symbols.get("$sSiN", 0):
                value = self.read64(source)
                sett(self.new("NSNumber", value - (1 << 64) if value >> 63 else value))
            else:
                self.panic(f"unsupported nonverbatim bridge metadata {metadata:#x}")
        elif name == "$sSD10FoundationE19_bridgeToObjectiveCSo12NSDictionaryCyF":
            sett(self.bridge_dictionary_to_objc(arg(0), arg(1), arg(2)))
        elif name == "$sSS4hash4intoys6HasherVz_tF":
            value = _nfc(self.swift_string(arg(1), arg(2))).encode("utf-8", "surrogateescape")
            self.hash_bytes(arg(0), value + b"\xff")
        elif name == "swift_allocError":
            metadata, witness, source = arg(0), arg(1), arg(2)
            size = self._value_size(metadata)
            if size > 1 << 20:
                self.panic("Swift error exceeds budget")
            value = self.alloc(size)
            box = self.new("HostSwiftError", None)
            self.objects[box].props = {"metadata": metadata, "witness": witness, "value": value}
            if source:
                self._copy(value, source, size)
            sett(box)
            self.set_reg(REG_X1, value)
        elif name == "swift_getErrorValue":
            box = self.objects.get(arg(0))
            if box is None or box.cls != "HostSwiftError":
                self.panic("unsupported unboxed Swift error")
            out = arg(2)
            self.write64(out, box.props.get("value", 0))
            self.write64(out + 8, box.props.get("metadata", 0))
            self.write64(out + 16, box.props.get("witness", 0))
        elif name in ("swift_errorRetain", "swift_errorRelease", "swift_willThrow"):
            pass
        elif name == "$s10Foundation10URLRequestV36_unconditionallyBridgeFromObjectiveCyACSo12NSURLRequestCSgFZ":
            value = arg(0)
            stored = self.objects.get(value)
            if stored is None or not self.kind_of(stored.cls, "NSURLRequest"):
                self.panic("invalid Swift request bridge input")
            self.write64(self.reg(REG_X8), value)
        elif name in ("$s10Foundation10URLRequestV19_bridgeToObjectiveCSo12NSURLRequestCyF",
                      "$s10Foundation3URLV19_bridgeToObjectiveCSo5NSURLCyF"):
            sett(self.read64(self.reg(REG_X20)))
        elif name == "$sScPwst":
            if arg(2) != 1 or arg(1) > 1:
                self.panic("unsupported task priority optional tag")
            size = self._value_size(arg(3))
            if size != 1:
                self.panic("unexpected priority size")
            self.mem_write(arg(0) + size, bytes([arg(1) & 0xFF]))
        elif name == "$sScPwet":
            size = self._value_size(arg(2))
            sett(self.mem_read(arg(0) + size, 1)[0])
        elif name == "$s10Foundation3URLV06isFileB0Sbvg":
            try:
                url = GoURL.parse(self.string(self.read64(self.reg(REG_X20))))
            except ValueError as exc:
                self.panic(str(exc))
            sett(1 if url.scheme == "file" else 0)
        elif name in ("$sSqwta", "$sSqwca", "$sSqwcp", "$sSqwtk", "swift_cvw_initWithCopy", "swift_cvw_assignWithCopy",
                      "swift_cvw_initWithTake", "swift_cvw_assignWithTake"):
            size = self._value_size(arg(2))
            if size > 1024:
                self.panic("Swift value copy exceeds budget")
            self._copy(arg(0), arg(1), size)
        elif name == "$s10Foundation3URLVwst":
            if arg(2) != 1 or arg(1) > 1:
                self.panic("unsupported URL optional tag")
            if arg(1) == 1:
                self.write64(arg(0), 0)
                self.write64(arg(0) + 8, 0)
        elif name == "$s10Foundation3URLVwet":
            if arg(1) != 1:
                self.panic("unsupported URL optional tag")
            sett(1 if self.read64(arg(0)) == 0 else 0)
        elif name in ("$s10Foundation3URLV9appending10components13directoryHintACxd_AC09DirectoryF0OtSyRzlF",
                      "$s10Foundation3URLV6append10components13directoryHintyxd_AC09DirectoryF0OtSyRzlF"):
            holder = self.reg(REG_X20)
            array = arg(0)
            count = self.read64(array + 16)
            if count > 32:
                self.panic("URL component count exceeds budget")
            value = self.string(self.read64(holder))
            for index in range(count):
                pointer = array + 32 + index * 16
                component = self.swift_string(self.read64(pointer), self.read64(pointer + 8))
                try:
                    value = url_join_path(value, component)
                except ValueError as exc:
                    self.panic(str(exc))
            if "9appending" in name:
                holder = self.reg(REG_X8)
            self.write64(holder, self.new("NSURL", value))
            self.write64(holder + 8, 0)
        elif name == "$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ":
            stored = self.objects.get(arg(0))
            if stored is None or stored.cls != "NSURL":
                self.panic("invalid Swift URL bridge input")
            out = self.reg(REG_X8)
            self.write64(out, arg(0))
            self.write64(out + 8, 0)
        elif name == "$s10ObjectiveC8SelectorV2eeoiySbAC_ACtFZ":
            sett(1 if arg(0) == arg(1) else 0)
        elif name == "$ss17_NativeDictionaryV12ensureUnique02isD08capacityS2b_SitF":
            self.ensure_unique_dictionary(self.reg(REG_X20), arg(0) != 0, arg(1), arg(2))
        elif name == "$ss6HasherV5_seedABSi_tcfC":
            self.init_hasher(self.reg(REG_X8), arg(0))
        elif name == "$ss6HasherV8_combineyySuF":
            self.hash_word(self.reg(REG_X20), arg(0))
        elif name == "$ss6HasherV9_finalizeSiyF":
            holder = self.reg(REG_X20)
            sett(self.hash_compress(holder, self.read64(holder), True))
        elif name == "$s10ObjectiveC8SelectorV4hash4intoys6HasherVz_tF":
            self.hash_word(arg(0), arg(1))
        elif name == ("$sSo17OS_dispatch_queueC8DispatchE5async5group3qos5flags7executeySo0a1_b1_F0CSg_AC0D3QoSVAC0D13"
                      "WorkItemFlagsVyyXBtF"):
            if arg(0) != 0:
                self.panic("Swift dispatch group unsupported")
            queue = self.reg(REG_X20)

            def enqueue(block: int) -> None:
                self.queue_pending(block, queue)
                sett(0)

            self.copy_block(arg(3), enqueue)
        elif name in ("$sSo17OS_dispatch_queueC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0D3QoSVAbCE"
                      "10AttributesVAbCE011AutoreleaseI0OABSgtcfC",
                      "$sSo24OS_dispatch_queue_serialC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0E"
                      "3QoSVAbCE10AttributesVSo0a1_b1_C0CACE011AutoreleaseJ0OANSgtcfC"):
            target = arg(5)
            queue = self.new("HostQueue", self.swift_string(arg(0), arg(1)))
            self.objects[queue].props["targetQueue"] = target
            sett(queue)
        elif name == "$ss10SetAlgebraPyxqd__ncSTRd__7ElementQyd__ACRtzlufCTj":
            accessors = meta.swift_accessors
            allowed = (accessors.get("$sSo24OS_dispatch_queue_serialC8DispatchE10AttributesVMa", 0),
                       accessors.get("$sSo17OS_dispatch_queueC8DispatchE10AttributesVMa", 0),
                       accessors.get("$s8Dispatch0A13WorkItemFlagsVMa", 0))
            if arg(3) not in allowed or self.read64(self.read64(arg(0)) + 16) != 0:
                self.panic("unsupported SetAlgebra initializer")
            self.write64(self.reg(REG_X8), 0)
        elif name == "$s8Dispatch0A3QoSV11unspecifiedACvgZ":
            out = self.reg(REG_X8)
            self.write64(out, 5)
            self.write64(out + 8, 0)
        elif name in ("swift_isUniquelyReferenced_nonNull_native", "swift_isUniquelyReferenced_nonNull_bridgeObject"):
            sett(0)  # copy conservatively: host handles may alias for the VM lifetime
        elif name in ("swift_retain_n", "swift_bridgeObjectRetain_n", "swift_retain", "swift_bridgeObjectRetain",
                      "swift_unknownObjectRetain", "swift_destroy_strong", "$ss15CollectionOfOneV8IteratorVwxx",
                      "swift_pod_destroy", "swift_arrayDestroy", "swift_deallocPartialClassInstance", "swift_cvw_destroy",
                      "swift_noop_void_return", "swift_release_n", "swift_bridgeObjectRelease_n", "swift_release",
                      "swift_bridgeObjectRelease", "swift_unknownObjectRelease", "swift_deallocObject"):
            pass
        elif name in ("swift_arrayInitWithCopy", "swift_arrayInitWithTakeFrontToBack", "swift_arrayInitWithTakeBackToFront"):
            destination, source, count, metadata = arg(0), arg(1), arg(2), arg(3)
            if count == 0:
                sett(destination)
                return True
            witnesses = self.read64(metadata - 8)
            stride = self.read64(witnesses + 72)
            if count > 65536 or stride > 1 << 20:
                self.panic("Swift array copy exceeds budget")
            offset = 16 if name == "swift_arrayInitWithCopy" else 32
            function = self.read64(witnesses + offset)
            position = {"index": 0}

            def advance() -> None:
                if position["index"] == count:
                    sett(destination)
                    return
                index = position["index"]
                if name == "swift_arrayInitWithTakeBackToFront":
                    index = count - position["index"] - 1
                position["index"] += 1
                self.callback_function(function, [destination + index * stride, source + index * stride, metadata],
                                       advance)

            advance()
        elif name == "swift_allocObject":
            metadata, size = arg(0), arg(1)
            if size < 16:
                self.panic("invalid Swift object size")
            created = self.alloc(size)
            self.write64(created, metadata)
            self.write64(created + 8, 3)  # inline refcount: one strong reference, live object
            sett(created)
        elif name == "swift_getForeignTypeMetadata":
            candidate = arg(1)
            value = meta.swift_foreign.get(str(candidate), 0)
            if value:
                sett(value)
                self.set_reg(REG_X1, 0)
                return True
            # AMSErrorCode: the pinned runtime returns this complete, static
            # enum metadata unchanged. Not to be generalized.
            if candidate != 0x1EAA52F08 or self.read64(candidate) != 0x201:
                self.panic(f"unsupported foreign metadata {candidate:#x}")
            sett(candidate)
            self.set_reg(REG_X1, 0)
        elif name == "swift_getWitnessTable":
            value = meta.swift_witnesses.get(f"{arg(0)}:{arg(1)}", 0)
            if value == 0:
                self.panic(f"unprepared witness descriptor {arg(0):#x} for metadata {arg(1):#x}")
            sett(value)
        elif name == "$sSD17dictionaryLiteralSDyxq_Gx_q_td_tcfC":
            if self.read64(arg(0) + 16) != 0:
                self.panic("nonempty Swift dictionary literal unsupported")
            sett(symbols.get("_swiftEmptyDictionarySingleton", 0))
        elif name == "swift_defaultActor_initialize":
            from .runtime import Obj

            # Serial host scheduler: a fresh actor has an empty mailbox.
            self.objects[arg(0)] = Obj("HostSwiftActor", None, {})
        elif name == "swift_getObjectType":
            sett(self.read64(arg(0)))
        elif name == "swift_getObjCClassFromMetadata":
            if self.class_names.get(arg(0), ""):
                return True
            if self.read64(arg(0)) == 0x305:
                sett(self.read64(arg(0) + 8))
                return True
            self.panic("unknown Objective-C class metadata")
        elif name == "swift_getObjCClassMetadata":
            pass  # Objective-C compatible class metadata is the class address itself
        elif name == "swift_getTypeByMangledNameInContext2":
            value = meta.swift_types.get(str(arg(0)), 0)
            if value == 0 or arg(2) != 0 or arg(3) != 0:
                self.panic(f"unprepared Swift type {arg(0):#x}/{arg(1)}")
            sett(value)
        elif name == "$sSS10FoundationE36_unconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ":
            self.return_swift_string(self.string(arg(0)))
        elif name == "$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF":
            sett(self.new("NSString", self.swift_string(arg(0), arg(1))))
        else:
            return self._swift_pattern(name)
        return True

    def _swift_pattern(self, name: str) -> bool:
        from .runtime import REG_X1

        arg, sett = self.arg, self.set
        if "NativeBoxIyLm8ELm8ELm8E" in name and "initializeBufferWithCopyOfBuffer" in name:
            self.write64(arg(0), self.read64(arg(1)))
            return True
        if "BridgeObjectBox" in name and ("initializeWithCopy" in name or "assignWithCopy" in name):
            self.write64(arg(0), self.read64(arg(1)))
            return True
        if "BridgeObjectBox" in name and "destroy" in name:
            return True
        if "tuple_initializeWithCopy" in name or "tuple_assignWithCopy" in name:
            size = self._value_size(arg(2))
            if size > 1024:
                self.panic("tuple copy exceeds budget")
            self._copy(arg(0), arg(1), size)
            return True
        if name.startswith("swift_memcpy"):
            match = _MEMCPY.match(name)
            if match is None or int(match.group(1)) > 1024:
                self.panic("unsupported Swift copy size")
            self._copy(arg(0), arg(1), int(match.group(1)))
            return True
        if "SwiftRetainableBox" in name and "7destroy" in name:
            return True
        if "SwiftRetainableBox" in name and "initializeBufferWithCopyOfBuffer" in name:
            self.write64(arg(0), self.read64(arg(1)))
            return True
        meta = self.profile.metadata
        value = meta.swift_globals.get(name, 0)
        if value:
            sett(value)
            return True
        if ((name.startswith("$sSo17OS_dispatch_queueC8DispatchE") or name.startswith("$s10Foundation3URLV13DirectoryHintO"))
                and name.endswith("Owui")):
            if self._value_size(arg(2)) != 1:
                self.panic("unexpected dispatch enum size")
            self.mem_write(arg(0), bytes([arg(1) & 0xFF]))
            return True
        value = meta.swift_accessors.get(name, 0)
        if value:
            sett(value)
            self.set_reg(REG_X1, 0)
            return True
        return False

    # -- dictionary.go ------------------------------------------------------------

    def ensure_unique_dictionary(self, holder: int, unique: bool, capacity: int, metadata: int) -> None:
        old = self.read64(holder)
        old_capacity = self.read64(old + 24)
        if unique and capacity <= old_capacity:
            self.set(0)
            return
        layout = self.profile.metadata.swift_dictionaries.get(str(metadata))
        if layout is None:
            self.panic(f"unprepared dictionary metadata {metadata:#x}")
        key_stride, value_stride = layout.get("KeyStride", 0), layout.get("ValueStride", 0)
        if key_stride not in (16, 32, 40) or value_stride not in (8, 16, 32):
            self.panic("unsupported dictionary copy layout")
        buckets = 1024
        storage_capacity = buckets * 3 // 4
        if capacity > storage_capacity:
            self.panic("dictionary exceeds runtime capacity")
        count = self.read64(old + 16)
        if count != 0 and old_capacity != storage_capacity:
            self.panic("dictionary resizing requires rehash")
        header = 64 + buckets // 8
        storage = self.alloc(header + buckets * (key_stride + value_stride))
        self.write64(storage, layout.get("Metadata", 0))
        self.write64(storage + 8, 3)
        self.write64(storage + 16, count)
        self.write64(storage + 24, storage_capacity)
        self.write64(storage + 32, 10)
        self.write64(storage + 40, self.read64(old + 40))
        keys = storage + header
        values = keys + buckets * key_stride
        self.write64(storage + 48, keys)
        self.write64(storage + 56, values)
        if count:
            for destination, source, size in ((storage + 64, old + 64, buckets // 8),
                                              (keys, self.read64(old + 48), buckets * key_stride),
                                              (values, self.read64(old + 56), buckets * value_stride)):
                self._copy(destination, source, size)
        self.write64(holder, storage)
        self.set(1 if old_capacity != storage_capacity else 0)

    def bridge_dictionary_to_swift(self, address: int, key_type: int, value_type: int) -> int:
        meta = self.profile.metadata
        symbols = meta.symbols
        empty = symbols.get("_swiftEmptyDictionarySingleton", 0)
        if address == 0:
            return empty
        values = self.dict_of(address)
        if not values:
            return empty
        type_ref, key_stride, value_stride = 0x1A2E1D5D6, 16, 32
        if value_type == symbols.get("$sSSN", 0):
            if key_type != value_type:
                self.panic("unsupported typed dictionary bridge")
            type_ref, value_stride = 0x1A2E1D7C6, 16
        if key_type == symbols.get("$ss11AnyHashableVN", 0):
            type_ref, key_stride = 0x1A2E1DB1A, 40
        metadata = meta.swift_types.get(str(type_ref), 0)
        if metadata == 0:
            self.panic("String/Any dictionary metadata not prepared")
        slot = self.alloc(8)
        self.write64(slot, empty)
        self.ensure_unique_dictionary(slot, False, len(values), metadata)
        storage = self.read64(slot)
        keys, items = self.read64(storage + 48), self.read64(storage + 56)
        seed = self.read64(storage + 40)
        buckets = 1 << (self.read64(storage + 32) & 0xFF)
        for key in sorted(values, key=lambda k: k.encode("utf-8", "surrogateescape")):
            hasher = self.alloc(72)
            self.init_hasher(hasher, seed)
            self.hash_bytes(hasher, _nfc(key).encode("utf-8", "surrogateescape") + b"\xff")
            digest = self.hash_compress(hasher, self.read64(hasher), True)
            index = digest & (buckets - 1)
            while self.read64(storage + 64 + (index // 64) * 8) & (1 << (index % 64)):
                index = (index + 1) & (buckets - 1)
            bitmap = storage + 64 + (index // 64) * 8
            self.write64(bitmap, self.read64(bitmap) | (1 << (index % 64)))
            self.return_swift_string(key)
            self.write64(keys + index * key_stride, self.arg(0))
            self.write64(keys + index * key_stride + 8, self.arg(1))
            if key_stride == 40:
                self.write64(keys + index * key_stride + 24, meta.bridges.get("anyHashableStringMetadata", 0))
                self.write64(keys + index * key_stride + 32, meta.bridges.get("anyHashableStringWitness", 0))
            if value_stride == 16:
                text = self.obj(values[key]).value
                if not isinstance(text, str):
                    self.panic("non-string value in typed dictionary bridge")
                self.return_swift_string(text)
                self.write64(items + index * 16, self.arg(0))
                self.write64(items + index * 16 + 8, self.arg(1))
            else:
                self.store_swift_any(items + index * 32, values[key])
        self.write64(storage + 16, len(values))
        return storage

    def store_swift_any(self, destination: int, address: int) -> None:
        stored = self.objects.get(address)
        if stored is None:
            self.panic("unknown object bridged to Swift Any")
        meta = self.profile.metadata
        symbols = meta.symbols
        value = stored.value
        if isinstance(value, str):
            self.return_swift_string(value)
            self.write64(destination, self.arg(0))
            self.write64(destination + 8, self.arg(1))
            metadata = symbols.get("$sSSN", 0)
        elif type(value) is bool:
            self.write64(destination, 1 if value else 0)
            metadata = symbols.get("$sSbN", 0)
        elif type(value) is int:
            self.write64(destination, value)
            metadata = symbols.get("$sSiN", 0)
        elif isinstance(value, float):
            self.write64(destination, struct.unpack("<Q", struct.pack("<d", value))[0])
            metadata = symbols.get("$sSdN", 0)
        else:
            cls = stored.cls
            if "Dictionary" in cls:
                cls = "NSDictionary"
            elif "Array" in cls:
                cls = "NSArray"
            elif "Data" in cls:
                cls = "NSData"
            metadata = meta.objc_metadata.get(cls, 0)
            self.write64(destination, address)
        if metadata == 0:
            self.panic("unprepared Swift Any metadata")
        self.write64(destination + 24, metadata)

    def bridge_dictionary_to_objc(self, storage: int, key_type: int, value_type: int) -> int:
        symbols = self.profile.metadata.symbols
        result: Dict[str, int] = {}
        count = self.read64(storage + 16)
        if count == 0:
            return self.new("NSDictionary", result)
        if key_type != symbols.get("$sSSN", 0) or value_type != symbols.get("$sSSN", 0):
            self.panic(f"unsupported dictionary Objective-C bridge types {key_type:#x}/{value_type:#x}")
        if count > 768 or self.read64(storage + 32) & 255 > 10:
            self.panic("dictionary bridge exceeds budget")
        keys, values = self.read64(storage + 48), self.read64(storage + 56)
        buckets = 1 << (self.read64(storage + 32) & 0xFF)
        for index in range(buckets):
            if not self.read64(storage + 64 + (index // 64) * 8) & (1 << (index % 64)):
                continue
            key = self.swift_string(self.read64(keys + index * 16), self.read64(keys + index * 16 + 8))
            value = self.swift_string(self.read64(values + index * 16), self.read64(values + index * 16 + 8))
            result[key] = self.new("NSString", value)
        if len(result) != count:
            self.panic("Swift dictionary count mismatch")
        return self.new("NSDictionary", result)

    # -- hashing.go (SipHash-1-3 with Swift's Hasher ABI) ---------------------------

    def init_hasher(self, address: int, seed: int) -> None:
        a = b = 0
        parameters = self.profile.metadata.symbols.get("_swift_stdlib_Hashing_parameters", 0)
        if parameters:
            a = self.read64(parameters)
            b = self.read64(parameters + 8)
        a ^= seed
        for index, value in enumerate((0, 0x736F6D6570736575 ^ a, 0x646F72616E646F6D ^ b, 0x6C7967656E657261 ^ a,
                                       0x7465646279746573 ^ b, 0, 0, 0, 0)):
            self.write64(address + index * 8, value)

    def hash_compress(self, address: int, word: int, final: bool) -> int:
        v = [self.read64(address + 8 + index * 8) for index in range(4)]
        v[3] ^= word
        _sip_round(v)
        v[0] ^= word
        if final:
            v[2] ^= 255
            for _ in range(3):
                _sip_round(v)
        for index, value in enumerate(v):
            self.write64(address + 8 + index * 8, value)
        return v[0] ^ v[1] ^ v[2] ^ v[3]

    def hash_word(self, address: int, word: int) -> None:
        tail = self.read64(address)
        count = tail >> 56
        shift = (count & 7) * 8
        chunk = word
        if shift:
            chunk = (tail & 0xFFFFFFFFFFFFFF) | ((word << shift) & U64)
            tail = (((count + 8) << 56) | (word >> (64 - shift))) & U64
        else:
            tail = (tail + (8 << 56)) & U64
        self.write64(address, tail)
        self.hash_compress(address, chunk, False)

    def hash_bytes(self, address: int, data: bytes) -> None:
        for byte in data:
            tail = self.read64(address)
            count = tail >> 56
            shift = (count & 7) * 8
            word = (tail & 0xFFFFFFFFFFFFFF) | (byte << shift)
            if shift == 56:
                self.hash_compress(address, word & U64, False)
                self.write64(address, ((count + 1) << 56) & U64)
            else:
                self.write64(address, (((count + 1) << 56) | word) & U64)

    # -- async.go (structured concurrency on a serial host scheduler) -----------------

    def async_symbol(self, name: str) -> bool:
        from .runtime import REG_PC, REG_X1, REG_X22, AsyncTask

        arg, sett = self.arg, self.set
        if name == "swift_task_localValueGet":
            sett(self.task_local_value(arg(0)))
        elif name == "swift_task_localValuePush":
            key, source, metadata = arg(0), arg(1), arg(2)
            size = self._value_size(metadata)
            value = self.alloc(size)
            self._copy(value, source, size)
            self.task_local_frames.setdefault(self.task_local_owner(), []).append((key, value))
            sett(0)
        elif name == "swift_task_localValuePop":
            frames = self.task_local_frames.get(self.task_local_owner(), [])
            if not frames:
                self.panic("empty TaskLocal binding stack")
            frames.pop()
        elif name == "swift_task_localsCopyTo":
            if arg(0) not in self.tasks:
                self.panic("unknown task for local bindings")
            self.task_local_frames[arg(0)] = list(self.task_local_frames.get(self.task_local_owner(), []))
        elif name == "swift_continuation_init":
            if self.current_task is None:
                self.panic("continuation initialized outside task")
            context, flags = arg(0), arg(1)
            if flags & 4:
                self.panic("preawaited continuation unsupported")
            self.current_task.continuation = context
            self.write64(context + 16, (flags & 1) | ((flags & 8) >> 2))
            self.write64(context + 24, 0)
            self.write64(context + 32, 0)
            if flags & 2 == 0:
                self.write64(context + 48, 0)
                self.write64(context + 56, 0)
            sett(self.current_task.handle)
        elif name in ("swift_continuation_resume", "swift_continuation_throwingResume",
                      "swift_continuation_throwingResumeWithError"):
            task = self.tasks.get(arg(0))
            if task is None or task.continuation == 0:
                self.panic("unknown Swift continuation")
            context = task.continuation
            if self.read64(context + 24) == 2:
                self.panic("Swift continuation resumed twice")
            if name == "swift_continuation_throwingResumeWithError":
                self.write64(context + 32, arg(1))
            self.write64(context + 24, 2)
            sett(0)
        elif name == "swift_continuation_await":
            context = arg(0)
            task = self.current_task
            if task is None or task.continuation != context:
                self.panic("awaiting unknown Swift continuation")

            def resume() -> None:
                if self.read64(context + 24) == 2:
                    task.continuation = 0
                    self.current_task = task
                    self.set_reg(REG_X22, context)
                    self.set_reg(REG_PC, self.read64(context + 8))
                    return
                block = self.next_pending()
                if block == 0:
                    self.panic("Swift continuation has no runnable completion")
                self.current_task = None

                def back() -> None:
                    self.current_task = task
                    resume()

                self.pending_callback(block, back)

            resume()
        elif name == "swift_task_create":
            flags, options, result_type, descriptor, closure = arg(0), arg(1), arg(2), arg(3), arg(4)
            if options != 0 or flags & ~0x1CFF & U64:
                self.panic("unsupported Swift task options")
            bits = self.read64(descriptor)
            size = bits >> 32
            if size < 16 or size > 1 << 20:
                self.panic("invalid Swift async context size")
            offset = bits & 0xFFFFFFFF
            if offset >> 31:
                offset -= 1 << 32
            task = AsyncTask(self.new("HostSwiftTask", None), self.alloc(size + 32) + 32,
                             (descriptor + offset) & U64, closure)
            value_size = self._value_size(result_type) if result_type else 0
            task.result = self.alloc(value_size)
            self.tasks[task.handle] = task
            if flags & (1 << 10):
                self.task_local_frames[task.handle] = list(self.task_local_frames.get(self.task_local_owner(), []))
            self.pending.append(self.host_block(lambda: self.start_async(task)))
            sett(task.handle)
            self.set_reg(REG_X1, task.context)
        elif name == "swift_task_alloc":
            sett(self.alloc(arg(0)))
        elif name == "swift_task_dealloc":
            pass
        elif name == "swift_task_getCurrent":
            sett(self.current_task.handle if self.current_task is not None else 0)
        elif name == "swift_task_isCancelled":
            sett(0)
        elif name == "swift_task_switch":
            if self.current_task is None:
                self.panic("executor switch outside a Swift task")
            function = arg(0)
            self.current_task.executor = (arg(1), arg(2))
            self.set_reg(REG_PC, function)
        elif name == "swift_task_getCurrentExecutor":
            executor = self.current_task.executor if self.current_task is not None else (0, 0)
            sett(executor[0])
            self.set_reg(REG_X1, executor[1])
        elif name == "swift_task_isCurrentExecutor":
            executor = self.current_task.executor if self.current_task is not None else (0, 0)
            sett(1 if executor == (arg(0), arg(1)) else 0)
        else:
            return False
        return True

    def start_async(self, task) -> None:
        from .runtime import REG_LR, REG_PC, REG_SP, REG_X0, REG_X29

        if task.done:
            self.panic("attempt to restart a completed Swift task")
        registers = [REG_SP, REG_LR, REG_X29] + [REG_X0 + index for index in range(19, 29)]
        saved = {register: self.reg(register) for register in registers}
        previous = self.current_task
        self.current_task = task
        completion = self.alloc(16)
        self.mem_write(completion, b"\xc0\x03\x5f\xd6")

        def completed() -> None:
            if task.done:
                self.panic("Swift task completed twice")
            task.done = True
            self.current_task = previous
            for register, value in saved.items():
                self.set_reg(register, value)
            self.set(0)
            self.set_reg(REG_PC, saved[REG_LR])

        self.callbacks[completion] = completed
        self.write64(task.context, 0)
        self.write64(task.context + 8, completion)
        self.write64(task.context - 32, task.result)
        self.write64(task.context - 24, task.entry)
        self.write64(task.context - 16, task.closure)
        self.set_reg(REG_X0, task.result)
        self.set_reg(REG_X0 + 20, task.closure)
        self.set_reg(REG_X0 + 21, 0)
        self.set_reg(REG_X0 + 22, task.context)
        self.set_reg(REG_PC, task.entry)

    def task_local_owner(self) -> int:
        return self.current_task.handle if self.current_task is not None else 0

    def task_local_value(self, key: int) -> int:
        for stored_key, value in reversed(self.task_local_frames.get(self.task_local_owner(), [])):
            if stored_key == key:
                return value
        return 0

