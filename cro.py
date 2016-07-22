import idaapi
import struct

CRO_SIGNATURE     = "CRO0"
CRO_FORMAT_NAME   = "CRO (CTR relocatable object)"


def accept_file(li, n):

    # we support only one format per file
    if n > 0:
        return 0

    # check the 3DSX signature
    li.seek(0x80)
    if li.read(4) == CRO_SIGNATURE:
        # accept the file
        return CRO_FORMAT_NAME

    # unrecognized format
    return 0

# -----------------------------------------------------------------------

def DecodeTag(segmentTable, tag):
    target_segment = tag & 0xF
    target_rel_offset = tag >> 4
    return segmentTable[target_segment] + target_rel_offset

def do_import_name(ea, name):
    idaapi.do_name_anyway(ea, "_import_" + name)

    #guess wrapper
    if idaapi.get_long(ea - 4) == 0xE51FF004: # "ldr pc, [pc, #-4]"
        idaapi.do_name_anyway(ea - 4, name)

def do_import_batch(li, segmentTable, batchOffset, name):
    li.seek(batchOffset)
    while True:
        target, patch_type, is_end, is_resolved, _, shift = struct.unpack("<IBBBBI", li.read(12))
        target_offset = DecodeTag(segmentTable, target)
        do_import_name(target_offset, name)
        if is_end != 0:
            break

def load_cro(li, is_crs):
    if is_crs:
        base = 0
    else:
        base = 0x00100000 # arbitrary

    li.seek(0x80)
    (Magic,
    NameOffset,
    NextCRO,
    PreviousCRO,
    FileSize,
    BssSize,
    FixedSize,
    UnknownZero,
    UnkSegmentTag,
    OnLoadSegmentTag,
    OnExitSegmentTag,
    OnUnresolvedSegmentTag,

    CodeOffset,
    CodeSize,
    DataOffset,
    DataSize,
    ModuleNameOffset,
    ModuleNameSize,
    SegmentTableOffset,
    SegmentNum,

    ExportNamedSymbolTableOffset,
    ExportNamedSymbolNum,
    ExportIndexedSymbolTableOffset,
    ExportIndexedSymbolNum,
    ExportStringsOffset,
    ExportStringsSize,
    ExportTreeTableOffset,
    ExportTreeNum,

    ImportModuleTableOffset,
    ImportModuleNum,
    ExternalPatchTableOffset,
    ExternalPatchNum,
    ImportNamedSymbolTableOffset,
    ImportNamedSymbolNum,
    ImportIndexedSymbolTableOffset,
    ImportIndexedSymbolNum,
    ImportAnonymousSymbolTableOffset,
    ImportAnonymousSymbolNum,
    ImportStringsOffset,
    ImportStringsSize,

    StaticAnonymousSymbolTableOffset,
    StaticAnonymousSymbolNum,
    InternalPatchTableOffset,
    InternalPatchNum,
    StaticPatchTableOffset,
    StaticPatchNum) = struct.unpack("<IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII", li.read(0x138 - 0x80))

    if not is_crs:
        li.file2base(0, base, base + FileSize, 0)

    # set segments
    li.seek(SegmentTableOffset)
    segmentDic = [
        ("CODE", ".text"),
        ("DATA", ".rodata"),
        ("DATA", ".data"),
        ("BSS", ".bss")
    ]
    segmentAddress = []
    for i in range(SegmentNum):
        SegmentOffset, SegmentSize, SegmentType = struct.unpack("<III", li.read(12))
        if SegmentType == 3:
            SegmentOffset = 0x08000000
            idaapi.enable_flags(base + SegmentOffset, base + SegmentOffset + SegmentSize, idaapi.STT_VA)

        segmentAddress.append(base + SegmentOffset)
        if SegmentSize :
            idaapi.add_segm(0, segmentAddress[i], segmentAddress[i] + SegmentSize, segmentDic[SegmentType][1], segmentDic[SegmentType][0])

    # do internal relocations
    li.seek(InternalPatchTableOffset)
    for i in range(InternalPatchNum):
        target, patch_type, source, _, _, shift = struct.unpack("<IBBBBI", li.read(12))
        target_offset = DecodeTag(segmentAddress, target)
        source_offset = segmentAddress[source] + shift
        if patch_type == 2:
            value = source_offset
        elif patch_type == 3:
            rel = source_offset - target_offset
            if rel < 0:
                rel += 0x100000000
            value = rel
        idaapi.patch_long(target_offset, value)
        f = idaapi.fixup_data_t()
        f.type = idaapi.FIXUP_OFF32
        f.off = value
        idaapi.set_fixup(target_offset, f)

    # import
    li.seek(ImportNamedSymbolTableOffset)
    importNamedSymbolTable = []
    for i in range(ImportNamedSymbolNum):
        importNamedSymbolTable.append(struct.unpack('<II', li.read(8)))

    for importNamedSymbol in importNamedSymbolTable:
        nameOffset, batchOffset = importNamedSymbol
        li.seek(nameOffset)
        name = ""
        while True:
            c = li.read(1)
            if c == '\0':
                break
            name += c
        do_import_batch(li, segmentAddress, batchOffset, name)

    li.seek(ImportModuleTableOffset)
    module = []
    for i in range(ImportModuleNum):
        module.append(struct.unpack('<IIIII', li.read(20)))

    for m in module:
        moduleNameOffset, indexed, indexedNum, anonymous, anonymousNum = m
        li.seek(moduleNameOffset)
        mname = ""
        while True:
            c = li.read(1)
            if c == '\0':
                break
            mname += c

        indexeds = []
        li.seek(indexed)
        for i in range(indexedNum):
            indexeds.append(struct.unpack('<II', li.read(8)))

        anonymouses = []
        li.seek(anonymous)
        for i in range(anonymousNum):
            anonymouses.append(struct.unpack('<II', li.read(8)))

        for i in indexeds:
            index, batchOffset = i
            do_import_batch(li, segmentAddress, batchOffset, "%s_%d"%(mname, index))

        for i in anonymouses:
            tag, batchOffset = i
            do_import_batch(li, segmentAddress, batchOffset, "%s_%08X"%(mname, tag))

    # export
    li.seek(ExportNamedSymbolTableOffset)
    exportNamedSymbolTable = []
    for i in range(ExportNamedSymbolNum):
        exportNamedSymbolTable.append(struct.unpack('<II', li.read(8)))

    for exportNamedSymbol in exportNamedSymbolTable:
        nameOffset, target = exportNamedSymbol
        target_offset = DecodeTag(segmentAddress, target)
        li.seek(nameOffset)
        name = ""
        while True:
            c = li.read(1)
            if c == '\0':
                break
            name += c
        idaapi.add_entry(target_offset, target_offset, name, idaapi.segtype(target_offset) == idaapi.SEG_CODE)
        idaapi.make_name_public(target_offset)

    li.seek(ExportIndexedSymbolTableOffset)
    for i in range(ExportIndexedSymbolNum):
        target, = struct.unpack('<I', li.read(4))
        target_offset = DecodeTag(segmentAddress, target)
        idaapi.add_entry(i, target_offset, "indexedExport_%d" % i, idaapi.segtype(target_offset) == idaapi.SEG_CODE)
        idaapi.make_name_public(target_offset)

def load_file(li, neflags, format):

    if format == CRO_FORMAT_NAME:

        idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)

        load_cro(li, False)

        print "Load OK"
        return 1

    return 0

def load_crs(name):
    f = open(name, "rb")
    load_cro(f, True)
    f.close()
