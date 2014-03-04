#-------------------------------------------------------------------------------
# elftools: elf/dynamic.py
#
# ELF Dynamic Tags
#
# Mike Frysinger (vapier@gentoo.org)
# This code is in the public domain
#-------------------------------------------------------------------------------
import itertools

from .sections import Section
from .segments import Segment
from ..common.utils import struct_parse, parse_cstring_from_stream
from ..common.exceptions import ELFError
from ..elf.relocation import Relocation

from .enums import ENUM_D_TAG


class DynamicRelocations(object):
    def __init__(self, entry, struct, elffile):
        self.base, self.size = entry
        self.base -= elffile.loadbase
        self.struct = struct
        self.elffile = elffile

    def num_relocations(self):
        return self.size / self.struct.sizeof()

    def get_relocation(self, n):
        entry_offset = self.base + n * self.struct.sizeof()
        entry = struct_parse(
                self.struct,
                self.elffile.stream,
                stream_pos = entry_offset)
        return Relocation(entry, self.elffile)

    def iter_relocations(self):
        for i in range(self.num_relocations()):
            yield self.get_relocation(i)

    def __str__(self):
        return '<DynamicRelocations %s>' % ', '.join(map(str, self.iter_relocations()))

class DynamicSymbols(object):
    def __init__(self, entry, elffile, strtab = None):
        self.base = entry - elffile.loadbase
        self.struct = elffile.structs.Elf_Sym
        self.elffile = elffile
        self.strtab = strtab

    def get_symbol(self, n):
        entry_offset = self.base + n * self.struct.sizeof()
        entry = struct_parse(
                self.struct,
                self.elffile.stream,
                stream_pos = entry_offset)
        if self.strtab:
            entry['st_name_idx'] = entry['st_name']
            entry['st_name'] = parse_cstring_from_stream( \
                    self.elffile.stream, self.strtab + entry['st_name'])
        return entry


class DynamicTag(object):
    """ Dynamic Tag object - representing a single dynamic tag entry from a
        dynamic section.

        Allows dictionary-like access to the dynamic structure. For special
        tags (those listed in the _HANDLED_TAGS set below), creates additional
        attributes for convenience. For example, .soname will contain the actual
        value of DT_SONAME (fetched from the dynamic symbol table).
    """
    _HANDLED_TAGS = frozenset(
        ['DT_NEEDED', 'DT_RPATH', 'DT_RUNPATH', 'DT_SONAME',
         'DT_SUNW_FILTER'])

    _MANGLED_TAGS = frozenset(
        ['DT_HASH','DT_GNU_HASH','DT_STRTAB','DT_SYMTAB','DT_DEBUG',
            'DT_PLTGOT','DT_JMPREL','DT_RELA','DT_VERSYM','DT_REL'])

    _REL_TAGS = frozenset(['DT_REL', 'DT_RELA', 'DT_JMPREL'])

    def __init__(self, entry, elffile, dyn):
        self.entry = entry
        self.loadbase = elffile.loadbase
        if entry.d_tag in self._HANDLED_TAGS:
            try:
                strtab = dyn['DT_STRTAB'].entry.d_ptr
            except KeyError:
                raise ELFError('no DT_STRTAB found!')

            dynstr = elffile.get_segment_by_address(strtab)
            if not dynstr:
                raise ELFError('could not find DT_STRTAB=%x segment, maybe wrong loadbase?' \
                        % strtab)
            if elffile.loadbase:
                off = strtab - (dynstr['p_vaddr'] - elffile.get_min_vaddr()) - elffile.loadbase + dynstr['p_offset']
            else:
                off = strtab
            off += entry.d_ptr
            string = parse_cstring_from_stream(elffile.stream, off)
            setattr(self, entry.d_tag[3:].lower(), string)

        elif entry.d_tag in self._REL_TAGS:
            if entry.d_tag == 'DT_JMPREL':
                # FIXME: consult DT_PLTREL
                tag = 'DT_RELA'
                sizet = 'DT_PLTRELSZ'
            else:
                tag = entry.d_tag
                sizet = tag + 'SZ'

            if tag == 'DT_RELA':
                struct = elffile.structs.Elf_Rela
            elif tag == 'DT_REL':
                struct = elffile.structs.Elf_Rel

            try:
                size = dyn[sizet].entry.d_ptr
            except KeyError:
                raise ELFError('could not find %s for %s' % (sizet, entry.d_tag))

            rel = DynamicRelocations((entry.d_ptr, size), struct, elffile)

            setattr(self, entry.d_tag[3:].lower(), rel)
        elif entry.d_tag == 'DT_SYMTAB':
            try:
                strtab = dyn['DT_STRTAB'].entry.d_ptr
            except KeyError:
                raise ELFError('no DT_STRTAB found!')

            dynstr = elffile.get_segment_by_address(strtab)
            if not dynstr:
                raise ELFError('could not find DT_STRTAB segment, maybe wrong loadbase?')
            delta = strtab - elffile.loadbase - dynstr['p_vaddr']
            strtab = dynstr['p_offset'] + delta
            symtab = DynamicSymbols(entry.d_ptr, elffile, strtab)

            setattr(self, 'symtab', symtab)

    def ismangled(self):
        """ Does a typical loader mangle this tag in memory?
        """
        return self.loadbase and self.entry.d_tag in self._MANGLED_TAGS

    def __getitem__(self, name):
        """ Implement dict-like access to entries
        """
        return self.entry[name]

    def __repr__(self):
        return '<DynamicTag (%s): %r>' % (self.entry.d_tag, self.entry)

    def __str__(self):
        if self.entry.d_tag in self._HANDLED_TAGS:
            s = '"%s"' % getattr(self, self.entry.d_tag[3:].lower())
        elif self.entry.d_tag in self._REL_TAGS:
            s = getattr(self, self.entry.d_tag[3:].lower())
        else:
            s = '%#x' % self.entry.d_ptr
        return '<DynamicTag (%s) %s>' % (self.entry.d_tag, s)


class Dynamic(object):
    """ Shared functionality between dynamic sections and segments.
    """
    def __init__(self, stream, elffile, position):
        self._stream = stream
        self._elffile = elffile
        self._elfstructs = elffile.structs
        self._num_tags = -1
        self._offset = position
        self._tagsize = self._elfstructs.Elf_Dyn.sizeof()
        self._cache = dict()
    
    def __getitem__(self, name):
        """ Implement dict-like access to entries
        """
        if name in self._cache:
            return self._cache[name]

        for n in itertools.count():
            offset = self._offset + n * self._tagsize
            entry = struct_parse(
                self._elfstructs.Elf_Dyn,
                self._stream,
                stream_pos=offset)

            if entry.d_tag == 'DT_NULL':
                break

            if entry.d_tag == name:
                entry = DynamicTag(entry, self._elffile, self)
                self._cache[name] = entry
                return entry

        raise KeyError(name)

    def iter_tags(self, type=None):
        """ Yield all tags (limit to |type| if specified)
        """
        for n in itertools.count():
            tag = self.get_tag(n)
            if type is None or tag.entry.d_tag == type:
                yield tag
            if tag.entry.d_tag == 'DT_NULL':
                break

    def get_tag(self, n):
        """ Get the tag at index #n from the file (DynamicTag object)
        """
        offset = self._offset + n * self._tagsize
        entry = struct_parse(
            self._elfstructs.Elf_Dyn,
            self._stream,
            stream_pos=offset)
        return DynamicTag(entry, self._elffile, self)

    def num_tags(self):
        """ Number of dynamic tags in the file
        """
        if self._num_tags != -1:
            return self._num_tags

        for n in itertools.count():
            tag = self.get_tag(n)
            if tag.entry.d_tag == 'DT_NULL':
                self._num_tags = n + 1
                return self._num_tags


class DynamicSection(Section, Dynamic):
    """ ELF dynamic table section.  Knows how to process the list of tags.
    """
    def __init__(self, header, name, stream, elffile):
        Section.__init__(self, header, name, stream)
        Dynamic.__init__(self, stream, elffile, self['sh_offset'])

    def __getitem__(self, name):
        try:
            if isinstance(self, Segment):
                return Segment.__getitem__(self, name)
            else:
                return Section.__getitem__(self, name)
        except KeyError:
            return Dynamic.__getitem__(self, name)

class DynamicSegment(Segment, Dynamic):
    """ ELF dynamic table segment.  Knows how to process the list of tags.
    """
    def __init__(self, header, stream, elffile):
        Segment.__init__(self, header, stream)
        Dynamic.__init__(self, stream, elffile, \
                self['p_vaddr'] - elffile.get_min_vaddr() \
                if elffile.loadbase else self['p_offset'])

    def __getitem__(self, name):
        try:
            return Segment.__getitem__(self, name)
        except KeyError:
            return Dynamic.__getitem__(self, name)
