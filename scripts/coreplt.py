#!/usr/bin/python

import os.path, sys
sys.path.append(os.path.join(os.path.split(__file__)[0], '..'))

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSegment
from elftools.common.exceptions import ELFError
from sys import argv, stdin, stderr
from struct import unpack
from re import match
from itertools import count

if __name__ == '__main__':
    mappings = list()

    for mapping in stdin.readlines():
        m = match(r'^\s*\d+\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+' \
                r'((?:r|-)(?:w|-)(?:x|-))', mapping)
        start, end = map(lambda x: int(x, 16), m.groups()[:2])
        mappings.append((start, end, m.group(3), mapping))


    hooks = dict()
    deps = list()
    soname = '?'
    base = int(argv[2], 16)

    with open(argv[1], 'rb') as inp:
        try:
            elf = ELFFile(inp, loadbase = base)            
        except ELFError:
            exit(1)

        for seg in elf.iter_segments():
            if not isinstance(seg, DynamicSegment):
                continue

            try:
                soname = seg['DT_SONAME'].soname
                print >>stderr, seg['DT_SONAME']
            except KeyError:
                soname = 'main'

            for tag in seg.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    print >> stderr, tag
                    deps.append(tag.needed)

            try:
                symtab = seg['DT_SYMTAB'].symtab
            except KeyError:
                print >> stderr, 'No SYMTAB!'
                continue

            for i in count():
                sym = symtab.get_symbol(i)
                if not sym['st_name'] and sym['st_name_idx'] > 0:
                    break
                if sym['st_value']:
                    print '~%016x:%s' % (sym['st_value'] + base,sym['st_name'])

            try:
                tag = seg['DT_JMPREL']
            except KeyError:
                continue

            for reloc in tag.jmprel.iter_relocations():
                seg = elf.get_segment_by_address(reloc['r_offset']+elf.loadbase)
                offset = seg['p_offset'] + (reloc['r_offset'] - seg['p_vaddr'])

                elf.stream.seek(offset)
                fnaddr = elf.stream.read(elf.elfclass/8)

                if len(fnaddr) == 8:
                    fnaddr = unpack('<Q', fnaddr)[0]
                elif len(fnaddr) == 4:
                    fnaddr = unpack('<I', fnaddr)[0]
                else:
                    fnaddr = -1
                    
                sym = symtab.get_symbol(reloc['r_info_sym'])
                print >> stderr, '\033[34m%16s: %x\033[0m' % (sym['st_name'], fnaddr)

                for start, end, prot, full in mappings:
                    if start <= fnaddr and end > fnaddr and prot == 'rwx':
                        sym = symtab.get_symbol(reloc['r_info_sym'])
                        print >> stderr, '\033[31m', hex(offset), hex(reloc['r_offset'] + elf.loadbase), \
                                hex(fnaddr), '[%3i = %s]' % (reloc['r_info_sym'], sym['st_name']), '\033[0m'
                        #print >> stderr, ' `> ' + full.strip()
                        hooks[fnaddr] = sym['st_name']

 
    print '=' + soname

    for dep in deps:
        print '<' + dep

    for addr, target in hooks.iteritems():
        print '!%016x:%s' % (addr, target)

