import os
import hashlib
import pefile
import re
from config import Config

class PEAnalyzer:
    def __init__(self):
        self.pe = None
        self.filepath = None
        self.hashes = {}

    def load_file(self, filepath):
        self.filepath = filepath
        self.pe = pefile.PE(filepath)
        self._compute_hashes()
        
        return {
            'basic_info': self._get_basic_info(),
            'hashes': self.hashes,
            'pe_info': self._get_pe_info(),
            'sections': self._get_sections(),
            'imports': self._get_imports(),
            'exports': self._get_exports(),
            'strings': self.extract_strings()
        }

    def _compute_hashes(self):
        with open(self.filepath, 'rb') as f:
            data = f.read()
        self.hashes = {
            'MD5': hashlib.md5(data).hexdigest(),
            'SHA1': hashlib.sha1(data).hexdigest(),
            'SHA256': hashlib.sha256(data).hexdigest(),
        }

    def _get_basic_info(self):
        return {
            'Filename': os.path.basename(self.filepath),
            'Size': f"{os.path.getsize(self.filepath):,} bytes",
            'Type': 'PE32' if self.pe.OPTIONAL_HEADER.Magic == 0x10b else 'PE32+'
        }

    def _get_pe_info(self):
        return [
            f"Entry Point: {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}",
            f"Image Base: {hex(self.pe.OPTIONAL_HEADER.ImageBase)}",
            f"Sections: {self.pe.FILE_HEADER.NumberOfSections}"
        ]

    def _get_sections(self):
        sections = []
        for section in self.pe.sections:
            sections.append({
                'name': section.Name.decode(errors='ignore').strip('\x00'),
                'virtual_addr': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'raw_size': hex(section.SizeOfRawData)
            })
        return sections

    def _get_imports(self):
        imports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore')
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode(errors='ignore'))
                    else:
                        functions.append(f"Ordinal {imp.ordinal}")
                imports.append({'dll': dll_name, 'functions': functions})
        return imports

    def _get_exports(self):
        exports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode(errors='ignore') if exp.name else f"Ordinal {exp.ordinal}"
                addr = hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address)
                exports.append({'name': name, 'address': addr})
        return exports

    def extract_strings(self, min_length=5, filter_name="All"):
        with open(self.filepath, "rb") as f:
            data = f.read()

        all_strings = re.findall(rb"[ -~]{%d,}" % min_length, data)
        pattern = Config.FILTERS.get(filter_name)

        if pattern:
            return [s.decode(errors='ignore') for s in all_strings if pattern.search(s)]
        return [s.decode(errors='ignore') for s in all_strings] 