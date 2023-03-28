class Pattern():
    # sig   [0x01, 0x02, 0x03, 0x0, 0x05]
    # mask  "xxx?x"
    def __init__(self, signature, mask):
        if len(signature) != len(mask):
            raise Exception("Pattern sig and mask length mismatch")

        self._signature = signature
        self._mask = mask
        self._pattern_len = len(mask) 

    def scan(self, bytes, max_len=0):
        results = []
        if max_len == 0:
            max_len = len(bytes)
        for i in range(0, max_len-self._pattern_len):
            for j in range(0, self._pattern_len):
                if self._mask[j] == "x":
                    if bytes[i+j] != self._signature[j]:
                        break
                if j == self._pattern_len-1:
                    results.append(i)
        return results

    def scan_reverse(self, bytes, max_len=0):
        results = []
        if max_len == 0:
            max_len = len(bytes)
        for i in range(max_len-self._pattern_len, 0, -1):
            for j in range(0, self._pattern_len):
                if self._mask[j] == "x":
                    if bytes[i+j] != self._signature[j]:
                        break
                if j == self._pattern_len-1:
                    results.append(i)
        return results

    def pattern_len(self):
        return self._pattern_len

class PatternWildcard():
    # sig   [0x01, 0x02, 0x03, 0x0, 0x05, 0, 0, 0xFF, 0xFF]
    # mask  "xxx?x**xx"
    # mask * = up to 10 bytes wildcard

    def __init__(self, signature, mask):
        self._patterns = list()
        self._maxlens = list()

        cur_pattern_bytes = list()
        cur_pattern_mask = ""
        skip = 0

        for i in range(0, len(mask)):
            if mask[i] == '*':
                skip += 10
            elif skip > 0:
                self._patterns.append(Pattern(cur_pattern_bytes, cur_pattern_mask))
                self._maxlens.append(skip)

                cur_pattern_bytes = list()
                cur_pattern_mask = ""
                skip = 0

                cur_pattern_bytes.append(signature[i])
                cur_pattern_mask += mask[i]
            else:
                cur_pattern_bytes.append(signature[i])
                cur_pattern_mask += mask[i]
                if i == len(mask)-1:
                    self._patterns.append(Pattern(cur_pattern_bytes, cur_pattern_mask))
                    #self._maxlens.append(skip)                    

    def _recurse_scan(self, bytes, patterns, maxlens, depth=0, max_depth=0, first_offset=0):
        if depth > max_depth:
            self._first_offsets.append(first_offset)
            return

        offsets_found = list()
        if depth == 0:
            offsets_found = patterns[depth].scan(bytes)
        else:
            offsets_found = patterns[depth].scan(bytes, maxlens[depth-1])

        for offset in offsets_found:
            new_bytes_to_scan = bytes[offset:]
            if first_offset == 0:
                self._recurse_scan(new_bytes_to_scan, patterns, maxlens, depth+1, max_depth, offset)
            else:
                self._recurse_scan(new_bytes_to_scan, patterns, maxlens, depth+1, max_depth, first_offset)
            

    def scan(self, bytes):
        self._first_offsets = list()
        self._recurse_scan(bytes, self._patterns, self._maxlens, 0, len(self._maxlens), 0)
        return self._first_offsets #list(set(self._first_offsets))
