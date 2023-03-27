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