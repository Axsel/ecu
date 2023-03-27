from enum import Enum

class Endian(Enum):
    HiLo = 1 # default
    LoHi = 2

class Sign(Enum):
    Unsigned = 1 # default
    Signed = 2

class TableType(Enum):
    OneByOne = 1
    OneByX = 2
    XbyX = 2
    XbyY = 3

# cell represents series a single or a series of data points of the table (data or axises)
class Cell:
    # name, offset in file, single cell element size in bytes (1 byte, 2 word), conversion factor, endianness (default 1 for HiLo)
    def __init__(self, name, file_offset, element_size=1, conversion_factor=1.0, endian=Endian.HiLo, sign=Sign.Unsigned):
        self.name=name
        self.offset=file_offset
        self.element_size=element_size
        self.conversion_factor=conversion_factor
        self.endian=endian
        self.sign=sign
        return

# axis is just a row of cells
class Axis(Cell):
    # name, offset in file, single cell element size in bytes (1 byte, 2 word), count of elements conversion factor, endianness (default 1 for HiLo)
    def __init__(self, name, file_offset, element_size=1, element_count=1, conversion_factor=1.0, endian=Endian.HiLo, sign=Sign.Unsigned):
        super().__init__(name, file_offset, element_size, conversion_factor, endian, sign)
        self.element_count = element_count
        self.size_in_bytes = element_count * element_size
        return

class Table:
    # 1x1 XxX XxY
    # pass empty list as axises for 1x1
    def __init__(self, cell: Cell, axises: list):
        if len(axises) == 0:
            self.table_type = TableType.OneByOne
        elif len(axises) == 1:
            self.table_type = TableType.OneByX
        elif len(axises) == 2:
            if axises[0].element_count == axises[1].element_count:
                self.table_type = TableType.XbyX
            else:
                self.table_type = TableType.XbyY
        else: 
            raise Exception("unknown table type")

        # first column, then row axis!
        self.axises = axises
        self.cell = cell
        # identify the table by the core data name
        if cell is not None:
            self.name = cell.name
        elif len(axises) > 0:
            self.name = axises[0].name
        return

class TableReader:
    def __init__(self, table: Table, me7):
        self.table_name = table.name
        self.table = table
        self.me7 = me7

        if self.table.table_type == TableType.OneByOne:
            self.max_element_count = 1
        elif self.table.table_type == TableType.OneByX:
            self.max_element_count = self.table.axises[0].element_count
        elif self.table.table_type == TableType.XbyX:
            self.max_element_count = self.table.axises[0].element_count * self.table.axises[0].element_count
        elif self.table.table_type == TableType.XbyY:
            self.max_element_count = self.table.axises[0].element_count * self.table.axises[1].element_count            
        else:
            raise Exception("unknown table type")

    def read_datacell_at(self, idx):
        offset = self.table.cell.offset
        element_size = self.table.cell.element_size

        if idx >= self.max_element_count:
            raise Exception("attempting to read out of table bouds")
        val = 0
        if element_size == 1:
            if self.table.cell.sign == Sign.Signed:
                val = self.me7.disasm.read_byte_signed(offset+(element_size*idx))
            else:
                val = self.me7.disasm.read_byte(offset+(element_size*idx))
        elif element_size == 2:
            if self.table.cell.sign == Sign.Signed:
                val = self.me7.disasm.read_word_signed(offset+(element_size*idx))
            else:
                val = self.me7.disasm.read_word(offset+(element_size*idx))
        else:
            raise Exception("unknown cell size")
        
        #TODO handle endian as well

        val = val * self.table.cell.conversion_factor
        return f"{val:.2f}"

    def read_axis_at(self, axis_name, idx):
        for a in self.table.axises:
            if a.name == axis_name:
                if idx >= a.element_count:
                    raise Exception("attempting to read out of table bounds")
                
                if a.element_size == 1:
                    val = self.me7.disasm.read_byte(a.offset+(a.element_size*idx))
                elif a.element_size == 2:
                    val = self.me7.disasm.read_word(a.offset+(a.element_size*idx))
                else:
                    raise Exception("unknown cell size")

                #TODO handle endian and sign as well

                val = val * a.conversion_factor
                return f"{val:.2f}"

        raise Exception("unknown axis")

    def print_table(self):
        col_name = self.table.axises[0].name
        col_len = self.table.axises[0].element_count
        row_name = self.table.axises[1].name
        row_len = self.table.axises[1].element_count

        hdr_row_values = [str(self.read_axis_at(row_name, i)) for i in range(0, row_len)]
        hdr_col_values = [str(self.read_axis_at(col_name, i)) for i in range(0, col_len)]

        col_header = "X\t\t" + "\t".join(hdr_col_values) + "\n"
        print(col_header)
        
        #for i in range(0, len(hdr_row_values)):
        #    row_header = hdr_row_values[i]
        #    row_values = [str(self.read_datacell_at(x)) for x in range(i*col_len,i*col_len+col_len)]
        #    row = row_header + "\t\t" + "\t".join(row_values)
        #    print(row)

        row_values = [str(self.read_datacell_at(i)) for i in range(0, self.max_element_count)]
        for i in range(0, len(hdr_row_values)):
            row_header = hdr_row_values[i]
            row = row_header + "\t\t" + "\t".join(row_values[i*col_len:i*col_len+col_len])
            print(row)
        

