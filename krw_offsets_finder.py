import re
import sys

# Find krw functions. PACIBSP is optional to work on arm64 library aswell.
patterns = {
    "kreadbuf":
        rb'[\x7F\x23\x03\xD5]?'# PACIBSP
        rb'\xFD\x7B\xBF\xA9'   # STP             X29, X30, [SP,#-0x10+var_s0]!
        rb'\xFD\x03\x00\x91'   # MOV             X29, SP
        rb'\xE8\x03\x03\xAA'   # MOV             X8, X3
        rb'\xEA\x03\x02\xAA'   # MOV             X10, X2
        rb'\x09\x18\x40\xF9',  # LDR             X9, [X0,#0x30]
        
    "kwritebuf":
        rb'[\x7F\x23\x03\xD5]?'# PACIBSP
        rb'\xF6\x57\xBD\xA9'   # STP             X22, X21, [SP,#-0x10+var_20]!
        rb'\xF4\x4F\x01\xA9'   # STP             X20, X19, [SP,#0x20+var_10]
        rb'\xFD\x7B\x02\xA9'   # STP             X29, X30, [SP,#0x20+var_s0]
        rb'\xFD\x83\x00\x91'   # ADD             X29, SP, #0x20
        rb'\xF3\x03\x03\xAA'   # MOV             X19, X3
        rb'\xF4\x03\x02\xAA'   # MOV             X20, X2
        rb'\xF6\x03\x01\xAA'   # MOV             X22, X1
        rb'\xF5\x03\x00\xAA'   # MOV             X21, X0
        rb'\x08\xAC\x40\xF9'   # LDR             X8, [X0,#0x158]
        rb'\x09\x50\xA0\xD2'   # MOV             X9, #0x1F530F02800000
        rb'\xE9\x61\xCA\xF2'   # MOV             X9, #0x1F530F02800000
        rb'\xE9\x03\xE0\xF2'   # MOV             X9, #0x1F530F02800000
        rb'\x1F\x01\x09\xEB',  # CMP             X8, X9

#    "krw_task_for_pid":
#        rb'\xE3\x03\x02\xAA'   # MOV             X3, X2
#        rb'\x02\x00\x80\xD2'   # MOV             X2, #0; name is NULL
#        rb'\x01\x00\x00\x14',  # B               krw_task_for_pid_or_name; branch right next to it
    "krw_task_for_pid_or_name":
        rb'[\x7F\x23\x03\xD5]?'# PACIBSP
        rb'\xFF\x03\x01\xD1'   # SUB             SP, SP, #0x40
        rb'\xF6\x57\x01\xA9'   # STP             X22, X21, [SP,#0x30+var_20]
        rb'\xF4\x4F\x02\xA9'   # STP             X20, X19, [SP,#0x30+var_10]
        rb'\xFD\x7B\x03\xA9'   # STP             X29, X30, [SP,#0x30+var_s0]
        rb'\xFD\xC3\x00\x91'   # ADD             X29, SP, #0x30
        rb'\xF3\x03\x03\xAA'   # MOV             X19, X3
        rb'\xF5\x03\x02\xAA'   # MOV             X21, X2
        rb'\xF6\x03\x01\xAA'   # MOV             X22, X1
        rb'\xF4\x03\x00\xAA'   # MOV             X20, X0
        rb'\x3F\x04\x00\x71',  # CMP             W1, #1
        
    "port_name_to_kaddr":
        rb'[\x7F\x23\x03\xD5]?'# PACIBSP
        rb'\xF6\x57\xBD\xA9'   # 'STP             X22, X21, [SP,#-0x10+var_20]!
        rb'\xF4\x4F\x01\xA9'   # 'STP             X20, X19, [SP,#0x20+var_10]
        rb'\xFD\x7B\x02\xA9'   # 'STP             X29, X30, [SP,#0x20+var_s0]
        rb'\xFD\x83\x00\x91'   # 'ADD             X29, SP, #0x20
        rb'\xF4\x03\x01\xAA'   # 'MOV             X20, X1
        rb'\xF3\x03\x00\xAA'   # 'MOV             X19, X0
        rb'\x1F\x20\x03\xD5',  # 'NOP
        
    "task_get_ipc_port":
        rb'[\x7F\x23\x03\xD5]?'# PACIBSP
        rb'\xFF\xC3\x00\xD1'   # SUB             SP, SP, #0x30
        rb'\xF4\x4F\x01\xA9'   # STP             X20, X19, [SP,#0x20+var_10]
        rb'\xFD\x7B\x02\xA9'   # STP             X29, X30, [SP,#0x20+var_s0]
        rb'\xFD\x83\x00\x91'   # ADD             X29, SP, #0x20
        rb'\xF3\x03\x00\xAA'   # MOV             X19, X0
        rb'....'               # BL              sub_339B4
        rb'....'               # CBZ             X0, loc_33A78
        rb'\xE1\x03\x00\xAA'   # MOV             X1, X0
        rb'\xE2\x23\x00\x91'   # ADD             X2, SP, #0x20+var_18
        rb'\xE0\x03\x13\xAA',  # MOV             X0, X19
        
    "ipc_port_get_kobject":
        rb'[\x7F\x23\x03\xD5]?'# PACIBSP
        rb'\xFF\xC3\x00\xD1'   # SUB             SP, SP, #0x30
        rb'\xF4\x4F\x01\xA9'   # STP             X20, X19, [SP,#0x20+var_10]
        rb'\xFD\x7B\x02\xA9'   # STP             X29, X30, [SP,#0x20+var_s0]
        rb'\xFD\x83\x00\x91'   # ADD             X29, SP, #0x20
        rb'\xF4\x03\x01\xAA'   # MOV             X20, X1
        rb'\xF3\x03\x00\xAA'   # MOV             X19, X0
        rb'\xE2\x13\x00\x91',  # ADD             X2, SP, #0x20+var_1C
        
    "task_csflags_get_kaddr":
        rb'[\x7F\x23\x03\xD5]?'# PACIBSP
        rb'\xF4\x4F\xBE\xA9'   # STP             X20, X19, [SP,#-0x10+var_10]!
        rb'\xFD\x7B\x01\xA9'   # STP             X29, X30, [SP,#0x10+var_s0]
        rb'\xFD\x43\x00\x91'   # ADD             X29, SP, #0x10
        rb'\xF3\x03\x00\xAA'   # MOV             X19, X0
        rb'\x14\xB0\xBF\x92'   # MOV             X20, #-0xfd800001 ; =-4253024257
        rb'\xF4\x61\xCA\xF2'   # MOVK            X20, #0x530f, lsl #32
        rb'\xF4\x03\xE0\xF2'   # MOVK            X20, #0x1f, lsl #48
        rb'\x08\xAC\x40\xF9'   # LDR             X8, [X0,#0x158]
        rb'\x1F\x01\x14\xEB',  # CMP             X8, X20
}

with open(sys.argv[1], "rb") as f:
    data = f.read()

print(f"Read: {sys.argv[1]}")

counts = {name: 0 for name in patterns}
offsets = {}

# build combined regex with named groups
combined = re.compile(
    b"|".join(f"(?P<{name}>{pat.decode('latin1')})".encode('latin1')
              for name, pat in patterns.items())
)

for m in combined.finditer(data):
    name = m.lastgroup
    counts[name] += 1

    if counts[name] > 1:
        print(f"error: {name} has multiple matches", file=sys.stderr)
        sys.exit(1)

    offsets[name] = m.start()-3

# check missing
for name in patterns:
    if counts[name] == 0:
        print(f"{name}: NOT found", file=sys.stderr)
        #sys.exit(1)

# output
for name, off in offsets.items():
    print(f"{name}: {hex(off)}")
