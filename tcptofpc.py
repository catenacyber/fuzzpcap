#tshark -r input.pcap -qz "follow,tcp,raw,0"
import struct
import sys
import binascii
import subprocess


result = subprocess.Popen( ["tshark", "-r", sys.argv[1], "-qz", "follow,tcp,raw,0"],
                             stdout=subprocess.PIPE)
sys.stdout.buffer.write(b"FPC\x80")
for i in range(4):
    result.stdout.readline()
dp=result.stdout.readline().split(b":")[2]
sp=result.stdout.readline().split(b":")[2]
sys.stdout.buffer.write(struct.pack('>H', int(sp)))
sys.stdout.buffer.write(struct.pack('>H', int(dp)))

for l in result.stdout.readlines():
    s2c = 0
    if l[0] == 9:
        l = l[1:]
        s2c = 1
    try:
        r = binascii.unhexlify(l[:-1])
    except:
        continue
    sys.stdout.buffer.write(struct.pack('>B', int(s2c)))
    sys.stdout.buffer.write(r)
    sys.stdout.buffer.write(b"FPC0")
