import os

for i in range(256):
    if i < 16:
            byte = "0{}488B01C3C3C3C3".format(hex(i)[2:])
    else:
            byte = "{}488B01C3C3C3C3".format(hex(i)[2:])

    print("---------{}488B01C3C3C3C3---------".format(hex(i)[2:]))
    os.system("rasm2 -b 64 -d {}".format(byte))