import std.algorithm;
import std.bitmanip;
import std.conv;
import std.exception;
import std.file;
import std.format;
import std.math : abs;
import std.path;
import std.range;
import std.socket : InternetAddress, Socket, SocketException, SocketSet, TcpSocket, SocketOption, SocketOptionLevel;
import std.stdio;
import std.string;
import elf;

Socket gdb;

enum mem_size = 0x100000000;
enum mem_base = 0x1000; // reserve first 4K page, to catch null pointers
enum mem_top = mem_base + mem_size;

enum SIGTRAP = 5;

struct System {
    RV32_CPU cpu;
    ubyte[] mem;
    int signal;
    bool stopped;
    uint[uint] breakpoints;
}

struct RV32_CPU {
    uint[32] regs;
    uint pc;
}

void write_mem(ubyte[] mem, uint addr, ubyte[] values) {
    mem[addr .. addr+values.length] = values[];
}

ref ubyte u8(ubyte[] mem, uint addr) {
    auto ptr = cast(ubyte*)(mem.ptr + addr);
    return *ptr;
}

ref ushort u16(ubyte[] mem, uint addr) {
    auto ptr = cast(ushort*)(mem.ptr + addr);
    return *ptr;
}

ref uint u32(ubyte[] mem, uint addr) {
    auto ptr = cast(uint*)(mem.ptr + addr);
    return *ptr;
}

bool in_mem_bounds(uint address) {
    return address >= mem_base &&
        address < mem_top;
}

void trap(System* system, string msg) {
    writeln(msg);
    (&system.cpu).print_regs();
    throw new Exception("stop");
}

ubyte read8(System* system, uint address) {
    if(!in_mem_bounds(address)) {
        writefln("READ8 %08X", address);
        trap(system, "segfault");
    }

    auto r = system.mem.u8(address);
    return r;
}

ushort read16(System* system, uint address) {
    if(!in_mem_bounds(address)) {
        writefln("READ16 %08X", address);
        trap(system, "segfault");
    }

    auto r = system.mem.u16(address);
    return r;
}

uint read32(System* system, uint address) {
    if(!in_mem_bounds(address)) {
        writefln("READ32 %08X", address);
        trap(system, "segfault");
    }

    if((address & 0b11) != 0) {
        writefln("READ32 %08X", address);
        trap(system, "unaligned load");
    }

    return system.mem.u32(address);
}

void write8(System* system, uint address, ubyte value) {
    if(!in_mem_bounds(address)) {
        trap(system, "segfault");
    }

    system.mem.u8(address) = value;
}

void write16(System* system, uint address, ushort value) {
    if(!in_mem_bounds(address)) {
        trap(system, "segfault");
    }

    if((address & 1) != 0) {
        trap(system, "unaligned store");
    }

    system.mem.u16(address) = value;
}

void write32(System* system, uint address, uint value) {
    if(!in_mem_bounds(address)) {
        writefln("WRITE32 %08X %X", address, value);
        trap(system, "segfault");
    }

    if((address & 0b11) != 0) {
        writefln("unaligned store to %08X", address);
        trap(system, "unaligned store");
    }

    system.mem.u32(address) = value;
}

char[] read_mem_str(System* system, uint addr) {
    char[] s;
    int c;
    do {
        assert(in_mem_bounds(addr));
        c = system.read8(addr);
        ++addr;
    } while(c != 0);
    return s;
}

void load(System* system, string elfFile)
{
    alias uint32_t = uint;

    struct Elf32_Phdr {
      uint32_t p_type;
      uint32_t p_offset;
      uint32_t p_vaddr;
      uint32_t p_paddr;
      uint32_t p_filesz;
      uint32_t p_memsz;
      uint32_t p_flags;
      uint32_t p_align;
    }

    ELF e = ELF.fromFile(elfFile);

    enum section = ".symtab";
	ELFSection s = e.getSection(section);

    auto pho = e.header.programHeaderOffset;
    auto num = e.header.numberOfProgramHeaderEntries;
    ubyte[] bin = cast(ubyte[]) std.file.read(elfFile);
    Elf32_Phdr* ph = cast(Elf32_Phdr*) (bin[pho .. pho + Elf32_Phdr.sizeof]).ptr;

    foreach(p; ph[0..num]) {
        auto writeStart = p.p_vaddr;
        auto writeFileStart = p.p_offset;
        auto writeEnd = p.p_vaddr + p.p_filesz;
        auto writeFileEnd = p.p_offset + p.p_filesz;

        while((writeStart & 0b1111) != 0) {
            writeStart--;
            writeFileStart--;
        }

        while((writeEnd & 0b1111) != 0) {
            writeEnd++;
            writeFileEnd++;
        }

        write_mem(system.mem, writeStart, bin[writeFileStart .. writeFileEnd]);

        auto zeroStart = p.p_vaddr + p.p_filesz;
        auto zeroEnd = p.p_vaddr + p.p_memsz;
        auto zeroSize = zeroEnd - zeroStart;

        if(zeroSize == 0) {
            continue;
        }

        while((zeroStart & 0b1111) != 0) {
            zeroStart++;
        }

        ubyte[] zeros = (cast(ubyte) 0).repeat.take(zeroSize).array;

        while((zeros.length & 0b1111) != 0) {
            zeros ~= 0;
        }

        write_mem(system.mem, zeroStart, zeros);
    }
}

immutable reg_abi_names = [
    "zero", "ra", "sp", "gp",
    "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1",
    "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3",
    "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
];

void print_regs(RV32_CPU* cpu)
{
    writefln("REGs at %08X", cpu.pc);

    foreach(j; 0 .. 32/4) {
        foreach(i; 0 .. 4) {
            auto reg = j*4+i;
            writef("%-04s: %08X  ", reg_abi_names[reg], cpu.regs[reg]);
        }

        writeln();
    }
}

pragma(inline, true)
uint mask(int start, int stop) {
    uint m = 0;

    foreach(i; start .. stop+1) {
        m = (m << 1) | 1;
    }

    return m << start;
}

pragma(inline, true)
uint bits(int start, int stop)(uint value) {
    assert(stop >= start);
    enum m = mask(start, stop);
    return (value & m) >> start;
}

pragma(inline, true)
int signext(uint value, int signBit) {
    auto shiftDistance = 31 - signBit;
    int svalue = value << shiftDistance;
    return svalue >> shiftDistance;
}

pragma(inline, true)
auto rn(int reg) {
    return reg_abi_names[reg];
}

void add_breakpoint(System* system, uint addr) {
    assert((addr & 0b11) == 0); // only aligned addrs for now
    auto instr = read32(system, addr);
    system.breakpoints[addr] = instr;
    write32(system, addr, 0);
}

void remove_breakpoint(System* system, uint addr) {
    auto instr = system.breakpoints[addr];
    write32(system, addr, instr);
    system.breakpoints.remove(addr);
}

bool has_breakpoint(System* system, uint addr) {
    return (addr in system.breakpoints) !is null;
}

void execute(System* system, int steps)
{
    RV32_CPU* cpu = &system.cpu;

    // if starting on a breakpoint, execute that instruction first
    /+
    if(has_breakpoint(system, cpu.pc)) {
        auto addr = cpu.pc;
        remove_breakpoint(system, addr);
        execute(system, 1);
        add_breakpoint(system, addr);
        --steps;
    }+/

    uint cycle;
    foreach(step; 0 .. steps)
    {
        auto inst = system.mem.u32(cpu.pc);
        //writefln("RUN %08X=%08X", cpu.pc, inst);

        auto is_valid_instr = inst & 0b11 && ((inst & 0b11100) != 0b11100);
        if(!is_valid_instr) {
            system.stopped = true;
            return;
        }

        uint opcode = inst & 0b111_1111;

        uint rd = inst.bits!(7, 11);
        uint funct3 = inst.bits!(12, 14);
        uint rs1 = inst.bits!(15, 19);
        uint rs2 = inst.bits!(20, 24);
        uint funct7 = inst.bits!(25, 31);
        alias shamt = rs2;

        int iimm = inst.bits!(20, 31).signext(11);

        int simm = inst.bits!(25, 31);
        simm = (simm << 5) | rd;
        simm = simm.signext(11);

        int uimm = inst & mask(12, 31);

        switch(opcode)
        {
            case 0b0110111:
            {
                if(rd != 0)
                    cpu.regs[rd] = uimm;
                break;
            }

            case 0b1101111: {
                int jimm = inst.bits!(31, 31);
                jimm = (jimm << 8) | inst.bits!(12, 19);
                jimm = (jimm << 1) | inst.bits!(20, 20);
                jimm = (jimm << 10) | inst.bits!(21, 30);
                jimm = (jimm << 1).signext(20);

                auto retpc = cpu.pc + 4;
                cpu.pc += jimm;
                if(rd != 0)
                    cpu.regs[rd] = retpc;

                break;
            }

            case 0b1100111: {
                assert((iimm & 0b11) == 0);
                auto retpc = cpu.pc + 4;
                cpu.pc = (cpu.regs[rs1] + iimm) & ~1;
                if(rd != 0) {
                    cpu.regs[rd] = retpc;
                }
                assert((cpu.pc & 0b11) == 0);
                break;
            }

            case 0b1100011: {
                int sbimm = inst.bits!(31, 31);
                sbimm = (sbimm << 1) | inst.bits!(7, 7);
                sbimm = (sbimm << 6) | inst.bits!(25, 30);
                sbimm = (sbimm << 4) | inst.bits!(8, 11);
                sbimm = (sbimm << 1).signext(12);

                switch(funct3) {
                    case 0b000: {
                        if(cpu.regs[rs1] == cpu.regs[rs2])
                            cpu.pc += sbimm;
                        else
                            cpu.pc += 4;

                        break;
                    }

                    case 0b001: {
                        if(cpu.regs[rs1] != cpu.regs[rs2]) {
                            cpu.pc += sbimm;
                        }
                        else {
                            cpu.pc += 4;
                        }
                        break;
                    }

                    case 0b100: {
                        if(cast(int)cpu.regs[rs1] < cast(int)cpu.regs[rs2]) {
                            cpu.pc += sbimm;
                        } else {
                            cpu.pc += 4;
                        }

                        break;
                    }

                    case 0b101: {
                        if(cast(int)cpu.regs[rs1] >= cast(int)cpu.regs[rs2]) {
                            cpu.pc += sbimm;
                        } else {
                            cpu.pc += 4;
                        }
                        break;
                    }

                    case 0b110: {
                        if(cpu.regs[rs1] < cpu.regs[rs2]) {
                            cpu.pc += sbimm;
                        } else {
                            cpu.pc += 4;
                        }
                        break;
                    }

                    case 0b111: {
                        if(cpu.regs[rs1] >= cpu.regs[rs2]) {
                            cpu.pc += sbimm;
                        } else {
                            cpu.pc += 4;
                        }
                        break;
                    }

                    default: {
                        system.stopped = true;
                        return;
                    }
                }

                break;
            }

            case 0b0000011: {
                switch(funct3) {
                    case 0b000: {
                        auto v = cast(byte) system.read8(cpu.regs[rs1] + iimm);
                        if(rd != 0) {
                            cpu.regs[rd] = v;
                        }
                        break;
                    }

                    case 0b001: {
                        auto v = cast(short) system.read16(cpu.regs[rs1] + iimm);
                        if(rd != 0) {
                            cpu.regs[rd] = v;
                        }
                        break;
                    }

                    case 0b010: {
                        auto v = system.read32(cpu.regs[rs1] + iimm);
                        if(rd != 0) {
                            cpu.regs[rd] = v;
                        }
                        break;
                    }

                    case 0b100: {
                        auto v = system.read8(cpu.regs[rs1] + iimm);
                        if(rd != 0) {
                            cpu.regs[rd] = v;
                        }
                        break;
                    }

                    case 0b101: {
                        auto v = system.read16(cpu.regs[rs1] + iimm);
                        if(rd != 0) {
                            cpu.regs[rd] = v;
                        }
                        break;
                    }

                    default:
                        system.stopped = true;
                        return;
                }

                break;
            }

            case 0b0100011: {
                switch(funct3) {
                    case 0b000: {
                        system.write8(cpu.regs[rs1] + simm, cast(ubyte) cpu.regs[rs2]);
                        break;
                    }

                    case 0b001: {
                        system.write16(cpu.regs[rs1] + simm, cast(ushort) cpu.regs[rs2]);
                        break;
                    }

                    case 0b010: {
                        system.write32(cpu.regs[rs1] + simm, cpu.regs[rs2]);
                        break;
                    }

                    default:
                        system.stopped = true;
                        return;
                }

                break;
            }

            case 0b0010011: {
                auto rdz = rd != 0;
                uint r;

                switch(funct3) {
                    case 0b000: {
                        r = cpu.regs[rs1] + iimm;
                        break;
                    }
                    case 0b010: {
                        r = cast(int)cpu.regs[rs1] < iimm ? 1 : 0;
                        break;
                    }

                    case 0b011: {
                        r = cpu.regs[rs1] < iimm ? 1 : 0;
                        break;
                    }

                    case 0b100: {
                        r = cpu.regs[rs1] ^ iimm;
                        break;
                    }

                    case 0b110: {
                        r = cpu.regs[rs1] | iimm;
                        break;
                    }

                    case 0b111: {
                        r = cpu.regs[rs1] & iimm;
                        break;
                    }

                    case 0b001: {
                        r = cpu.regs[rs1] << (shamt & 31);
                        break;
                    }

                    case 0b101: {
                        if(inst.bits!(30, 30) == 0) {
                            r = cpu.regs[rs1] >> (shamt & 31);
                        } else {
                            r = (cast(int)cpu.regs[rs1]) >> (shamt & 31);
                        }
                        break;
                    }

                    default:
                        writeln("funct3: ", funct3);
                        assert(0);
                }

                if(rdz) {
                    cpu.regs[rd] = r;
                }

                break;
            }

            case 0b0110011: {
                auto rdz = rd != 0;
                uint r;

                if(inst.bits!(25, 25) == 1) {
                    switch(funct3) {
                        case 0b000: {
                            r = cast(int)cpu.regs[rs1] * cast(int)cpu.regs[rs2];
                            break;
                        }

                        case 0b001: {
                            r = cast(uint)((cast(long)cpu.regs[rs1] * cast(long)cpu.regs[rs2]) >> 32);
                            break;
                        }

                        case 0b011: {
                            r = cast(uint)((cast(ulong)cpu.regs[rs1] * cast(ulong)cpu.regs[rs2]) >> 32);
                            break;
                        }

                        case 0b100: {
                            r = cast(int)cpu.regs[rs1] / cast(int)cpu.regs[rs2];
                            break;
                        }

                        case 0b111: {
                            r = cpu.regs[rs1] % cpu.regs[rs2];
                            break;
                        }

                        default: {
                            writeln("funct3: ", funct3);
                            system.stopped = true;
                            return;
                        }
                    }
                }
                else {
                    switch(funct3) {
                        case 0b000: {
                            if(inst.bits!(30, 30) == 0) {
                                r = cpu.regs[rs1] + cpu.regs[rs2];
                                break;
                            } else {
                                r = cpu.regs[rs1] - cpu.regs[rs2];
                                break;
                            }
                        }

                        case 0b001: {
                            r = cpu.regs[rs1] << (cpu.regs[rs2] & 31);
                            break;
                        }

                        case 0b010: {
                            r = cast(int)cpu.regs[rs1] < cast(int)cpu.regs[rs2] ? 1 : 0;
                            break;
                        }

                        case 0b011: {
                            r = cpu.regs[rs1] < cpu.regs[rs2] ? 1 : 0;
                            break;
                        }

                        case 0b100: {
                            r = cpu.regs[rs1] ^ cpu.regs[rs2];
                            break;
                        }

                        case 0b101: {
                            if(inst.bits!(30, 30) == 0)
                                r = cpu.regs[rs1] >> (cpu.regs[rs2] & 31);
                            else
                                r = cast(int)cpu.regs[rs1] >> (cpu.regs[rs2] & 31);
                            break;
                        }

                        case 0b110: {
                            r = cpu.regs[rs1] | cpu.regs[rs2];
                            break;
                        }

                        case 0b111: {
                            r = cpu.regs[rs1] & cpu.regs[rs2];
                            break;
                        }

                        default: {
                            writeln("funct3: ", funct3);
                            system.stopped = true;
                            return;
                        }
                    }
                }

                if(rdz) {
                    cpu.regs[rd] = r;
                }

                break;
            }

            case 0b0001111: { // FENCE
                break;
            }

            case 0b1110011: { // ECALL, EBREAK, etc
                bool abort_flag;
                system.cpu.regs[10] = syscall(system, cpu.regs[17],
                    cpu.regs[10], cpu.regs[11], cpu.regs[12], abort_flag);
                if(abort_flag) {
                    return;
                }
                break;
            }

            case 0b0010111: { // AUIPC
                if(rd != 0) {
                    cpu.regs[rd] = uimm + cpu.pc;
                }
                break;
            }

            default: {
                writefln("%08X: %08X", cpu.pc, inst);
                cpu.print_regs();
                system.stopped = true;
                return;
            }
        }

        if(opcode != 0b1100111 && opcode != 0b1100011 && opcode != 0b1101111) {
            cpu.pc += 4;
        }

        ++cycle;
    }
}

extern(C) int fstat(int fd, void* statbuf);

uint syscall(System* system, uint num, uint arg1, uint arg2, uint arg3, ref bool abort) {
    switch(num) {
        case 64: { // write
            uint fd = arg1;
            uint buf = arg2;
            uint count = arg3;

            assert(fd == 1); // fd == stdout

            foreach(i; 0 .. count) {
                char c = system.read8(buf+i);
                write(c);
            }

            return count;
        }

        case 80: { // fstat
            ubyte[128] buf;
            auto ret = fstat(arg1, buf.ptr);
            if(ret != -1) {
                write_mem(system.mem, arg2, buf);
            }
            return ret;
        }

        case 93: { // exit
            abort = true;
            return 0;
        }

        case 214: { // sbrk
            return 0x200_0000; // TODO
        }

        default:
            writefln("Unsupported syscall %s", num);
            assert(false);
    }
}

System* create_system() {
    auto sys = new System;
    sys.mem = new ubyte[mem_size];
    sys.signal = 2;
    return sys;
}

void run_exe(string elf_file_name) {
    auto sys = create_system();

    sys.load(elf_file_name);

    sys.cpu.pc = 0x10094; // 0x1000;
    sys.cpu.regs[2] = 0x100_0000;   // SP
    sys.cpu.regs[3] = 0x23948;      // GP

    gdb_handle_msg(sys);
}

bool use_ack = true;
char[] msg_buffer;
void gdb_read_socket() {
    char[4096] read_buffer;
    auto msg_len = gdb.receive(read_buffer[]);
    assert(msg_len > 0);
    msg_buffer = msg_buffer ~ read_buffer[0 .. msg_len];
}

void gdb_start() {
    auto listener = new TcpSocket();
    listener.setOption(SocketOptionLevel.SOCKET, SocketOption.REUSEADDR, 1);
    assert(listener.isAlive);
    listener.blocking = true;
    listener.bind(new InternetAddress(1234));
    listener.listen(5);
    gdb = listener.accept();
    gdb_expect_ack();
}

void gdb_expect_ack() {
    if(!use_ack)
        return;
    if(msg_buffer.length == 0)
        gdb_read_socket();
    if(msg_buffer[0] != '+')
        writeln(msg_buffer);
    assert(msg_buffer[0] == '+');
    msg_buffer = msg_buffer[1 .. $];
}

void gdb_send_ack() {
    if(!use_ack)
        return;
    gdb.send("+");
}

string gdb_encode(string msg) {
    int sum = 0;
    foreach(c; msg) {
        assert(c != '}'); // TODO escaping
        sum = (sum + c) % 256;
    }
    return format("$%s#%02x", msg, sum);
}

void gdb_send_msg(string msg) {
    msg = gdb_encode(msg);
    gdb.send(msg);
    gdb_expect_ack();
}

char[] gdb_read_msg() {
    if(msg_buffer.length == 0)
        gdb_read_socket();

    assert(msg_buffer[0] == '$');

    int i = 1;

    while(1) {
        if(i >= msg_buffer.length) {
            gdb_read_socket();
            continue;
        }
        if(msg_buffer[i] == '}') {
            if(i+1 >= msg_buffer.length) {
                gdb_read_socket();
            }
            assert(false);
        }
        if(msg_buffer[i] == '#') {
            while(i+2 >= msg_buffer.length) {
                gdb_read_socket();
            }
            auto msg = msg_buffer[1 .. i];
            msg_buffer = msg_buffer[i+3 .. $];
            gdb_send_ack();
            return msg;
        }
        ++i;
    }
}

const(char[]) gdb_parse_cmd(const(char)[] msg) {
    assert(msg.length > 0);

    auto c = msg[0];
    if(c == 'm' || c == 'M' || c == 'H' || c == 'Z' || c == 'z' || c == 'x' || c == 'p') {
        auto cmd = msg[0 .. 1];
        //msg = msg[1 .. $];
        return cmd;
    }

    if(msg.canFind(":")) {
        return msg.findSplit(":")[0];
    }

    // TODO: handler other cases

    return msg;
}

void test_gdb_parse_cmd() {
    assert(gdb_parse_cmd("vMustReplyEmpty") == "vMustReplyEmpty");
    assert(gdb_parse_cmd("!") == "!");
    assert(gdb_parse_cmd("?") == "?");
    assert(gdb_parse_cmd("Hg0") == "H");
    assert(gdb_parse_cmd("Hc-1") == "H");
    assert(gdb_parse_cmd("qSymbol::") == "qSymbol");
    assert(gdb_parse_cmd("vCont?") == "vCont?");
    assert(gdb_parse_cmd("M101c0,4:73001000") == "M");
    assert(gdb_parse_cmd("qXfer:features:read:target.xml:0,fff") == "qXfer");
}

uint gdb_read_reg(System* sys, int reg) {
    switch(reg) {
        case 0: .. case 31: // GPRS
            return sys.cpu.regs[reg];
        case 32: // PC
            return sys.cpu.pc;
        case 4161: // priv
            return 0;
        default:
            assert(false);
    }
}


void gdb_handle_msg(System* sys) {
    /*
    From <https://sourceware.org/gdb/current/onlinedocs/gdb/Overview.html>

    At a minimum, a stub is required to support the ‘?’ command to tell GDB the
    reason for halting, ‘g’ and ‘G’ commands for register access, and the ‘m’
    and ‘M’ commands for memory access. Stubs that only control single-threaded
    targets can implement run control with the ‘c’ (continue) command, and if
    the target architecture supports hardware-assisted single-stepping, the ‘s’
    (step) command. Stubs that support multi-threading targets should support
    the ‘vCont’ command. All other commands are optional.
    */

    /*
    From <https://sourceware.org/gdb/current/onlinedocs/gdb/RISC_002dV-Features.html>

    The ‘org.gnu.gdb.riscv.cpu’ feature is required for RISC-V targets. It
    should contain the registers ‘x0’ through ‘x31’, and ‘pc’. Either the
    architectural names (‘x0’, ‘x1’, etc) can be used, or the ABI names
    (‘zero’, ‘ra’, etc).

    The ‘org.gnu.gdb.riscv.fpu’ feature is optional. (...)
    The ‘org.gnu.gdb.riscv.virtual’ feature is optional. (...)
    The ‘org.gnu.gdb.riscv.csr’ feature is optional (...)
    */

    while(1) {
        auto msg = gdb_read_msg();
        auto cmd = gdb_parse_cmd(msg);
        msg = msg[cmd.length .. $];
        writefln("CMD %s", cmd);

        switch(cmd) {
            // Extended mode. Persistent remote server.
            // 'R' cmd to restart program.
            case "!":
                gdb_send_msg("OK");
                break;

            case "?": // Stop reason
                //gdb_send_msg("S02");
                gdb_send_msg("T05thread:p01.01");
                break;

            case "p":
                auto reg = msg.to!int(16);
                writefln("READ REG %s", reg);
                auto val = gdb_read_reg(sys, reg);
                auto r = format("%08x", swapEndian(val));
                gdb_send_msg(r);
                break;

            case "g":
                string r;
                foreach(reg; 0 .. 32+1) {
                    auto val = gdb_read_reg(sys, reg);
                    r ~= format("%08x", swapEndian(val));
                }
                r ~= format("%02x", 0); // priv level
                gdb_send_msg(r);
                break;

            case "m":
            case "x":
                auto addr = msg.until(',').to!int(16);
                msg.findSkip(",");
                auto count = msg.to!int(16);
                string r;
                bool hex = cmd == "m";
                while(count) {
                    ubyte b = read8(sys, addr);
                    if(hex)
                        r = r ~ format("%02x", b);
                    else
                        r = r ~ b;
                    --count;
                    ++addr;
                }
                gdb_send_msg(r);
                break;

            case "z": // remove breakpoint
            case "Z": // add breakpoint
                assert(msg[0] == '0');
                assert(msg[1] == ',');
                msg.findSkip(",");
                auto addr = msg.until(',').to!int(16);
                msg.findSkip(",");
                auto kind = msg.to!int(16);
                if(cmd == "Z")
                    add_breakpoint(sys, addr);
                else
                    remove_breakpoint(sys, addr);
                gdb_send_msg("OK");
                break;

            case "H":
                msg.popFront();
                int tid;
                if(msg == "-1")
                    tid = -1;
                else
                    tid = msg.to!int(16);
                assert(tid == -1 || tid == 0 || tid == 1); // tid == 0 used by GDB
                gdb_send_msg("OK");
                break;

            case "vMustReplyEmpty":
                gdb_send_msg("");
                break;

            case "QStartNoAckMode":
                gdb_send_msg("OK");
                use_ack = false;
                break;

            case "qTStatus":
                gdb_send_msg("");
                break;

            case "qfThreadInfo":
                gdb_send_msg("m1"); // (just) thread id 1
                break;

            case "qsThreadInfo":
                gdb_send_msg("l"); // end of thread id list
                break;

            case "qC": // current thread Id
                gdb_send_msg("QC01");
                break;

            case "qAttached":
                gdb_send_msg("1");
                break;

            case "qOffsets":
                gdb_send_msg("Text=0;Data=0;Bss=0");
                break;

            case "qSymbol":
                assert(msg == "::");
                gdb_send_msg("OK");
                break;

            case "vCont?":
                gdb_send_msg("");
                break;

            case "s":
                sys.execute(1);
                gdb_send_msg("S05");
                break;

            case "c":
                sys.stopped = false;
                while(!sys.stopped) {
                    sys.execute(1024);
                }
                gdb_send_msg("S05");
                break;

            case "qSupported":
                gdb_send_msg("PacketSize=4000;qXfer:memory-map:read-;QStartNoAckMode+;qXfer:features:read+");
                break;

            case "qXfer":
                // Example: qXfer:features:read:target.xml:0,fff
                assert(msg[0] == ':');
                msg.findSkip(":");
                auto object = msg.until(':').array;
                assert(object == "features"); // TODO others
                msg.findSkip(":");
                auto read = msg.until(':').array;
                assert(read == "read");
                msg.findSkip(":");
                auto annex = msg.until(':').array;
                assert(annex == "target.xml"); // TODO others
                msg.findSkip(":");
                auto offset = msg.until(',').to!int(16);
                msg.findSkip(",");
                auto length = msg.to!int(16);
                //writefln("qXfer: %s %s %s", object, offset, length);
                immutable features = import("target.xml");
                auto end = min(features.length, offset+length);
                if(offset+length < features.length)
                    gdb_send_msg("m" ~ features[offset .. end]);
                else
                    gdb_send_msg("l" ~ features[offset .. end]);
                break;

            default:
                writefln("UNSUPPORTED gdb command [%s]", cmd);
                gdb_send_msg("");
        }
    }
}

void run_tests() {
    test_gdb_parse_cmd();
}

void main(string[] args) {
    run_tests();

    string execname;
    if(args.length > 1) {
        execname = args[1];
    }
    gdb_start();
    run_exe(execname);
}
