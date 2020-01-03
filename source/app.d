import std.algorithm;
import std.file;
import std.math : abs;
import std.path;
import std.range;
import std.stdio;
import std.string;
import elf;

//version = Trace;
//version = TraceLoad;
version = GFX;

version(none)
{
    enum memMax = 0x80004000;
    enum systemAddr = 0xFFFF_FFFF;
}
else version(all)
{
    enum memMax = 0x80_0000;
    enum systemAddr = 0x8000_0000;
}
else
{
    enum memMax = 0x000000007fbecda0;
    enum systemAddr = 0x8000_0000;
}

struct RISCV32
{
    uint[32] regs;
    uint pc;
}

struct Symbol
{
    ulong addr;
    ulong size;
    string name;
    int count;
}

struct System
{
    RISCV32 cpu;
    ubyte[] mem;
    version(Profile) Symbol[] symbols;
}

void writeMem(ubyte[] mem, uint addr, ubyte[] values)
{
    mem[addr .. addr+values.length] = values[];
}

ref ubyte u8(ubyte[] mem, uint addr)
{
    auto ptr = cast(ubyte*)(mem.ptr + addr);
    return *ptr;
}

ref ushort u16(ubyte[] mem, uint addr)
{
    auto ptr = cast(ushort*)(mem.ptr + addr);
    return *ptr;
}

ref uint u32(ubyte[] mem, uint addr)
{
    auto ptr = cast(uint*)(mem.ptr + addr);
    return *ptr;
}

ubyte read8(System* system, uint address)
{
    if(address < systemAddr && address >= memMax || address < 0x1000)
    {
        writefln("READ8 %08X", address);
        writeln("segfault");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    auto r = system.mem.u8(address);
    version(Trace) writefln("READ8 %08X %08X", address, r);
    return r;
}

ushort read16(System* system, uint address)
{
    if(address < systemAddr && address >= memMax || address < 0x1000)
    {
        writefln("READ16 %08X", address);
        writeln("segfault");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    version(none) if((address & 1) != 0)
    {
        writefln("READ16 %08X", address);
        writeln("unaligned load");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    auto r = system.mem.u16(address);
    version(Trace) writefln("READ16 %08X %08X", address, r);
    return r;
}

uint read32(System* system, uint address)
{
    if(address < systemAddr && address >= memMax || address < 0x1000)
    {
        writefln("READ32 %08X", address);
        writeln("segfault");
        (&system.cpu).printRegs();
        writeln(opcount);
        throw new Exception("stop");
    }

    version(none) if((address & 0b11) != 0)
    {
        writefln("READ32 %08X", address);
        writeln("unaligned load");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    uint r;
    if(address >= systemAddr)
        r = 0;
    else
        r = system.mem.u32(address);

    version(Trace) writefln("READ32 %08X %08X", address, r);

    return r;
}

void write8(System* system, uint address, ubyte value)
{
    version(Trace) writefln("WRITE8 %08X %X", address, value);

    if(address < systemAddr && address >= memMax || address < 0x1000)
    {
        writeln("segfault");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    if(address < systemAddr)
        system.mem.u8(address) = value;
    else
    {
        version(all)
        {
            if(address == systemAddr) // UART
                write(cast(char) value);
        }
        else
        {
            writeln("###", cast(char) value);
            writeln(opcount);
            (&system.cpu).printRegs();

            static int count;
            if(++count > 6)
                throw new Exception("stop");
        }
    }
}

void write16(System* system, uint address, ushort value)
{
    version(Trace) writefln("WRITE16 %08X %X", address, value);

    if(address < systemAddr && address >= memMax || address < 0x1000)
    {
        writeln("segfault");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    if((address & 1) != 0)
    {
        writeln("unaligned store");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    assert(address < memMax);
    system.mem.u16(address) = value;
}

void write32(System* system, uint address, uint value)
{
    version(Trace) writefln("WRITE32 %08X %X", address, value);

    if(address < systemAddr && address >= memMax || address < 0x1000)
    {
        writefln("WRITE32 %08X %X", address, value);
        writeln("segfault");
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    if((address & 0b11) != 0)
    {
        writefln("unaligned store to %08X", address);
        (&system.cpu).printRegs();
        throw new Exception("stop");
    }

    assert(address < memMax);
    system.mem.u32(address) = value;
}

version(Profile)
Symbol* findSymbol(System* system, ulong addr)
{
    foreach(ref symbol; system.symbols)
    {
        if(addr >= symbol.addr && addr < symbol.addr + symbol.size)
            return &symbol;
    }

    return null;
}

void load(System* system, string elfFile)
{
    alias uint32_t = uint;

    struct Elf32_Phdr
    {
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

    foreach(symbol; SymbolTable(s).symbols())
    {
        version(Profile)
        {
            Symbol sym;
            sym.addr = symbol.value;
            sym.size = symbol.size;
            sym.name = symbol.name;
            system.symbols ~= sym;
        }

        if(symbol.name == "_D8graphics12_frameBufferG1310720h")
        {
		    frameBufferAddress = cast(uint)symbol.value;
            writefln("Framebuffer at %X", frameBufferAddress);
        }
    }

    auto pho = e.header.programHeaderOffset;
    auto num = e.header.numberOfProgramHeaderEntries;
    ubyte[] bin = cast(ubyte[]) std.file.read(elfFile);
    Elf32_Phdr* ph = cast(Elf32_Phdr*) (bin[pho .. pho + Elf32_Phdr.sizeof]).ptr;

    foreach(p; ph[0..num])
    {
        auto writeStart = p.p_vaddr;
        auto writeFileStart = p.p_offset;
        auto writeEnd = p.p_vaddr + p.p_filesz;
        auto writeFileEnd = p.p_offset + p.p_filesz;

        while((writeStart & 0b1111) != 0)
        {
            writeStart--;
            writeFileStart--;
        }

        while((writeEnd & 0b1111) != 0)
        {
            writeEnd++;
            writeFileEnd++;
        }

        version(TraceLoad) writefln("WRITE %X - %X (%X - %X)", writeStart, writeEnd, writeFileStart, writeFileEnd);
        system.mem.writeMem(writeStart, bin[writeFileStart .. writeFileEnd]);

        auto zeroStart = p.p_vaddr + p.p_filesz;
        auto zeroEnd = p.p_vaddr + p.p_memsz;
        auto zeroSize = zeroEnd - zeroStart;

        if(zeroSize == 0)
            continue;

        while((zeroStart & 0b1111) != 0)
        {
            zeroStart++;
        }

        ubyte[] zeros = (cast(ubyte) 0).repeat.take(zeroSize).array;

        while((zeros.length & 0b1111) != 0)
            zeros ~= 0;

        version(TraceLoad) writefln("CLEAR %X - %X", zeroStart, zeroEnd);
        system.mem.writeMem(zeroStart, zeros);
    }
}

static int[string] opcount;
File log;

pragma(inline, true)
void trace(Args...)(uint pc, uint inst, string mnemonic, Args args)
{
    version(Trace)
    {
        log.writef("core   0: 0x%016x (0x%08x) %-8s", pc, inst, mnemonic);
        log.writefln(args);
    }
}

enum regNames =
[
    "zero", "ra", "sp", "gp",
    "tp", "t0", "t1", "t2",
    "s0", "s1", "a0", "a1",
    "a2", "a3", "a4", "a5",
    "a6", "a7", "s2", "s3",
    "s4", "s5", "s6", "s7",
    "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
];

void printRegs(RISCV32* cpu)
{
    writefln("REGs at %08X", cpu.pc);

    foreach(j; 0 .. 32/4)
    {
        foreach(i; 0 .. 4)
        {
            auto reg = j*4+i;
            writef("%-04s: %08X  ", regNames[reg], cpu.regs[reg]);
        }

        writeln();
    }
}

pragma(inline, true)
uint mask(int start, int stop)
{
    uint m = 0;

    foreach(i; start .. stop+1)
    {
        m = (m << 1) | 1;
    }

    return m << start;
}

pragma(inline, true)
uint bits(int start, int stop)(uint value)
{
    assert(stop >= start);
    enum m = mask(start, stop);
    return (value & m) >> start;
}

pragma(inline, true)
int signext(uint value, int signBit)
{
    auto shiftDistance = 31 - signBit;
    int svalue = value << shiftDistance;
    return svalue >> shiftDistance;
}

pragma(inline, true)
auto rn(int reg)
{
    return regNames[reg];
}

void eventLoop()
{
    SDL_Event e;

    while(SDL_PollEvent(&e))
    {
        switch(e.type)
        {
            case SDL_QUIT:
                throw new Exception("Quit");

            case SDL_KEYUP:
            case SDL_KEYDOWN:
                break;

            default:
        }
    }
}

void execute(System* system)
{
    RISCV32* cpu = &system.cpu;

    uint cycle;
    //foreach(cycle; 0..414)
    //foreach(cycle; 0..100_000)
    while(true)
    {
        version(Profile) if(cycle % 100_000 == 0)
        {
            auto sym = system.findSymbol(system.cpu.pc);
            if(sym)
                sym.count++;
        }

        version(GFX) if(cycle % 2_000_000 == 0)
        {
            eventLoop();

            if(cycle % 10_000_000 == 0)
                system.refresh();
        }

        auto inst = system.mem.u32(cpu.pc);

        version(Trace) writefln("%08d %08X: %08X", cycle, cpu.pc, inst);

        assert(inst & 0b11 && ((inst & 0b11100) != 0b11100));

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
                version(Trace) trace(cpu.pc, inst, "lui", "%s, 0x%x", rd.rn, uimm >>> 12);
                if(rd != 0)
                    cpu.regs[rd] = uimm;
                break;
            }

            case 0b1101111:
            {
                int jimm = inst.bits!(31, 31);
                jimm = (jimm << 8) | inst.bits!(12, 19);
                jimm = (jimm << 1) | inst.bits!(20, 20);
                jimm = (jimm << 10) | inst.bits!(21, 30);
                jimm = (jimm << 1).signext(20);

                version(Trace)
                {
                    if(jimm < 0)
                        trace(cpu.pc, inst, "j", "pc - 0x%x", abs(jimm));
                    else
                        trace(cpu.pc, inst, "j", "pc + 0x%x", jimm);
                }

                auto retpc = cpu.pc + 4;
                cpu.pc += jimm;
                if(rd != 0)
                    cpu.regs[rd] = retpc;

                break;
            }

            case 0b1100111:
            {
                version(Trace)
                {
                    if(rd == 0)
                        trace(cpu.pc, inst, "ret", "");
                    else if(rd == 1)
                        trace(cpu.pc, inst, "jalr", "%s", rs1.rn);
                    else
                        trace(cpu.pc, inst, "jalr", "%s, %s", rd.rn, rs1.rn);
                }

                assert((iimm & 0b11) == 0);
                auto retpc = cpu.pc + 4;
                cpu.pc = (cpu.regs[rs1] + iimm) & ~1;
                if(rd != 0)
                    cpu.regs[rd] = retpc;
                assert((cpu.pc & 0b11) == 0);
                break;
            }

            case 0b1100011:
            {
                int sbimm = inst.bits!(31, 31);
                sbimm = (sbimm << 1) | inst.bits!(7, 7);
                sbimm = (sbimm << 6) | inst.bits!(25, 30);
                sbimm = (sbimm << 4) | inst.bits!(8, 11);
                sbimm = (sbimm << 1).signext(12);

                switch(funct3)
                {
                    case 0b000:
                    {
                        version(Trace)
                        {
                            if(rs2 == 0)
                                trace(cpu.pc, inst, "beqz", "%s, pc + %s", rs1.rn, sbimm);
                            else
                                trace(cpu.pc, inst, "beq", "%s, %s, pc + %s", rs1.rn, rs2.rn, sbimm);
                        }

                        if(cpu.regs[rs1] == cpu.regs[rs2])
                            cpu.pc += sbimm;
                        else
                            cpu.pc += 4;

                        break;
                    }

                    case 0b001:
                    {
                        version(Trace)
                        {
                            if(rs2 == 0)
                            {
                                if(sbimm < 0)
                                    trace(cpu.pc, inst, "bnez", "%s, pc - %s", rs1.rn, abs(sbimm));
                                else
                                    trace(cpu.pc, inst, "bnez", "%s, pc + %s", rs1.rn, sbimm);
                            }
                            else
                            {
                                if(sbimm < 0)
                                    trace(cpu.pc, inst, "bne", "%s, %s, pc - %s", rs1.rn, rs2.rn, abs(sbimm));
                                else
                                    trace(cpu.pc, inst, "bne", "%s, %s, pc + %s", rs1.rn, rs2.rn, sbimm);
                            }
                        }

                        if(cpu.regs[rs1] != cpu.regs[rs2])
                            cpu.pc += sbimm;
                        else
                            cpu.pc += 4;

                        break;
                    }

                    case 0b100:
                    {
                        version(Trace)
                        {
                            if(rs2 == 0)
                                trace(cpu.pc, inst, "bltz", "%s, pc + %s", rs1.rn, sbimm);
                            else
                                trace(cpu.pc, inst, "blt", "%s, %s, pc + %s", rs1.rn, rs2.rn, sbimm);
                        }

                        if(cast(int)cpu.regs[rs1] < cast(int)cpu.regs[rs2])
                            cpu.pc += sbimm;
                        else
                            cpu.pc += 4;

                        break;
                    }

                    case 0b101:
                    {
                        version(Trace) trace(cpu.pc, inst, "bge", "%s, %s, pc + %s", rs1.rn, rs2.rn, sbimm);

                        if(cast(int)cpu.regs[rs1] >= cast(int)cpu.regs[rs2])
                            cpu.pc += sbimm;
                        else
                            cpu.pc += 4;

                        break;
                    }

                    case 0b110:
                    {
                        version(Trace)
                        {
                            if(sbimm < 0)
                                trace(cpu.pc, inst, "bltu", "%s, %s, pc - %s", rs1.rn, rs2.rn, abs(sbimm));
                            else
                                trace(cpu.pc, inst, "bltu", "%s, %s, pc + %s", rs1.rn, rs2.rn, sbimm);
                        }

                        if(cpu.regs[rs1] < cpu.regs[rs2])
                            cpu.pc += sbimm;
                        else
                            cpu.pc += 4;

                        break;
                    }

                    case 0b111:
                    {
                        version(Trace) trace(cpu.pc, inst, "bgeu", "%s, %s, pc + %s", rs1.rn, rs2.rn, sbimm);

                        if(cpu.regs[rs1] >= cpu.regs[rs2])
                            cpu.pc += sbimm;
                        else
                            cpu.pc += 4;

                        break;
                    }

                    default:
                        assert(0);
                }

                break;
            }

            case 0b0000011:
            {
                switch(funct3)
                {
                    case 0b000:
                    {
                        version(Trace) trace(cpu.pc, inst, "lb", "%s, %s(%s)", rd.rn, iimm, rs1.rn);
                        auto v = cast(byte) system.read8(cpu.regs[rs1] + iimm);
                        if(rd != 0)
                            cpu.regs[rd] = v;
                        break;
                    }

                    case 0b001:
                    {
                        version(Trace) trace(cpu.pc, inst, "lh", "%s, %s(%s)", rd.rn, iimm, rs1.rn);
                        auto v = cast(short) system.read16(cpu.regs[rs1] + iimm);
                        if(rd != 0)
                            cpu.regs[rd] = v;
                        break;
                    }

                    case 0b010:
                    {
                        version(Trace) trace(cpu.pc, inst, "lw", "%s, %s(%s)", rd.rn, iimm, rs1.rn);
                        auto v = system.read32(cpu.regs[rs1] + iimm);
                        if(rd != 0)
                            cpu.regs[rd] = v;
                        break;
                    }

                    case 0b100:
                    {
                        version(Trace) trace(cpu.pc, inst, "lbu", "%s, %s(%s)", rd.rn, iimm, rs1.rn);
                        auto v = system.read8(cpu.regs[rs1] + iimm);
                        if(rd != 0)
                            cpu.regs[rd] = v;
                        break;
                    }

                    case 0b101:
                    {
                        version(Trace) trace(cpu.pc, inst, "lhu", "%s, %s(%s)", rd.rn, iimm, rs1.rn);
                        auto v = system.read16(cpu.regs[rs1] + iimm);
                        if(rd != 0)
                            cpu.regs[rd] = v;
                        break;
                    }

                    default:
                        assert(0);
                }

                break;
            }

            case 0b0100011:
            {
                switch(funct3)
                {
                    case 0b000:
                    {
                        version(Trace) trace(cpu.pc, inst, "sb", "%s, %s(%s)", rs2.rn, simm, rs1.rn);
                        system.write8(cpu.regs[rs1] + simm, cast(ubyte) cpu.regs[rs2]);
                        break;
                    }

                    case 0b001:
                    {
                        version(Trace) trace(cpu.pc, inst, "sh", "%s, %s(%s)", rs2.rn, simm, rs1.rn);
                        system.write16(cpu.regs[rs1] + simm, cast(ushort) cpu.regs[rs2]);
                        break;
                    }

                    case 0b010:
                    {
                        version(Trace) trace(cpu.pc, inst, "sw", "%s, %s(%s)", rs2.rn, simm, rs1.rn);
                        system.write32(cpu.regs[rs1] + simm, cpu.regs[rs2]);
                        break;
                    }

                    default:
                        assert(0);
                }

                break;
            }

            case 0b0010011:
            {
                auto rdz = rd != 0;
                uint r;

                switch(funct3)
                {
                    case 0b000:
                    {
                        version(Trace)
                        {
                            if(rs1 == 0)
                                trace(cpu.pc, inst, "li", "%s, %s", rd.rn, iimm);
                            else if(iimm == 0)
                                trace(cpu.pc, inst, "mv", "%s, %s", rd.rn, rs1.rn);
                            else
                                trace(cpu.pc, inst, "addi", "%s, %s, %s", rd.rn, rs1.rn, iimm);
                        }

                        r = cpu.regs[rs1] + iimm;

                        break;
                    }

                    case 0b010:
                    {
                        r = cast(int)cpu.regs[rs1] < iimm ? 1 : 0;
                        break;
                    }

                    case 0b011:
                    {
                        r = cpu.regs[rs1] < iimm ? 1 : 0;
                        break;
                    }

                    case 0b100:
                    {
                        r = cpu.regs[rs1] ^ iimm;
                        break;
                    }

                    case 0b110:
                    {
                        version(Trace) trace(cpu.pc, inst, "ori", "%s, %s, %s", rd.rn, rs1.rn, iimm);
                        r = cpu.regs[rs1] | iimm;
                        break;
                    }

                    case 0b111:
                    {
                        version(Trace) trace(cpu.pc, inst, "andi", "%s, %s, %s", rd.rn, rs1.rn, iimm);
                        r = cpu.regs[rs1] & iimm;
                        break;
                    }

                    case 0b001:
                    {
                        version(Trace) trace(cpu.pc, inst, "slli", "%s, %s, %s", rd.rn, rs1.rn, shamt);
                        r = cpu.regs[rs1] << (shamt & 31);
                        break;
                    }

                    case 0b101:
                    {
                        if(inst.bits!(30, 30) == 0)
                        {
                            version(Trace) trace(cpu.pc, inst, "srli", "%s, %s, %s", rd.rn, rs1.rn, shamt);
                            r = cpu.regs[rs1] >> (shamt & 31);
                        }
                        else
                        {
                            r = (cast(int)cpu.regs[rs1]) >> (shamt & 31);
                        }

                        break;
                    }

                    default:
                        writeln("funct3: ", funct3);
                        assert(0);
                }

                if(rdz)
                    cpu.regs[rd] = r;

                break;
            }

            case 0b0110011:
            {
                auto rdz = rd != 0;
                uint r;

                if(inst.bits!(25, 25) == 1)
                {
                    switch(funct3)
                    {
                        case 0b000:
                        {
                            r = cast(int)cpu.regs[rs1] * cast(int)cpu.regs[rs2];
                            break;
                        }

                        case 0b001:
                        {
                            r = cast(uint)((cast(long)cpu.regs[rs1] * cast(long)cpu.regs[rs2]) >> 32);
                            break;
                        }

                        case 0b011:
                        {
                            r = cast(uint)((cast(ulong)cpu.regs[rs1] * cast(ulong)cpu.regs[rs2]) >> 32);
                            break;
                        }

                        case 0b100:
                        {
                            r = cast(int)cpu.regs[rs1] / cast(int)cpu.regs[rs2];
                            break;
                        }

                        case 0b111:
                        {
                            r = cpu.regs[rs1] % cpu.regs[rs2];
                            break;
                        }

                        default:
                            writeln("funct3: ", funct3);
                            enforce(0);
                            assert(0);
                    }
                }
                else
                {
                    switch(funct3)
                    {
                        case 0b000:
                        {
                            if(inst.bits!(30, 30) == 0)
                            {
                                version(Trace) trace(cpu.pc, inst, "add", "%s, %s, %s", rd.rn, rs1.rn, rs2.rn);
                                r = cpu.regs[rs1] + cpu.regs[rs2];
                                break;
                            }
                            else
                            {
                                version(Trace) trace(cpu.pc, inst, "sub", "%s, %s, %s", rd.rn, rs1.rn, rs2.rn);
                                r = cpu.regs[rs1] - cpu.regs[rs2];
                                break;
                            }
                        }
                    
                        case 0b001:
                        {
                            r = cpu.regs[rs1] << (cpu.regs[rs2] & 31);
                            break;
                        }
                    
                        case 0b010:
                        {
                            version(Trace) trace(cpu.pc, inst, "slt", "%s, %s, %s", rd.rn, rs1.rn, rs2.rn);
                            r = cast(int)cpu.regs[rs1] < cast(int)cpu.regs[rs2] ? 1 : 0;
                            break;
                        }
                    
                        case 0b011:
                        {
                            r = cpu.regs[rs1] < cpu.regs[rs2] ? 1 : 0;
                            break;
                        }
                    
                        case 0b100:
                        {
                            r = cpu.regs[rs1] ^ cpu.regs[rs2];
                            break;
                        }
                    
                        case 0b101:
                        {
                            if(inst.bits!(30, 30) == 0)
                                r = cpu.regs[rs1] >> (cpu.regs[rs2] & 31);
                            else
                                r = cast(int)cpu.regs[rs1] >> (cpu.regs[rs2] & 31);
                            break;
                        }
                    
                        case 0b110:
                        {
                            version(Trace) trace(cpu.pc, inst, "or", "%s, %s, %s", rd.rn, rs1.rn, rs2.rn);
                            r = cpu.regs[rs1] | cpu.regs[rs2];
                            break;
                        }
                    
                        case 0b111:
                        {
                            r = cpu.regs[rs1] & cpu.regs[rs2];
                            break;
                        }
                    
                        default:
                            writeln("funct3: ", funct3);
                            enforce(0);
                            assert(0);
                    }
                }

                if(rdz)
                    cpu.regs[rd] = r;

                break;
            }

            case 0b0001111: // FENCE
            {
                break;
            }

            case 0b1110011: // ECALL, EBREAK, etc
            {
                if(cpu.regs[17] == 64)
                {
                    uint ptr = cpu.regs[11];
                    uint len = cpu.regs[12];

                    foreach(i; 0..len)
                    {
                        char c = system.read8(ptr+i);
                        write(c);
                    }
                }
                else if(cpu.regs[17] == 93)
                {
                    return;
                }
                else
                {
                    version(GFX)
                    {
                        while(1)
                            //SDL_Delay(1_000);
                            eventLoop();
                    }
                }

                break;
            }

            case 0b0010111: // AUIPC
            {
                if(rd != 0)
                    cpu.regs[rd] = uimm + cpu.pc;

                break;
            }

            default:
                writefln("%08X: %08X", cpu.pc, inst);
                cpu.printRegs();
                enforce(0);
                assert(0);
        }

        if(opcode != 0b1100111 && opcode != 0b1100011 && opcode != 0b1101111)
            cpu.pc += 4;

        //if(cycle % 1000 == 0) cpu.printRegs();
        //cpu.printRegs();

        ++cycle;
    }
}

//version=test;
version=empire;

void main(string[] args)
{
    string execname;
    
    if(args.length > 1)
        execname = args[1];

    version(empire) runExecutable(execname);
    version(test) runStressTests();
}

void runExecutable(string execname)
{
    version(Trace) log = File("trace-discv.txt", "w");

    initGraphics();

    __gshared System sys;

    sys.mem = new ubyte[memMax];

    auto elfFile = execname ? execname : "/home/luismarques/Projects/luis/empire4/empire";

    (&sys).load(elfFile);

    sys.cpu.pc = 0x1000;

    //sys.cpu.regs[2] = 0x000000007fbecda0;
    sys.cpu.regs[2] = 0x6C_0000;

    version(MemDump)
    {
        auto f = File("logimem.txt", "w");
        
        f.writeln("v2.0 raw");
        foreach(i; 0 .. 0x290000/4)
        {
            auto v = (&sys).read32(i*4);
            f.writefln("%X", v);
        }
        if(execname)
            return;
    }

    //(&sys.cpu).printRegs();

    (&sys).execute();

    version(Profile)
    {
        sys.symbols.sort!((a, b) => a.count < b.count);    
        sys.symbols.filter!(a => a.count > 0).each!writeln();
    }
}

void runStressTests()
{
    version(Trace) log = File("trace-discv.txt", "w");

    initGraphics();

    foreach(DirEntry e; dirEntries("/Users/luismarques/Projects/riscv/riscv-tests/isa", SpanMode.shallow))
    {
        if(!e.name.baseName.startsWith("rv32ui-p-") || e.name.endsWith(".dump"))
        {
            continue;
        }

        __gshared System sys;

        sys.mem = new ubyte[memMax];

        auto elfFile = e.name;

        std.stdio.write(elfFile, " ");
        stdout.flush();

        (&sys).load(elfFile);

        sys.cpu.pc = 0x800000fc;

        (&sys).execute();

        auto gp = sys.cpu.regs[3];
        if(gp == 1)
            writeln("PASS");
        else
            writefln("FAIL %d", gp);
    }
}

import derelict.sdl2.sdl;
import std.exception : enforce;

SDL_Window* window;
SDL_Renderer* renderer;
SDL_Texture* texture;

enum width = 1280;
enum height = 1024;

uint frameBufferAddress = 0x6C0000;

auto initGraphics()
{
    version(GFX)
    {
        DerelictSDL2.load();

        enforce(SDL_Init(SDL_INIT_EVERYTHING) == 0);

        window = SDL_CreateWindow(
            "RISC-V",
            SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
            width, height,
            SDL_WINDOW_SHOWN);

        enforce(window !is null);

        renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_SOFTWARE);
        enforce(renderer !is null);

        SDL_RenderClear(renderer);

        texture = SDL_CreateTexture(
            renderer,
            SDL_PIXELFORMAT_RGB332,
            SDL_TEXTUREACCESS_STREAMING,
            width, height);
    }
}

void refresh(System* system)
{
    SDL_UpdateTexture(
        texture,
        null,
        system.mem.ptr + frameBufferAddress,
        width);

    SDL_RenderCopy(renderer, texture, null, null);
    SDL_RenderPresent(renderer);
}
