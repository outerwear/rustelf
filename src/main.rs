use std::io;
use std::fs::File;
use std::io::prelude::*;
use std::str::from_utf8;

/* I guess this is like #define from C */
const MAGIC: &'static [u8]  = &[0x7f, 0x45, 0x4c, 0x46];
const ELF32: u8 = 0;
const ELF64: u8 = 0;

fn elf_fmt_println(bits: u8, idx: usize, content: &str) {
    let label: String;

    /* we want a clean format that is evenly spaced much like readelf */
    if idx <= 0x18 {
        match idx {
            0x00 => label = String::from("Magic Number:"),
            0x04 => label = String::from("Class:"),
            0x05 => label = String::from("Endianness:"),
            0x06 => label = String::from("Version:"),
            0x07 => label = String::from("OS/ABI:"),
            0x08 => label = String::from("ABI Version:"),
            0x10 => label = String::from("Type:"),
            0x12 => label = String::from("Machine:"),
            0x14 => label = String::from("Version:"),
            0x18 => label = String::from("Entry:"),
            _    => label = std::format!("Unknown index({}):", idx)
        }
    /* now ELF differs in size/offset depending on bit format */
    } else if bits == ELF32 {
        match idx {
            0x1c => label = String::from("Program header offset"),
            _    => label = std::format!("Unknown index({}):", idx)
        }
    } else if bits == ELF64 {
        match idx {
            0x20 => label = String::from("Program header offset"),
            _    => label = std::format!("Unknown index({}):", idx)
        }
    } else {
        /* absolutely shouldn't be here. */
        label = String::from("Serious error.");
    }

    println!("  {:<20} {}", label, content.to_string());
}

fn main() -> io::Result<()> {
    println!("Rust ELF reader");
    let mut idx = 0;
    let mut bits = ELF32; /* default to 32-bit */

    let mut file = File::open("foo.exe")?;
    /* elf header is 52 bytes on 32bit and 64bytes for 64bit */
    let mut hdr = [0u8; 64];

    file.read_exact(&mut hdr)?;

    /* aight so shit is in this buffer time to see if it matches.
     * this is where in C we would simply cast to a struct to derefence and compare each
     * but that isn't the /Rust/ way of doing things so for now by hand until I learn better.
     */

    /* magic header*/
    if MAGIC == &hdr[idx..4] {
        elf_fmt_println(bits, idx, from_utf8(MAGIC).unwrap());
    } else {
        println!("found this garbage instead: {:x?}", &hdr[0..4]);
    }
    idx += 4;

    /* 32 or 64 bit */
    if 1 == hdr[idx] {
        bits = ELF32;
        elf_fmt_println(bits, idx, "ELF32");
    } else if 2 == hdr[4] {
        bits = ELF64;
        elf_fmt_println(bits, idx, "ELF64");
    } else {
        println!("wtf size is this: {}", hdr[4]);
    }
    idx += 1;

    /* endianness */
    if 1 == hdr[idx] {
        elf_fmt_println(bits, idx, "Little Endian");
    } else if 2 == hdr[idx] {
        elf_fmt_println(bits, idx, "Big endian");
    } else {
        println!("bad endian value: {:x?}", hdr[idx]);
    }
    idx += 1;

    /* version check */
    if 1 == hdr[idx] {
        elf_fmt_println(bits, idx, "Current");
    } else {
        println!("no idea version bro");
    }
    idx += 1;

    /* ABI target */
    match hdr[idx] {
        0x00 => elf_fmt_println(bits, idx, "UNIX - System V"),
        0x01 => elf_fmt_println(bits, idx, "HP-UX"),
        0x02 => elf_fmt_println(bits, idx, "NetBSD"),
        0x03 => elf_fmt_println(bits, idx, "Linux"),
        0x04 => elf_fmt_println(bits, idx, "GNU Hurd"),
        0x06 => elf_fmt_println(bits, idx, "Solaris"),
        0x07 => elf_fmt_println(bits, idx, "AIX (Monterey)"),
        0x08 => elf_fmt_println(bits, idx, "IRIX"),
        0x09 => elf_fmt_println(bits, idx, "FreeBSD"),
        0x0A => elf_fmt_println(bits, idx, "Tru64"),
        0x0B => elf_fmt_println(bits, idx, "Novell Modesto"),
        0x0C => elf_fmt_println(bits, idx, "OpenBSD"),
        0x0D => elf_fmt_println(bits, idx, "OpenVMS"),
        0x0E => elf_fmt_println(bits, idx, "NonStop Kernel"),
        0x0F => elf_fmt_println(bits, idx, "AROS"),
        0x10 => elf_fmt_println(bits, idx, "FenixOS"),
        0x11 => elf_fmt_println(bits, idx, "Nuxi CloudABI"),
        0x12 => elf_fmt_println(bits, idx, "Stratus Technologies OpenVOS"),
        _ => println!("Bad ABI found: {:x?}", hdr[idx])
    }

    /* ABI version */
    /* there is something special here if it is compiled glibc 2.12+... skip for now since its mostly ignored */
    idx += 2;

    /* reserved padding bytes
     * should be 0s but ignored anyway, and doc shows it is size 7
     */
    idx += 7;

    /* object file type */
    match u32::from_le_bytes([hdr[idx], hdr[idx+1], 0, 0]) {
        0x0000 => elf_fmt_println(bits, idx, "Unknown"),
        0x0001 => elf_fmt_println(bits, idx, "Relocatable file"),
        0x0002 => elf_fmt_println(bits, idx, "Executable file"),
        0x0003 => elf_fmt_println(bits, idx, "Shared object"),
        0x0004 => elf_fmt_println(bits, idx, "Core file"),
        0xFE00 | 0xFEFF => elf_fmt_println(bits, idx, "Reserved inclusive range."),
        0xFF00 | 0xFFFF => elf_fmt_println(bits, idx, "Reserved inclusive range. Processor specific"),
        _ => println!("bad object file type identifier: {:x?}", &hdr[idx..(idx+2)])

    }
    idx += 2;

    /* target instruction set arch */
    match u32::from_le_bytes([hdr[idx], hdr[idx+1], 0, 0]) {
        0x0000 => elf_fmt_println(bits, idx, "No specific instruction set."),
        0x0001 => elf_fmt_println(bits, idx, "AT&T WE 32100"),
        0x0002 => elf_fmt_println(bits, idx, "SPARC"),
        0x0003 => elf_fmt_println(bits, idx, "x86"),
        0x0004 => elf_fmt_println(bits, idx, "Motorola 68000 (M68k)"),
        0x0005 => elf_fmt_println(bits, idx, "Motorola 88000 (M88k)"),
        0x0006 => elf_fmt_println(bits, idx, "Intel MCU"),
        0x0007 => elf_fmt_println(bits, idx, "Intel 80860"),
        0x0008 => elf_fmt_println(bits, idx, "MIPS"),
        0x0009 => elf_fmt_println(bits, idx, "IBM System/370"),
        0x000A => elf_fmt_println(bits, idx, "MIPS RS3000 Little Endian"),
        0x000B | 0x000C | 0x000D | 0x000E => elf_fmt_println(bits, idx, "Unknown (reserved for future use)"),
        0x000F => elf_fmt_println(bits, idx, "Hewlett Packard PA-RISC"),
        0x0013 => elf_fmt_println(bits, idx, "Intel 80960"),
        0x0014 => elf_fmt_println(bits, idx, "PowerPC"),
        0x0015 => elf_fmt_println(bits, idx, "PowerPC (64-bit)"),
        0x0016 => elf_fmt_println(bits, idx, "S390/S390x"),
        0x0017 => elf_fmt_println(bits, idx, "IBM SPU/SPC"),
        0x0018 | 0x0019 | 0x0020 | 0x0021 | 0x0022 | 0x0023 => elf_fmt_println(bits, idx, "Unknown (reserved for future use)"),
        0x0024 => elf_fmt_println(bits, idx, "NEC V800"),
        0x0025 => elf_fmt_println(bits, idx, "Fujitsu FR20"),
        0x0026 => elf_fmt_println(bits, idx, "TRW RH-32"),
        0x0027 => elf_fmt_println(bits, idx, "Motorola RCE"),
        0x0028 => elf_fmt_println(bits, idx, "Arm"),
        0x0029 => elf_fmt_println(bits, idx, "Digital Alpha"),
        0x002A => elf_fmt_println(bits, idx, "SuperH"),
        0x002B => elf_fmt_println(bits, idx, "SPARC Version 9"),
        0x002C => elf_fmt_println(bits, idx, "Siemens TriCore embedded processor"),
        0x002D => elf_fmt_println(bits, idx, "Argonaut RISC Core"),
        0x002E => elf_fmt_println(bits, idx, "Hitachi H8/300"),
        0x002F => elf_fmt_println(bits, idx, "Hitachi H8/300H"),
        0x0030 => elf_fmt_println(bits, idx, "Hitachi H8S"),
        0x0031 => elf_fmt_println(bits, idx, "Hitachi H8/500"),
        0x0032 => elf_fmt_println(bits, idx, "IA-64"),
        0x0033 => elf_fmt_println(bits, idx, "Stanford MIPS-X"),
        0x0034 => elf_fmt_println(bits, idx, "Motorola ColdFire"),
        0x0035 => elf_fmt_println(bits, idx, "Motorola M68HC12"),
        0x0036 => elf_fmt_println(bits, idx, "Fujitsu MMA Multimedia Accelerator"),
        0x0037 => elf_fmt_println(bits, idx, "Siemens PCP"),
        0x0038 => elf_fmt_println(bits, idx, "Sony nCPU embedded RISC processor"),
        0x0039 => elf_fmt_println(bits, idx, "Denso NDR1 microprocessor"),
        0x003A => elf_fmt_println(bits, idx, "Motorola Star*Core processor"),
        0x003B => elf_fmt_println(bits, idx, "Toyota ME16 processor"),
        0x003C => elf_fmt_println(bits, idx, "STMicroelectronics ST100 processor"),
        0x003D => elf_fmt_println(bits, idx, "Advanced Logic Corp. TinyJ embedded processor family"),
        0x003E => elf_fmt_println(bits, idx, "AMD x86-64"),
        0x003F => elf_fmt_println(bits, idx, "Sony DSP Processor"),
        0x0040 => elf_fmt_println(bits, idx, "Digital Equipment Corp. PDP-10"),
        0x0041 => elf_fmt_println(bits, idx, "Digital Equipment Corp. PDP-11"),
        0x0042 => elf_fmt_println(bits, idx, "Siemens FX66 microcontroller"),
        0x0043 => elf_fmt_println(bits, idx, "STMicroelectronics ST9+ 8/16 bit microcontroller"),
        0x0044 => elf_fmt_println(bits, idx, "STMicroelectronics ST7 8-bit microcontroller"),
        0x0045 => elf_fmt_println(bits, idx, "Motorola MC68HC16 Microcontroller"),
        0x0046 => elf_fmt_println(bits, idx, "Motorola MC68HC11 Microcontroller"),
        0x0047 => elf_fmt_println(bits, idx, "Motorola MC68HC08 Microcontroller"),
        0x0048 => elf_fmt_println(bits, idx, "Motorola MC68HC05 Microcontroller"),
        0x0049 => elf_fmt_println(bits, idx, "Silicon Graphics SVx"),
        0x004A => elf_fmt_println(bits, idx, "STMicroelectronics ST19 8-bit microcontroller"),
        0x004B => elf_fmt_println(bits, idx, "Digital VAX"),
        0x004C => elf_fmt_println(bits, idx, "Axis Communications 32-bit embedded processor"),
        0x004D => elf_fmt_println(bits, idx, "Infineon Technologies 32-bit embedded processor"),
        0x004E => elf_fmt_println(bits, idx, "Element 14 64-bit DSP Processor"),
        0x004F => elf_fmt_println(bits, idx, "LSI Logic 16-bit DSP Processor"),
        0x008C => elf_fmt_println(bits, idx, "TMS320C6000 Family"),
        0x00AF => elf_fmt_println(bits, idx, "MCST Elbrus e2k"),
        0x00B7 => elf_fmt_println(bits, idx, "Arm 64-bits (Armv8/AArch64)"),
        0x00DC => elf_fmt_println(bits, idx, "Zilog Z80"),
        0x00F3 => elf_fmt_println(bits, idx, "RISC-V"),
        0x00F7 => elf_fmt_println(bits, idx, "Berkeley Packet Filter"),
        0x101 => elf_fmt_println(bits, idx, "WDC 65C816"),
        _ => println!("bad instruction set: {:x?}", &hdr[idx..(idx+2)])
    }



    Ok(())
}
