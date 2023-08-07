use std::io;
use std::fs::File;
use std::io::prelude::*;

static MAGIC: &'static [u8]  = &[0x7f, 0x45, 0x4c, 0x46];

fn elf_fmt_println(idx: usize, content: String) {
    /* we want a clean format that is evenly spaced much like readelf */
    match idx {
        0  => println!("  {:<20} {}", "Magic Number:", content),
        4  => println!("  {:<20} {}", "Class:", content),
        5  => println!("  {:<20} {}", "Endianness:", content),
        6  => println!("  {:<20} {}", "Version:", content),
        7  => println!("  {:<20} {}", "OS/ABI:", content),
        16 => println!("  {:<20} {}", "ABI Version:", content),
        _  => println!("Unknown index {}. Content: {}", idx, content)
    }
}

fn main() -> io::Result<()> {
    println!("Rust ELF reader");
    let mut idx = 0;

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
        elf_fmt_println(idx, format!("{:x?}", &hdr[idx..16]));
    } else {
        println!("found this garbage instead: {:x?}", &hdr[0..4]);
    }
    idx += 4;

    /* 32 or 64 bit */
    if 1 == hdr[idx] {
        elf_fmt_println(idx, "ELF32".to_string());
    } else if 2 == hdr[4] {
        elf_fmt_println(idx, "ELF64".to_string());
    } else {
        println!("wtf size is this: {}", hdr[4]);
    }
    idx += 1;

    /* endianness */
    if 1 == hdr[idx] {
        elf_fmt_println(idx, "Little Endian".to_string());
    } else if 2 == hdr[idx] {
        elf_fmt_println(idx, "Big endian".to_string());
    } else {
        println!("bad endian value: {:x?}", hdr[idx]);
    }
    idx += 1;

    /* version check */
    if 1 == hdr[idx] {
        elf_fmt_println(idx, "Current".to_string());
    } else {
        println!("no idea version bro");
    }
    idx += 1;

    /* ABI target */
    match hdr[idx] {
        0x00 => elf_fmt_println(idx, "UNIX - System V".to_string()),
        0x01 => elf_fmt_println(idx, "HP-UX".to_string()),
        0x02 => elf_fmt_println(idx, "NetBSD".to_string()),
        0x03 => elf_fmt_println(idx, "Linux".to_string()),
        0x04 => elf_fmt_println(idx, "GNU Hurd".to_string()),
        0x06 => elf_fmt_println(idx, "Solaris".to_string()),
        0x07 => elf_fmt_println(idx, "AIX (Monterey)".to_string()),
        0x08 => elf_fmt_println(idx, "IRIX".to_string()),
        0x09 => elf_fmt_println(idx, "FreeBSD".to_string()),
        0x0A => elf_fmt_println(idx, "Tru64".to_string()),
        0x0B => elf_fmt_println(idx, "Novell Modesto".to_string()),
        0x0C => elf_fmt_println(idx, "OpenBSD".to_string()),
        0x0D => elf_fmt_println(idx, "OpenVMS".to_string()),
        0x0E => elf_fmt_println(idx, "NonStop Kernel".to_string()),
        0x0F => elf_fmt_println(idx, "AROS".to_string()),
        0x10 => elf_fmt_println(idx, "FenixOS".to_string()),
        0x11 => elf_fmt_println(idx, "Nuxi CloudABI".to_string()),
        0x12 => elf_fmt_println(idx, "Stratus Technologies OpenVOS".to_string()),
        _ => println!("Bad ABI found: {:x?}", hdr[idx])
    }

    /* ABI version */
    /* there is something special here if it is compiled glibc 2.12+... skip for now since its mostly ignored */
    idx += 2;

    /* reserved padding bytes
     * should be 0s but ignored anyway
     */
    idx += 7;

    /* object file type */
    match u32::from_le_bytes([hdr[idx], hdr[idx+1], 0, 0]) {
        0x0000 => elf_fmt_println(idx, "Unknown".to_string()),
        0x0001 => elf_fmt_println(idx, "Relocatable file".to_string()),
        0x0002 => elf_fmt_println(idx, "Executable file".to_string()),
        0x0003 => elf_fmt_println(idx, "Shared object".to_string()),
        0x0004 => elf_fmt_println(idx, "Core file".to_string()),
        0xFE00 | 0xFEFF => elf_fmt_println(idx, "Reserved inclusive range.".to_string()),
        0xFF00 | 0xFFFF => elf_fmt_println(idx, "Reserved inclusive range. Processor specific".to_string()),
        _ => println!("bad object file type identifier: {:x?}", &hdr[idx..(idx+2)])

    }
    idx += 2;

    Ok(())
}
