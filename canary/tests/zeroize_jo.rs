use std::alloc::{Layout, alloc, dealloc};
use std::ptr;

use entlib_native_secure_buffer::SecureBuffer;

const PAGE_SIZE: usize = 4096;

fn verify_jo_zeroization(poison: u8) {
    let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
    let raw_ptr = unsafe { alloc(layout) };
    assert!(!raw_ptr.is_null());

    unsafe { ptr::write_bytes(raw_ptr, poison, PAGE_SIZE) };

    {
        let _buffer = unsafe { SecureBuffer::from_raw_parts(raw_ptr, PAGE_SIZE).unwrap() };
    }

    let slice = unsafe { core::slice::from_raw_parts(raw_ptr, PAGE_SIZE) };
    let mut unclean = 0usize;
    let mut first_idx = None;
    for (i, &byte) in slice.iter().enumerate() {
        if byte != 0x00 {
            unclean += 1;
            if first_idx.is_none() {
                first_idx = Some(i);
            }
        }
    }

    unsafe { dealloc(raw_ptr, layout) };

    if unclean > 0 {
        panic!(
            "JO zeroization failed: poison=0x{:02X}, {}/{} bytes unclean, first at offset {}",
            poison, unclean, PAGE_SIZE, first_idx.unwrap()
        );
    }
}

#[test]
fn jo_zeroize_0xff_all_bits_set() {
    verify_jo_zeroization(0xFF);
}

#[test]
fn jo_zeroize_0xaa_even_bits() {
    verify_jo_zeroization(0xAA);
}

#[test]
fn jo_zeroize_0x55_odd_bits() {
    verify_jo_zeroization(0x55);
}

#[test]
fn jo_zeroize_complement_pair_proves_bitwise_independence() {
    verify_jo_zeroization(0xAA);
    verify_jo_zeroization(0x55);
}

#[test]
fn jo_zeroize_sequential_all_byte_values() {
    let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
    let raw_ptr = unsafe { alloc(layout) };
    assert!(!raw_ptr.is_null());

    let slice = unsafe { core::slice::from_raw_parts_mut(raw_ptr, PAGE_SIZE) };
    for (i, byte) in slice.iter_mut().enumerate() {
        *byte = (i % 256) as u8;
    }

    {
        let _buffer = unsafe { SecureBuffer::from_raw_parts(raw_ptr, PAGE_SIZE).unwrap() };
    }

    let slice = unsafe { core::slice::from_raw_parts(raw_ptr, PAGE_SIZE) };
    for (i, &byte) in slice.iter().enumerate() {
        assert_eq!(byte, 0x00, "Sequential pattern: byte at offset {} not zeroed (was 0x{:02X})", i, byte);
    }

    unsafe { dealloc(raw_ptr, layout) };
}
