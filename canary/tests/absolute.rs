use std::alloc::{Layout, alloc, dealloc};
use std::panic;
use std::ptr;

use entlib_native_secure_buffer::SecureBuffer;

const PAGE_SIZE: usize = 4096;

fn verify_panic_survival(poison: u8) {
    let layout = Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap();
    let raw_ptr = unsafe { alloc(layout) };
    assert!(!raw_ptr.is_null());

    unsafe { ptr::write_bytes(raw_ptr, poison, PAGE_SIZE) };

    let result = panic::catch_unwind(|| {
        unsafe {
            let _buffer = SecureBuffer::from_raw_parts(raw_ptr, PAGE_SIZE).unwrap();
            panic!("Simulated cryptographic operation failure");
        }
    });

    assert!(result.is_err(), "Panic must occur for Drop to be invoked via stack unwinding");

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
            "Panic-path zeroization failed: poison=0x{:02X}, {}/{} bytes unclean, first at offset {}",
            poison, unclean, PAGE_SIZE, first_idx.unwrap()
        );
    }
}

#[test]
fn panic_survival_0xff() {
    verify_panic_survival(0xFF);
}

#[test]
fn panic_survival_0xaa() {
    verify_panic_survival(0xAA);
}

#[test]
fn panic_survival_0x55() {
    verify_panic_survival(0x55);
}

#[test]
fn panic_survival_complement_pair() {
    verify_panic_survival(0xAA);
    verify_panic_survival(0x55);
}
