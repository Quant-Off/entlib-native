use std::alloc::{Layout, alloc, dealloc};
use std::ptr;

use entlib_native_secure_buffer::SecureBuffer;

const PAGE_SIZE: usize = 4096;

fn verify_jo_multi_page(num_pages: usize) {
    let total = PAGE_SIZE * num_pages;
    let layout = Layout::from_size_align(total, PAGE_SIZE).unwrap();
    let raw_ptr = unsafe { alloc(layout) };
    assert!(!raw_ptr.is_null());

    unsafe { ptr::write_bytes(raw_ptr, 0xFF, total) };

    {
        let _buffer = unsafe { SecureBuffer::from_raw_parts(raw_ptr, total).unwrap() };
    }

    let slice = unsafe { core::slice::from_raw_parts(raw_ptr, total) };
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
            "Multi-page zeroization failed: pages={}, {}/{} bytes unclean, first at offset {}",
            num_pages, unclean, total, first_idx.unwrap()
        );
    }
}

#[test]
fn multi_page_3_pages() {
    verify_jo_multi_page(3);
}

#[test]
fn multi_page_10_pages() {
    verify_jo_multi_page(10);
}

#[test]
fn page_boundary_bytes_explicitly_verified() {
    let num_pages = 3;
    let total = PAGE_SIZE * num_pages;
    let layout = Layout::from_size_align(total, PAGE_SIZE).unwrap();
    let raw_ptr = unsafe { alloc(layout) };
    assert!(!raw_ptr.is_null());

    unsafe { ptr::write_bytes(raw_ptr, 0xCC, total) };

    {
        let _buffer = unsafe { SecureBuffer::from_raw_parts(raw_ptr, total).unwrap() };
    }

    let slice = unsafe { core::slice::from_raw_parts(raw_ptr, total) };

    let boundary_offsets = [
        0,
        PAGE_SIZE - 1,
        PAGE_SIZE,
        PAGE_SIZE + 1,
        2 * PAGE_SIZE - 1,
        2 * PAGE_SIZE,
        2 * PAGE_SIZE + 1,
        total - 1,
    ];

    for &offset in &boundary_offsets {
        assert_eq!(
            slice[offset], 0x00,
            "Page boundary byte at offset {} not zeroed (was 0x{:02X})",
            offset, slice[offset]
        );
    }

    unsafe { dealloc(raw_ptr, layout) };
}

#[test]
fn ro_multi_page_padding_gap() {
    let size = 5000;
    let mut buffer = SecureBuffer::new_owned(size).unwrap();
    let ptr = buffer.as_mut_slice().as_mut_ptr();
    let capacity = buffer.capacity();
    assert!(capacity >= 2 * PAGE_SIZE, "5000 bytes should span 2 pages");

    unsafe { ptr::write_bytes(ptr, 0xBB, capacity) };

    drop(buffer);

    let slice = unsafe { core::slice::from_raw_parts(ptr, capacity) };
    for (i, &byte) in slice.iter().enumerate() {
        assert_eq!(
            byte, 0x00,
            "RO multi-page: byte at offset {} not zeroed (capacity={})",
            i, capacity
        );
    }
}
