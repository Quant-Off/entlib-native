use std::ptr;

use entlib_native_secure_buffer::SecureBuffer;

#[test]
fn ro_full_capacity_zeroed_including_padding_gap() {
    let size = 100;
    let mut buffer = SecureBuffer::new_owned(size).unwrap();
    let ptr = buffer.as_mut_slice().as_mut_ptr();
    let capacity = buffer.capacity();
    assert!(capacity > size, "capacity({}) must exceed len({})", capacity, size);

    unsafe { ptr::write_bytes(ptr, 0xAA, capacity) };

    drop(buffer);

    let slice = unsafe { core::slice::from_raw_parts(ptr, capacity) };
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

    if unclean > 0 {
        panic!(
            "RO zeroization failed: {}/{} bytes unclean (len={}, capacity={}), first at offset {}",
            unclean, capacity, size, capacity, first_idx.unwrap()
        );
    }
}

#[test]
fn ro_padding_gap_explicitly_poisoned_then_zeroed() {
    let size = 64;
    let mut buffer = SecureBuffer::new_owned(size).unwrap();
    let ptr = buffer.as_mut_slice().as_mut_ptr();
    let capacity = buffer.capacity();

    unsafe {
        ptr::write_bytes(ptr, 0x42, size);
        ptr::write_bytes(ptr.add(size), 0xFF, capacity - size);
    };

    drop(buffer);

    let slice = unsafe { core::slice::from_raw_parts(ptr, capacity) };

    for (i, &byte) in slice[..size].iter().enumerate() {
        assert_eq!(byte, 0x00, "RO data region: byte at offset {} not zeroed", i);
    }

    for (i, &byte) in slice[size..].iter().enumerate() {
        assert_eq!(byte, 0x00, "RO padding gap: byte at offset {} not zeroed", size + i);
    }
}

#[test]
fn ro_complement_patterns() {
    for poison in [0xAA_u8, 0x55, 0xFF] {
        let size = 200;
        let mut buffer = SecureBuffer::new_owned(size).unwrap();
        let ptr = buffer.as_mut_slice().as_mut_ptr();
        let capacity = buffer.capacity();

        unsafe { ptr::write_bytes(ptr, poison, capacity) };

        drop(buffer);

        let slice = unsafe { core::slice::from_raw_parts(ptr, capacity) };
        for (i, &byte) in slice.iter().enumerate() {
            assert_eq!(
                byte, 0x00,
                "RO poison=0x{:02X}: byte at offset {} not zeroed",
                poison, i
            );
        }
    }
}
