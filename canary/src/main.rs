use std::alloc::{alloc, dealloc, Layout};
use std::ptr;
use entlib_native_secure_buffer::SecureBuffer;

const CANARY: &[u8; 32] = b"ENTLIB_FORENSIC_CANARY_PATTERN__";

// fn test_secure_buffer_zeroization_and_abort() { // 이거 개무거움
//     // 스코프 블록을 생성하여 명시적인 Drop(소거) 유도
//     {
//         // 1. Rust-Owned (RO) 패턴으로 안전한 버퍼 할당
//         // 내부적으로 SecureMemoryBlock::allocate_locked를 호출하며 페이지 정렬됨
//         let mut buffer = SecureBuffer::new_owned(32).expect("Failed to allocate SecureBuffer");
//         let slice = buffer.as_mut_slice();
//
//         unsafe {
//             // 2. 카나리아 데이터를 메모리에 주입
//             ptr::copy_nonoverlapping(CANARY.as_ptr(), slice.as_mut_ptr(), 32);
//
//             // 컴파일러 최적화 방지 및 메모리 쓰기 강제화
//             let _ = ptr::read_volatile(slice.as_ptr());
//         }
//     } // 스코프 종료
//
//     // 3. 소거 직후 OS에 시그널을 보내 강제 크래시 및 코어 덤프 생성 유도
//     process::abort();
// }

fn test_zeroization_in_memory_forensic() {
    let page_size = 4096; // macOS 기본 페이지 크기
    // 1. 페이지 크기에 맞게 정렬된 메모리를 수동으로 할당 (Java FFM API 오프힙 모사)
    let layout = Layout::from_size_align(page_size, page_size).unwrap();

    unsafe {
        let raw_ptr = alloc(layout);
        assert!(!raw_ptr.is_null(), "Failed to allocate memory");

        // 2. 카나리아 데이터 주입
        ptr::copy_nonoverlapping(CANARY.as_ptr(), raw_ptr, CANARY.len());

        // 3. 단일 병목점 스코 프생성
        {
            // JO 패턴으로 메모리 래핑
            let buffer = SecureBuffer::from_raw_parts(raw_ptr, page_size)
                .expect("Failed to create SecureBuffer");

            // 컴파일러 최적화 방지용 volatile read
            let _ = ptr::read_volatile(buffer.as_slice().as_ptr());

        }

        // 4. 인메모리 포렌식 전수 스캔 (코어 덤프 대체ㅇ)
        // SecureBuffer는 파괴되었지만, raw_ptr은 아직 OS에 반환되지 않았으므로 안전하게 읽을 수 있음
        let dumped_slice = core::slice::from_raw_parts(raw_ptr, page_size);

        let mut unclean_bytes = 0usize;
        let mut first_unclean_index = None;

        for (i, &byte) in dumped_slice.iter().enumerate() {
            if byte != 0x00 {
                unclean_bytes += 1;
                if first_unclean_index.is_none() {
                    first_unclean_index = Some(i);
                }
            }
        }

        dealloc(raw_ptr, layout);

        // 5. 검증 단언 (Assert)
        if unclean_bytes > 0 {
            let idx = first_unclean_index.unwrap();
            panic!(
                "CRITICAL FAILURE: Zeroization NOT 100% complete!\n\
                 Found {}/{} uncleared bytes. First at offset [{}].",
                unclean_bytes, page_size, idx
            );
        } else {
            println!("==========================================================");
            println!("[+] SUCCESS: Full-capacity ({} bytes) Forensic Zeroization Verified!", page_size);
            println!("[+] The compiler did NOT optimize away the zeroization logic.");
            println!("==========================================================");
        }
    }
}

fn main() {
    test_zeroization_in_memory_forensic();
}