use core::ptr::write_volatile;
use entlib_native_secure_buffer::SecureBuffer;
use std::io::{self, Write};

pub(crate) fn read_stdin() -> Result<SecureBuffer, String> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = io::stdin().as_raw_fd();
        if unsafe { libc::isatty(fd) == 1 } {
            eprint!(">>>> 입력 모드 활성화.\n입력: ");
            io::stderr().flush().ok();
            return read_no_echo(fd);
        }
    }

    use std::io::Read;
    let mut raw: Vec<u8> = Vec::new();
    io::stdin()
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    // 파이프 경유 시 상류 명령이 추가한 개행 문자 제거
    if raw.last() == Some(&b'\n') {
        raw.pop();
    }
    if raw.last() == Some(&b'\r') {
        raw.pop();
    }
    vec_to_secure(raw)
}

#[cfg(unix)]
fn read_no_echo(fd: i32) -> Result<SecureBuffer, String> {
    let mut old: libc::termios = unsafe { core::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err("터미널 속성 획득 실패".into());
    }

    let mut raw = old;
    raw.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        return Err("에코 비활성화 실패".into());
    }

    let result = read_line_bytes();
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    eprintln!();
    result
}

fn read_line_bytes() -> Result<SecureBuffer, String> {
    use std::io::Read;
    // Q. T. Felix NOTE: with_capacity로 재할당 최소화
    //                   재할당 시 이전 heap 영역은 소거 불가
    let mut raw: Vec<u8> = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match io::stdin().read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if byte[0] != b'\r' {
                    raw.push(byte[0]);
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    vec_to_secure(raw)
}

/// 패스프레이즈를 TTY에서 에코 없이 읽습니다.
/// stdin이 파이프이더라도 /dev/tty에서 직접 읽어 충돌을 방지합니다.
pub(crate) fn read_passphrase(prompt: &str) -> Result<SecureBuffer, String> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let path = CString::new("/dev/tty").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            eprint!("{prompt}");
            io::stderr().flush().ok();
            let result = read_no_echo_fd(fd);
            unsafe { libc::close(fd) };
            eprintln!();
            return result;
        }
    }
    // TTY 열기 실패 시 stdin 폴백
    eprint!("{prompt}");
    io::stderr().flush().ok();
    read_stdin()
}

#[cfg(unix)]
fn read_no_echo_fd(fd: i32) -> Result<SecureBuffer, String> {
    let mut old: libc::termios = unsafe { core::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err("터미널 속성 획득 실패".into());
    }
    let mut raw = old;
    raw.c_lflag &= !(libc::ECHO | libc::ECHOE | libc::ECHOK | libc::ECHONL);
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
        return Err("에코 비활성화 실패".into());
    }
    let result = read_line_from_fd(fd);
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    result
}

#[cfg(unix)]
fn read_line_from_fd(fd: i32) -> Result<SecureBuffer, String> {
    let mut raw: Vec<u8> = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, byte.as_mut_ptr() as *mut libc::c_void, 1) };
        match n {
            0 => break,
            n if n < 0 => return Err("패스프레이즈 읽기 오류".into()),
            _ => {
                if byte[0] == b'\n' {
                    break;
                }
                if byte[0] != b'\r' {
                    raw.push(byte[0]);
                }
            }
        }
    }
    vec_to_secure(raw)
}

pub(crate) fn read_file(path: &str) -> Result<SecureBuffer, String> {
    let mut raw = std::fs::read(path).map_err(|e| format!("파일 읽기 오류: {e}"))?;
    let mut buf =
        SecureBuffer::new_owned(raw.len()).map_err(|e| format!("메모리 할당 오류: {e}"))?;
    buf.as_mut_slice().copy_from_slice(&raw);
    for b in raw.iter_mut() {
        unsafe { write_volatile(b as *mut u8, 0) };
    }
    Ok(buf)
}

fn vec_to_secure(mut raw: Vec<u8>) -> Result<SecureBuffer, String> {
    let mut buf =
        SecureBuffer::new_owned(raw.len()).map_err(|e| format!("메모리 할당 오류: {e}"))?;
    buf.as_mut_slice().copy_from_slice(&raw);
    for b in raw.iter_mut() {
        unsafe { write_volatile(b as *mut u8, 0) };
    }
    Ok(buf)
}

pub(crate) fn write_output(result: SecureBuffer, out_file: Option<&str>, interactive: bool) {
    if let Some(path) = out_file {
        if let Err(e) = std::fs::write(path, result.as_slice()) {
            eprintln!("파일 쓰기 오류: {e}");
            std::process::exit(1);
        }
        // SecureBuffer 소거부
        return;
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();
    // stdout이 TTY일 때만 사람 친화적 접두사 표시 — 파이프 경유 시 raw 출력 유지
    let tty_out = is_tty_stdout();
    if interactive && tty_out {
        let _ = write!(out, "결과: ");
    }
    if let Err(e) = out.write_all(result.as_slice()) {
        eprintln!("출력 오류: {e}");
        std::process::exit(1);
    }
    let _ = writeln!(out);
    // SecureBuffer 소거부
}

#[cfg(unix)]
fn is_tty_stdout() -> bool {
    use std::os::fd::AsRawFd;
    unsafe { libc::isatty(io::stdout().as_raw_fd()) == 1 }
}

#[cfg(not(unix))]
fn is_tty_stdout() -> bool {
    false
}
