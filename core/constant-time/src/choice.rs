use core::ops::{BitAnd, BitOr, BitXor, Not};

/// 비밀 데이터의 상태를 안전하게 표현하는 상수-시간 논리 타입입니다.
///
/// 이 구조체는 암호학적 연산에서 조건 분기(Branch)를 제거하여 타이밍 공격(Timing Attack)을
/// 방지하기 위해 설계되었습니다. 내부적으로 `0x00`(False) 또는 `0xFF`(True) 값만을 가집니다.
///
/// # Security Note
/// `Choice`는 반드시 `0x00` 또는 `0xFF` 두 값 중 하나만을 가져야 합니다.
/// 이 불변 조건이 유지될 때, 비트 연산(`&`, `|`, `^`, `!`)은 논리 연산(AND, OR, XOR, NOT)과
/// 수학적으로 동치이며, CPU 분기 예측기를 자극하지 않는 상수-시간(Constant-Time) 연산을 보장합니다.
///
/// # Safety
/// - 내부 필드 `u8`은 절대로 공개(`pub`)처리되어선 안 됩니다.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Choice(u8);

impl Choice {
    /// 비밀 데이터의 상태 마스크를 상수-시간으로 안전하게 정규화합니다.
    ///
    /// # Security Note
    /// 어떠한 바이트(u8) 입력이 들어오더라도 수학적 비트 연산을 통해
    /// 0x00(False) 또는 0xFF(True)로 강제 변환합니다.
    /// 임의의 u8을 0x00(False) 또는 0xFF(True)로 정규화합니다.
    ///
    /// # Security Note
    /// 임의 바이트 입력을 받으므로 정규화 후 `black_box`를 통해
    /// LLVM이 결과값을 역추적하여 분기를 생성하는 것을 방지합니다.
    #[cfg(feature = "audit_mode")]
    #[inline(always)]
    pub(crate) fn from_mask_normalized(mask: u8) -> Self {
        let msb_set = mask | mask.wrapping_neg();
        let is_nonzero = msb_set >> 7;
        let secure_mask = is_nonzero.wrapping_neg();
        Choice(core::hint::black_box(secure_mask))
    }

    /// 이미 정규화된 0x00/0xFF 마스크로 직접 구성합니다.
    ///
    /// # Security Note
    /// 호출자는 mask ∈ {0x00, 0xFF} 를 보장해야 합니다.
    /// `black_box`는 LLVM이 mask 값을 추적하여 이후 연산을 조건 분기로
    /// 대체하는 것을 방지하는 상수-시간 경계로 작동합니다.
    #[inline(always)]
    pub(crate) fn from_mask(mask: u8) -> Self {
        Choice(core::hint::black_box(mask))
    }

    /// 내부 값을 반환합니다. 컴파일러 최적화를 방지하기 위해 `black_box`를 사용합니다.
    ///
    /// # Returns
    /// * `0x00` - False
    /// * `0xFF` - True
    #[inline(always)]
    pub fn unwrap_u8(self) -> u8 {
        #[cfg(not(feature = "saw_verify"))]
        {
            core::hint::black_box(self.0)
        }
        #[cfg(feature = "saw_verify")]
        {
            self.0
        }
    }

    /// `Choice` 값을 논리적으로 반전(NOT)합니다.
    ///
    /// `!choice` 연산자와 동일한 동작을 수행합니다.
    #[inline(always)]
    pub fn choice_not(self) -> Self {
        Choice(!self.0)
    }
}

impl BitAnd for Choice {
    type Output = Choice;

    /// 논리 AND 연산을 수행합니다.
    ///
    /// 두 `Choice` 값이 모두 참(`0xFF`)일 때만 참(`0xFF`)을 반환합니다.
    ///
    /// # Constant-Time
    /// `&` 연산자는 단일 CPU 명령어(AND)로 컴파일되며, 입력 값에 상관없이 항상 일정한
    /// CPU 사이클을 소모합니다. 분기문(`if`)을 대체하여 비밀 데이터에 의존적인 제어 흐름을 제거합니다.
    ///
    /// # Examples
    /// * `0xFF & 0xFF = 0xFF` (True AND True = True)
    /// * `0xFF & 0x00 = 0x00` (True AND False = False)
    /// * `0x00 & 0x00 = 0x00` (False AND False = False)
    #[inline(always)]
    fn bitand(self, rhs: Choice) -> Choice {
        Choice(self.0 & rhs.0)
    }
}

impl BitOr for Choice {
    type Output = Choice;

    /// 논리 OR 연산을 수행합니다.
    ///
    /// 두 `Choice` 값 중 하나라도 참(`0xFF`)이면 참(`0xFF`)을 반환합니다.
    ///
    /// # Constant-Time
    /// `|` 연산자는 단일 CPU 명령어(OR)로 컴파일되며, 분기 없이 실행됩니다.
    ///
    /// # Examples
    /// * `0xFF | 0x00 = 0xFF` (True OR False = True)
    /// * `0x00 | 0x00 = 0x00` (False OR False = False)
    #[inline(always)]
    fn bitor(self, rhs: Choice) -> Choice {
        Choice(self.0 | rhs.0)
    }
}

impl BitXor for Choice {
    type Output = Choice;

    /// 논리 XOR 연산을 수행합니다.
    ///
    /// 두 `Choice` 값이 서로 다를 때만 참(`0xFF`)을 반환합니다.
    ///
    /// # Constant-Time
    /// `^` 연산자는 단일 CPU 명령어(XOR)로 컴파일됩니다.
    ///
    /// # Examples
    /// * `0xFF ^ 0xFF = 0x00` (True XOR True = False)
    /// * `0xFF ^ 0x00 = 0xFF` (True XOR False = True)
    /// * `0x00 ^ 0x00 = 0x00` (False XOR False = False)
    #[inline(always)]
    fn bitxor(self, rhs: Choice) -> Choice {
        Choice(self.0 ^ rhs.0)
    }
}

impl Not for Choice {
    type Output = Choice;

    /// 논리 NOT 연산을 수행합니다.
    ///
    /// 참(`0xFF`)을 거짓(`0x00`)으로, 거짓(`0x00`)을 참(`0xFF`)으로 반전합니다.
    ///
    /// # Constant-Time
    /// `!` 연산자는 단일 CPU 명령어(NOT)로 컴파일됩니다.
    ///
    /// # Examples
    /// * `!0xFF = 0x00` (NOT True = False)
    /// * `!0x00 = 0xFF` (NOT False = True)
    #[inline(always)]
    fn not(self) -> Choice {
        Choice(!self.0)
    }
}
