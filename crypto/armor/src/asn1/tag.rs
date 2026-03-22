/// ASN.1 태그 클래스입니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal = 0x00,
    Application = 0x40,
    Context = 0x80,
    Private = 0xC0,
}

/// DER 태그 바이트를 감싸는 구조체입니다.
/// 단순 u8 래퍼로, 비트 필드(클래스·구성·번호)를 직접 해석합니다.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Tag(pub u8);

impl Tag {
    pub const BOOLEAN: Tag = Tag(0x01);
    pub const INTEGER: Tag = Tag(0x02);
    pub const BIT_STRING: Tag = Tag(0x03);
    pub const OCTET_STRING: Tag = Tag(0x04);
    pub const NULL: Tag = Tag(0x05);
    pub const OID: Tag = Tag(0x06);
    pub const UTF8_STRING: Tag = Tag(0x0C);
    pub const PRINTABLE_STRING: Tag = Tag(0x13);
    pub const IA5_STRING: Tag = Tag(0x16);
    pub const UTC_TIME: Tag = Tag(0x17);
    pub const GENERALIZED_TIME: Tag = Tag(0x18);
    /// SEQUENCE OF / SEQUENCE (구성형 0x30)
    pub const SEQUENCE: Tag = Tag(0x30);
    /// SET OF / SET (구성형 0x31)
    pub const SET: Tag = Tag(0x31);

    /// 태그 클래스를 반환합니다.
    #[inline(always)]
    pub fn class(self) -> TagClass {
        match self.0 & 0xC0 {
            0x00 => TagClass::Universal,
            0x40 => TagClass::Application,
            0x80 => TagClass::Context,
            _ => TagClass::Private,
        }
    }

    /// 태그가 구성형(Constructed)이면 true를 반환합니다.
    #[inline(always)]
    pub fn is_constructed(self) -> bool {
        self.0 & 0x20 != 0
    }

    /// 태그 번호(하위 5비트)를 반환합니다.
    #[inline(always)]
    pub fn number(self) -> u8 {
        self.0 & 0x1F
    }

    /// 컨텍스트 태그를 생성합니다.
    ///
    /// # Arguments
    /// - `num` — 태그 번호 (0-30)
    /// - `constructed` — 구성형 여부
    #[inline(always)]
    pub fn context(num: u8, constructed: bool) -> Tag {
        Tag(0x80 | (if constructed { 0x20 } else { 0x00 }) | (num & 0x1F))
    }
}
