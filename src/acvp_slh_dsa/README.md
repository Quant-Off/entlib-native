기본적으로, 모든 테스트 케이스는 다음 두 필드의 값은 누락될 수 없음

- `sk`
- `message`

다음은 모든 테스트 케이스에서 가능한 필드 유형을 열거한 것임

# signatureInterface: external

- preHash: pure
    - req: context
    - option: additionalRandomness
- preHash: preHash
    - req: context
    - req: hashAlg
    - option: additionalRandomness

# signatureInterface: internal

- option: additionalRandomness