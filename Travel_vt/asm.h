#pragma once
#include "common.h"

//
// ref: Vol2A[(INVPCID-Invalidate Process-Context Identifier)]
//
#ifdef __cplusplus
extern "C" {
#endif


enum class invpcid_t : uint32_t
{
  individual_address                = 0x00000000,
  single_context                    = 0x00000001,
  all_contexts                      = 0x00000002,
  all_contexts_retaining_globals    = 0x00000003,
};

struct invpcid_desc_t
{
  uint64_t pcid : 12;
  uint64_t reserved : 52;
  uint64_t linear_address;
};

static_assert(sizeof(invpcid_desc_t) == 16);

enum class invept_t : uint32_t
{
  single_context                    = 0x00000001,
  all_contexts                      = 0x00000002,
};

enum class invvpid_t : uint32_t
{
  individual_address                = 0x00000000,
  single_context                    = 0x00000001,
  all_contexts                      = 0x00000002,
  single_context_retaining_globals  = 0x00000003,
};

struct invept_desc_t
{
  uint64_t ept_pointer;
  uint64_t reserved;
};

static_assert(sizeof(invept_desc_t) == 16);

struct invvpid_desc_t
{
  uint64_t vpid : 16;
  uint64_t reserved : 48;
  uint64_t linear_address;
};

static_assert(sizeof(invvpid_desc_t) == 16);


inline void ia32_asm_pause() noexcept
{
	_mm_pause();
}


void ia32_asm_invd() noexcept;

void ia32_asm_halt() noexcept;


uint16_t ia32_asm_read_cs() noexcept;
void ia32_asm_write_cs(uint16_t cs) noexcept;
uint16_t ia32_asm_read_ds() noexcept;
void ia32_asm_write_ds(uint16_t ds) noexcept;
uint16_t ia32_asm_read_es() noexcept;
void ia32_asm_write_es(uint16_t es) noexcept;
uint16_t ia32_asm_read_fs() noexcept;
void ia32_asm_write_fs(uint16_t fs) noexcept;
uint16_t ia32_asm_read_gs() noexcept;
void ia32_asm_write_gs(uint16_t gs) noexcept;
uint16_t ia32_asm_read_ss() noexcept;
void ia32_asm_write_ss(uint16_t ss) noexcept;
uint16_t ia32_asm_read_tr() noexcept;
void ia32_asm_write_tr(uint16_t tr) noexcept;
uint16_t ia32_asm_read_ldtr() noexcept;
void ia32_asm_write_ldtr(uint16_t ldt) noexcept;



void     ia32_asm_read_gdtr(void* gdt) noexcept;
void     ia32_asm_write_gdtr(const void* gdt) noexcept;
uint32_t ia32_asm_read_ar(uint16_t selector) noexcept;
uint32_t ia32_asm_read_sl(uint32_t segment) noexcept;


inline void ia32_asm_read_idtr(void* idt) noexcept
{
	__sidt(idt);
}
inline void ia32_asm_write_idtr(void* idt) noexcept
{
	__lidt(idt);
}


#ifdef __cplusplus
}
#endif