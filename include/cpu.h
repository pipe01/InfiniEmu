#pragma once

#include <setjmp.h>
#include <stdint.h>
#include <capstone/capstone.h>

#include "arm.h"
#include "memory.h"
#include "runlog.h"

typedef struct cpu_inst_t cpu_t;

typedef void (*branch_cb_t)(cpu_t *cpu, uint32_t old_pc, uint32_t new_pc, void *userdata);

cpu_t *cpu_new(const uint8_t *program, size_t program_size, memreg_t *mem, size_t max_external_interrupts, size_t priority_bits);
void cpu_free(cpu_t *cpu);
void cpu_reset(cpu_t *cpu);
void cpu_step(cpu_t *cpu);

void cpu_set_runlog(cpu_t *cpu, runlog_t *runlog);

void cpu_set_branch_cb(cpu_t *cpu, branch_cb_t cb, void *userdata);

memreg_t *cpu_mem(cpu_t *cpu);
bool cpu_mem_read(cpu_t *cpu, uint32_t addr, uint8_t *value);
bool cpu_mem_write(cpu_t *cpu, uint32_t addr, uint8_t value);

uint32_t cpu_reg_read(cpu_t *cpu, arm_reg reg);
void cpu_reg_write(cpu_t *cpu, arm_reg reg, uint32_t value);

uint32_t cpu_sysreg_read(cpu_t *cpu, arm_sysreg reg);
void cpu_sysreg_write(cpu_t *cpu, arm_sysreg reg, uint32_t value, bool can_update_it);

arm_exception cpu_get_top_running_exception(cpu_t *cpu);
void cpu_jump_exception(cpu_t *cpu, arm_exception ex);
int16_t cpu_get_exception_priority(cpu_t *cpu, arm_exception ex);
void cpu_set_exception_priority(cpu_t *cpu, arm_exception ex, int16_t priority);
void cpu_exception_set_pending(cpu_t *cpu, arm_exception ex);
void cpu_exception_clear_pending(cpu_t *cpu, arm_exception ex);
bool cpu_exception_is_pending(cpu_t *cpu, arm_exception ex);
bool cpu_exception_is_active(cpu_t *cpu, arm_exception ex);
void cpu_exception_set_enabled(cpu_t *cpu, arm_exception ex, bool enabled);
bool cpu_exception_get_enabled(cpu_t *cpu, arm_exception ex);
