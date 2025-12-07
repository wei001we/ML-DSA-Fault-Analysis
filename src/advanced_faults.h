#ifndef ADVANCED_FAULTS_H
#define ADVANCED_FAULTS_H
#include <stdint.h>
#include <stddef.h>
typedef enum {
    FAULT_NONE = 0,
    FAULT_INSTRUCTION_SKIP = 1,
    FAULT_BIT_FLIP = 2,
    FAULT_PARTIAL_ZERO = 3,
    FAULT_FIXED_RNG = 4
} FaultType;
typedef struct {
    FaultType type;
    int prob_percent;
    size_t granularity;
    unsigned int seed;
    int enabled;
} FaultModel;
// 這裡的宣告會在 Patch 時被移除，所以沒關係
void fault_init_from_env(void);
int fault_should_skip_rng(void);
void fault_apply(uint8_t *buf, size_t len);
#endif 