#include "advanced_faults.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

// 全域故障模型，由環境變數配置
FaultModel g_fault_model = {0};

// --- 靜態輔助函數 ---

static int get_env_int(const char *name, int default_val) {
    const char *env = getenv(name);
    if (!env || !*env) return default_val;
    return atoi(env);
}

// 模擬一個固定、非零、非重複的隨機數序列，用於 FAULT_FIXED_RNG 測試
// 確保這個序列本身不是全零或全一，且長度足夠（例如 64 bytes）
static const uint8_t FIXED_RNG_SEQUENCE[64] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
    0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0x00, 0xAA, 0x55,
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x1A, 0x1B,
    0xCC, 0x33, 0xDD, 0x44, 0xEE, 0x55, 0xFF, 0x66,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x77, 0x77, 0x77, 0x77, 0x88, 0x88, 0x88, 0x88,
    0x66, 0x66, 0x66, 0x66, 0x55, 0x55, 0x55, 0x55
};

// --- 公共介面實作 ---

void fault_init_from_env(void) {
    const char *type = getenv("MLDSA_FAULT_TYPE");
    g_fault_model.type = FAULT_NONE;

    if (type) {
        if (strcmp(type, "SKIP") == 0) g_fault_model.type = FAULT_INSTRUCTION_SKIP;
        if (strcmp(type, "FLIP") == 0) g_fault_model.type = FAULT_BIT_FLIP;
        if (strcmp(type, "PARTIAL") == 0) g_fault_model.type = FAULT_PARTIAL_ZERO;
        // 載入 FIXED_RNG 類型
        if (strcmp(type, "FIXED") == 0) g_fault_model.type = FAULT_FIXED_RNG;
    }
    g_fault_model.prob_percent = get_env_int("MLDSA_FAULT_PROB", 0);
    g_fault_model.granularity = get_env_int("MLDSA_FAULT_GRAN", 1);
    g_fault_model.seed = get_env_int("MLDSA_FAULT_SEED", 12345);

    // 只有當類型被設定且機率 > 0 時才啟用
    g_fault_model.enabled = (g_fault_model.type != FAULT_NONE && g_fault_model.prob_percent > 0);
    srand(g_fault_model.seed);

    fprintf(stderr, "[FAULT] Init: Type=%d, Prob=%d%%, Seed=%u\n",
            g_fault_model.type, g_fault_model.prob_percent, g_fault_model.seed);
} 

static int fault_trigger_now(void) {
    if (!g_fault_model.enabled) return 0;
    // 使用 rand() 檢查是否達到設定的機率門檻
    return (rand() % 100) < g_fault_model.prob_percent;
}

// 供 sign.c 檢查是否要跳過 RNG 呼叫
int fault_should_skip_rng(void) {
    if (g_fault_model.type != FAULT_INSTRUCTION_SKIP) return 0;
    return fault_trigger_now();
}

// 應用資料型故障 (BIT_FLIP, PARTIAL_ZERO, FIXED_RNG)
void fault_apply(uint8_t *buf, size_t len) {
    if (!g_fault_model.enabled || !buf || len == 0) return;

    // 只有資料型故障才需要走這條路徑
    if (g_fault_model.type == FAULT_INSTRUCTION_SKIP) return; 
    
    // 檢查是否觸發
    if (!fault_trigger_now()) return;

    if (g_fault_model.type == FAULT_BIT_FLIP) {
        // 隨機選擇一個位元組 (idx) 和一個位元 (1 << rand()%8) 進行翻轉
        size_t idx = rand() % len;
        buf[idx] ^= (1 << (rand() % 8));
        fprintf(stderr, "[FAULT] Applied BIT_FLIP at index %zu\n", idx);

    } else if (g_fault_model.type == FAULT_PARTIAL_ZERO) {
        // 從緩衝區中點開始，清零設定的粒度 (granularity)
        size_t g = g_fault_model.granularity;
        size_t start_idx = len / 2;

        if(g > len) g = len;
        if(start_idx + g > len) g = len - start_idx; // 避免越界

        memset(buf + start_idx, 0, g);
        fprintf(stderr, "[FAULT] Applied PARTIAL_ZERO: start=%zu, len=%zu\n", start_idx, g);
        
    } else if (g_fault_model.type == FAULT_FIXED_RNG) {
        // 使用預定義的序列覆蓋目標緩衝區 (FIXED_RNG)
        size_t bytes_to_copy = (len < sizeof(FIXED_RNG_SEQUENCE)) ? len : sizeof(FIXED_RNG_SEQUENCE);
        memcpy(buf, FIXED_RNG_SEQUENCE, bytes_to_copy);
        fprintf(stderr, "[FAULT] Applied FIXED_RNG (Non-zero state)\n");
    }
}