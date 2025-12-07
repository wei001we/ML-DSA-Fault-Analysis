#!/bin/bash
###############################################################################
# ML-DSA Comprehensive Attack Experiment (Ideal vs Realistic)
#
# 目標：回應「攻擊模型過於理想化」的批判
# 方法：同時執行「理想攻擊 (Success)」與「現實模擬 (Fail/DoS)」
# 新增：量化 Flip Random 故障粒度對碰撞率的敏感度
###############################################################################

set +e

# ================= 配置區 =================
LIBOQS_ROOT="$HOME/liboqs"
LIBOQS_BUILD="$HOME/liboqs/build"
INSTALL_DIR="$HOME/liboqs-install"
PROJECT_DIR="$HOME/mldsa-fault-attack"
C_IMPL_DIR="$PROJECT_DIR/c-impl"
# 確保我們生成一個新的 CSV 文件來區分這次敏感度測試
RESULTS_CSV="$PROJECT_DIR/comprehensive_results_sensitivity.csv" 

mkdir -p "$C_IMPL_DIR"
mkdir -p "$INSTALL_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════╗
║   ML-DSA Comprehensive Attack Verification       ║
║   CRITICAL REVISION: Fault Granularity Analysis  ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ================= Phase 0: 生成全能故障引擎 (Fault Engine remains the same) =================
echo -e "${YELLOW}[Phase 0]${NC} Generating Comprehensive Fault Engine..."

# (此處省略 fault_engine.h 內容，假設它已被寫入 /tmp/fault_engine.h)
cat > /tmp/fault_engine.h << 'EOF'
#ifndef FAULT_ENGINE_H
#define FAULT_ENGINE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

typedef enum {
    FAULT_NONE = 0,
    FAULT_SKIP = 1,
    FAULT_ZERO = 2, 	  // Partial Zero
    FAULT_FLIP_STUCK = 3, // Ideal: Stuck-at-1 (0xFF)
    FAULT_FLIP_RANDOM = 4, // Real: Random Bit Flips
    FAULT_COMBINED = 5 	 // Real: Skip + Random Flip
} FaultType;

typedef struct {
    FaultType type;
    int prob;
    size_t gran;
    int zero_offset; // 0=Head(Strong), 1=Middle(Weak)
    int enabled;
} FaultModel;

static FaultModel g_fm;

static int f_env(const char *n, int d) {
    const char *e = getenv(n); return (e ? atoi(e) : d);
}

static void fault_init(void) {
    const char *t = getenv("MLDSA_FAULT_TYPE");
    g_fm.type = FAULT_NONE;
    if (t) {
        if (!strcmp(t, "SKIP")) g_fm.type = FAULT_SKIP;
        else if (!strcmp(t, "ZERO")) g_fm.type = FAULT_ZERO;
        else if (!strcmp(t, "FLIP_STUCK")) g_fm.type = FAULT_FLIP_STUCK;
        else if (!strcmp(t, "FLIP_RANDOM")) g_fm.type = FAULT_FLIP_RANDOM;
        else if (!strcmp(t, "COMBINED")) g_fm.type = FAULT_COMBINED;
    }
    g_fm.prob = f_env("MLDSA_FAULT_PROB", 0);
    g_fm.gran = f_env("MLDSA_FAULT_GRAN", 1);
    g_fm.zero_offset = f_env("MLDSA_FAULT_OFFSET", 0);
    
    g_fm.enabled = (g_fm.type != FAULT_NONE);
    srand(f_env("MLDSA_FAULT_SEED", 12345));
}

static int f_trigger(void) {
    if (!g_fm.enabled) return 0;
    return (rand() % 100) < g_fm.prob;
}

static int fault_should_skip(void) {
    if (g_fm.type == FAULT_SKIP || g_fm.type == FAULT_COMBINED) return f_trigger();
    return 0;
}

static void fault_apply_data(uint8_t *buf, size_t len) {
    if (!g_fm.enabled || !buf) return;
    if (g_fm.type == FAULT_SKIP) return;
    
    if (!f_trigger()) return;

    // 1. Ideal Flip (Stuck-at-1) -> Deterministic -> Collision
    if (g_fm.type == FAULT_FLIP_STUCK) {
        memset(buf, 0xFF, len);
    }

    // 2. Real Flip (Random) -> Non-deterministic -> No Collision, but Verify Fail
    // gran 現在代表要翻轉的位元組數量 (Bytes)
    if (g_fm.type == FAULT_FLIP_RANDOM || g_fm.type == FAULT_COMBINED) {
        for(size_t i=0; i<g_fm.gran; i++) { 
            size_t idx = rand() % len;
            // 每次循環翻轉該位元組內的一個隨機位元
            buf[idx] ^= (1 << (rand() % 8)); 
        }
    }

    // 3. Zeroing (Controlled by Offset)
    if (g_fm.type == FAULT_ZERO) {
        size_t start = 0;
        if (g_fm.zero_offset == 1) start = len / 2; // Weak Attack
        
        size_t g = g_fm.gran;
        if (start + g > len) g = len - start;
        memset(buf + start, 0, g);
    }
}
#endif
EOF
# (End of Phase 0)

# (Phase 1 & 2: Patching and Rebuild remains the same)
# ... [Original Phase 1 & 2 Code] ...
echo -e "${YELLOW}[Phase 1]${NC} Patching Liboqs..."

TARGET_FILES=$(find "$LIBOQS_ROOT/src/sig/ml_dsa" -name "sign.c" | grep "ml-dsa-65")

for SIGN_C in $TARGET_FILES; do
    if [ -f "${SIGN_C}.backup" ]; then cp "${SIGN_C}.backup" "$SIGN_C"; else cp "$SIGN_C" "${SIGN_C}.backup"; fi
    
    sed -i '10i #include "/tmp/fault_engine.h"' "$SIGN_C"
    sed -i '11i static int f_inited = 0;' "$SIGN_C"
    
    TARGET_LINE=$(grep -nE "shake256.*rhoprime" "$SIGN_C" | head -1 | cut -d: -f1)
    if [ -z "$TARGET_LINE" ]; then continue; fi
    
    awk -v line="$TARGET_LINE" '
    NR == line {
        print "     /* [ATTACK HOOK] */"
        print "     if (!f_inited) { fault_init(); f_inited = 1; }"
        print ""
        print "     if (fault_should_skip()) {"
        print "         memset(rhoprime, 0, CRHBYTES); // Skip implies zero state"
        print "     } else {"
        print "     " $0
        print "     }"
        print "     fault_apply_data(rhoprime, CRHBYTES);"
        next
    }
    {print}
    ' "$SIGN_C" > "${SIGN_C}.tmp" && mv "${SIGN_C}.tmp" "$SIGN_C"
    
    echo "  ✓ Patched $SIGN_C"
done

# ================= Phase 2: Rebuild =================
echo -e "${YELLOW}[Phase 2]${NC} Rebuilding..."
cd "$LIBOQS_BUILD"
cmake -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" -DOQS_ENABLE_SIG_ML_DSA=ON .. > /dev/null
if ! make -j$(nproc) > /tmp/build.log 2>&1; then
    make -j1 > /tmp/build_error.log 2>&1
    tail -n 20 /tmp/build_error.log
    exit 1
fi
make install > /dev/null 2>&1
echo -e "${GREEN}✓ Liboqs installed${NC}"

# ================= Phase 3: Compile Tool (Remains the same) =================
echo -e "${YELLOW}[Phase 3]${NC} Compiling Verify Tool..."
cd "$C_IMPL_DIR"

cat > mldsa_verify_tool.c << 'EOF'
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    uint8_t *pk=malloc(sig->length_public_key), *sk=malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig, pk, sk);
    
    uint8_t *buf=malloc(sig->length_signature);
    size_t sl;
    char msg[]="Fixed";
    uint8_t **rec=calloc(100, sizeof(uint8_t*));
    
    int gen=0, cols=0, fails=0;
    
    for(int i=0; i<100; i++) {
        memset(buf, 0, sig->length_signature);
        int r = OQS_SIG_sign(sig, buf, &sl, (uint8_t*)msg, 5, sk);
        
        if(r == OQS_SUCCESS) {
            gen++;
            // Check Collision
            int dup = 0;
            for(int j=0; j<i; j++) {
                if(rec[j] && memcmp(rec[j], buf, sig->length_signature)==0) {
                    cols++; dup=1; break;
                }
            }
            if(!dup) {
                rec[i] = malloc(sig->length_signature);
                memcpy(rec[i], buf, sig->length_signature);
            }
            // Check Validity (Integrity)
            if(OQS_SIG_verify(sig, (uint8_t*)msg, 5, buf, sl, pk) != OQS_SUCCESS) {
                fails++;
            }
        }
    }
    printf("100,%d,%d,%d\n", gen, cols, fails);
    return 0;
}
EOF

gcc mldsa_verify_tool.c -o mldsa_verify_tool \
    -I"$INSTALL_DIR/include" \
    "$INSTALL_DIR/lib/liboqs.a" \
    -lssl -lcrypto -lm

# ================= Phase 4: Scenarios & Sensitivity Analysis =================
echo -e "${YELLOW}[Phase 4]${NC} Running Comprehensive Scenarios and Sensitivity Analysis..."
echo "Scenario,Total,Gen,Collisions,VerifyFails,Interpretation" > "$RESULTS_CSV"

run() {
    export MLDSA_FAULT_TYPE=$2
    export MLDSA_FAULT_PROB=100
    export MLDSA_FAULT_GRAN=$3
    export MLDSA_FAULT_OFFSET=$4
    
    RES=$(./mldsa_verify_tool)
    # RES: 100, Gen, Col, Fail
    C=$(echo $RES | cut -d',' -f3)
    F=$(echo $RES | cut -d',' -f4)
    
    echo "$1,$RES,$5" >> "$RESULTS_CSV"
    echo "  $1: Col=$C, Fail=$F"
}

# 1. Baseline & Ideal Attacks (Reference Data)
echo -e "${YELLOW}--- 1. Reference Runs ---${NC}"
run "Baseline" "NONE" "1" "0" "Secure"
run "Skip_Attack" "SKIP" "1" "0" "Fatal_Leakage"
run "Flip_Stuck" "FLIP_STUCK" "1" "0" "Fatal_Leakage"
run "Zero_Strong" "ZERO" "64" "0" "Fatal_Leakage"


# 2. Sensitivity Analysis: Random Flip Granularity (NEW CRITICAL DATA)
echo -e "${YELLOW}--- 2. Flip Granularity Sensitivity (NEW CRITICAL DATA) ---${NC}"
# 测试翻转 1, 2, 4, 8, 16 个 BYTE（每次翻转一个随机位元）
# Note: Granularity here refers to the number of bytes/indices to flip a bit in.
FLIP_GRANULARITIES=(1 2 4 8 16)

for GRAN in "${FLIP_GRANULARITIES[@]}"; do
    # 執行 3 次以獲得更穩定的平均值
    for i in {1..3}; do
        run "Flip_Random_G${GRAN}_R${i}" "FLIP_RANDOM" "$GRAN" "0" "Noise_G${GRAN}_Degradation"
    done
done

# 3. Weak/Real Attacks (Context Data)
echo -e "${YELLOW}--- 3. Contextual Realism Runs ---${NC}"
run "Zero_Weak" "ZERO" "64" "1" "Ineffective_due_to_Diffusion"
run "Combined_Real" "COMBINED" "4" "0" "Noise_Protects_Confidentiality"
run "Flip_Random_G4_SingleRun" "FLIP_RANDOM" "4" "0" "DoS_Availability_Loss"


echo -e "\n${GREEN}================ SENSITIVITY REPORT ================${NC}"
column -s, -t < "$RESULTS_CSV" 2>/dev/null || cat "$RESULTS_CSV"
echo -e "${GREEN}========================================================${NC}"

# Cleanup
for SIGN_C in $TARGET_FILES; do if [ -f "${SIGN_C}.backup" ]; then cp "${SIGN_C}.backup" "$SIGN_C"; fi; done