#!/bin/bash
###############################################################################
# ML-DSA Double Fault Verification (Final Clean Version)
#
# 目標：驗證 "God Mode" 攻擊 (同時繞過 RNG 和 防禦檢查)
# 預期：
#   1. Single Fault (Skip RNG) -> Blocked by Defense
#   2. Double Fault (Skip RNG + Skip Check) -> 99 Collisions (Defense Bypassed)
###############################################################################

set +e

# ================= 配置區 =================
LIBOQS_ROOT="$HOME/liboqs"
LIBOQS_BUILD="$HOME/liboqs/build"
INSTALL_DIR="$HOME/liboqs-install"
PROJECT_DIR="$HOME/mldsa-fault-attack"
C_IMPL_DIR="$PROJECT_DIR/c-impl"
RESULTS_CSV="$PROJECT_DIR/double_fault_results.csv"

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
║   ML-DSA Double Fault Verification               ║
║   The "God Mode" Attack (Bypassing Defense)      ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ================= Phase 0: 生成雙重故障引擎 =================
echo -e "${YELLOW}[Phase 0]${NC} Generating God-Mode Engine..."

cat > /tmp/god_mode.h << 'EOF'
#ifndef GOD_MODE_H
#define GOD_MODE_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef enum { 
    FAULT_NONE=0, 
    FAULT_SINGLE_SKIP=1, // 只跳過 RNG (一般攻擊)
    FAULT_DOUBLE_SKIP=2  // 跳過 RNG + 跳過防禦 (神級攻擊)
} FaultType;

static struct { FaultType type; int enabled; } g_fault;
static struct { int level; } g_def;

typedef struct { uint8_t cs; void *addr; size_t len; int act; } StateSnap;

static void sys_init(void) {
    const char *ft = getenv("MLDSA_FAULT_TYPE");
    g_fault.type = FAULT_NONE;
    if (ft) {
        if (!strcmp(ft, "SINGLE")) g_fault.type = FAULT_SINGLE_SKIP;
        if (!strcmp(ft, "DOUBLE")) g_fault.type = FAULT_DOUBLE_SKIP;
    }
    g_fault.enabled = (g_fault.type != FAULT_NONE);

    const char *dl = getenv("MLDSA_DEFENSE_LEVEL");
    g_def.level = (dl && !strcmp(dl, "FULL")) ? 1 : 0;
}

// 簡單的 Checksum
static uint8_t calc_cs(const void *d, size_t l) {
    const uint8_t *p=d; uint8_t a=0; for(size_t i=0;i<l;i++) a^=p[i]; return a;
}

static void def_snapshot(StateSnap *s, void *a, size_t l) {
    s->act = g_def.level;
    s->addr = a; s->len = l;
    // 模擬 Snapshot (讀取當前狀態)
    volatile uint8_t *p = a; 
    s->cs = calc_cs((void*)p, l);
}

static int def_validate(StateSnap *s) {
    if (!s->act) return 1; // 防禦沒開，直接過
    
    // [DOUBLE FAULT CORE]
    // 如果攻擊者發動 DOUBLE_SKIP，他連這個檢查函數都跳過了
    if (g_fault.type == FAULT_DOUBLE_SKIP) {
        // 這裡我們用 return 1 模擬檢查被繞過
        return 1; 
    }

    // 正常的防禦邏輯
    volatile uint8_t *p = s->addr; 
    uint8_t curr = calc_cs((void*)p, s->len);
    
    // Stuck Check (Hash 沒變)
    if (s->cs == curr) return 0; 
    
    // Zero Check (全 0)
    size_t z=0; for(size_t i=0;i<s->len;i++) if(p[i]==0) z++;
    if(z==s->len) return 0;

    return 1;
}

static int fault_should_skip_rng(void) {
    // 無論是單跳還是雙跳，目標都是讓 RNG 不執行
    return (g_fault.type == FAULT_SINGLE_SKIP || g_fault.type == FAULT_DOUBLE_SKIP);
}
#endif
EOF

# ================= Phase 1: Patching =================
echo -e "${YELLOW}[Phase 1]${NC} Patching Liboqs..."

# 確保找到 sign.c
TARGETS=$(find "$LIBOQS_ROOT/src/sig/ml_dsa" -name "sign.c" | grep "ml-dsa-65")

if [ -z "$TARGETS" ]; then
    echo -e "${RED}Error: No sign.c found! Check path: $LIBOQS_ROOT${NC}"
    exit 1
fi

for SIGN_C in $TARGETS; do
    # Restore
    if [ -f "${SIGN_C}.backup" ]; then cp "${SIGN_C}.backup" "$SIGN_C"; else cp "$SIGN_C" "${SIGN_C}.backup"; fi
    
    # Inject Header
    sed -i '10i #include "/tmp/god_mode.h"' "$SIGN_C"
    sed -i '11i static int g_sys_init = 0;' "$SIGN_C"
    
    # Find RNG
    TARGET_LINE=$(grep -nE "shake256.*rhoprime" "$SIGN_C" | head -1 | cut -d: -f1)
    if [ -z "$TARGET_LINE" ]; then 
        echo "  Skipping $SIGN_C (RNG Not Found)"
        continue 
    fi

    # Inject Logic
    awk -v line="$TARGET_LINE" '
    NR == line {
        print "    if (!g_sys_init) { sys_init(); g_sys_init = 1; }"
        print "    StateSnap snap;"
        print "    def_snapshot(&snap, rhoprime, CRHBYTES);"
        print ""
        print "    if (fault_should_skip_rng()) {"
        print "        memset(rhoprime, 0, CRHBYTES);"
        print "    } else {"
        print "    " $0
        print "    }"
        print ""
        print "    // Defense Check (Can be skipped by Double Fault)"
        print "    if (!def_validate(&snap)) {"
        print "        return -1; // Blocked"
        print "    }"
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

# ================= Phase 3: Test Tool =================
echo -e "${YELLOW}[Phase 3]${NC} Compiling Tool..."
cd "$C_IMPL_DIR"

cat > mldsa_double_eval.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig, pk, sk);
    
    uint8_t *buf = malloc(sig->length_signature);
    size_t sl;
    char msg[] = "Fixed";
    
    int success = 0, blocked = 0, collisions = 0;
    uint8_t **hist = calloc(100, sizeof(uint8_t*));
    
    for(int i=0; i<100; i++) {
        memset(buf, 0, sig->length_signature);
        int ret = OQS_SIG_sign(sig, buf, &sl, (uint8_t*)msg, 5, sk);
        
        // Implicit Block check
        int all_zero = 1;
        for(int k=0;k<sig->length_signature;k++) if(buf[k]!=0) all_zero=0;

        if (ret == OQS_SUCCESS && !all_zero) {
            success++;
            int dup = 0;
            for(int j=0; j<i; j++) {
                if(hist[j] && memcmp(hist[j], buf, sig->length_signature)==0) {
                    collisions++; dup=1; break;
                }
            }
            if(!dup) {
                hist[i] = malloc(sig->length_signature);
                memcpy(hist[i], buf, sig->length_signature);
            }
        } else {
            blocked++;
        }
    }
    printf("100,%d,%d,%d\n", success, blocked, collisions);
    return 0;
}
EOF

gcc mldsa_double_eval.c -o mldsa_double_eval \
    -I"$INSTALL_DIR/include" \
    "$INSTALL_DIR/lib/liboqs.a" \
    -lssl -lcrypto -lm

# ================= Phase 4: Run =================
echo -e "${YELLOW}[Phase 4]${NC} Running Experiments..."
echo "Scenario,Total,Success,Blocked,Collisions,Meaning" > "$RESULTS_CSV"

run() {
    export MLDSA_FAULT_TYPE=$2
    export MLDSA_DEFENSE_LEVEL=$3
    RES=$(./mldsa_double_eval)
    echo "$1,$RES,$4" >> "$RESULTS_CSV"
    echo "  $1: $RES"
}

# 1. Single Fault vs Full Defense -> Blocked (Defense Wins)
run "Single_Fault_vs_Defense" "SINGLE" "FULL" "Defense Wins"

# 2. Double Fault vs Full Defense -> Collision (Attacker Wins)
run "Double_Fault_Bypass" "DOUBLE" "FULL" "Attacker Wins (God Mode)"

echo -e "\n${GREEN}================ DOUBLE FAULT REPORT ================${NC}"
column -s, -t < "$RESULTS_CSV" 2>/dev/null || cat "$RESULTS_CSV"
echo -e "${GREEN}=====================================================${NC}"

# Cleanup
for SIGN_C in $TARGETS; do if [ -f "${SIGN_C}.backup" ]; then cp "${SIGN_C}.backup" "$SIGN_C"; fi; done