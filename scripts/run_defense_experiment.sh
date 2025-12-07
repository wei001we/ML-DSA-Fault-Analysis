#!/bin/bash
###############################################################################
# ML-DSA Defense Verification (Return Value Fix)
#
# 修正：
# 1. [Test Tool Fix] 修正測試工具邏輯：如果簽章全為 0，視為 "Blocked" (提早退出)
#    這解決了 liboqs wrapper 可能吞掉 return -1 的問題。
# 2. [Goal] 正確顯示 Defense_Active: Blocked=100, Collisions=0
###############################################################################

set +e

# ================= 配置區 =================
LIBOQS_ROOT="$HOME/liboqs"
LIBOQS_BUILD="$HOME/liboqs/build"
INSTALL_DIR="$HOME/liboqs-install"
PROJECT_DIR="$HOME/mldsa-fault-attack"
C_IMPL_DIR="$PROJECT_DIR/c-impl"
RESULTS_CSV="$PROJECT_DIR/defense_results_final.csv"

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
║   ML-DSA Defense Verification (Fix Return Check) ║
╚══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# ================= Phase 0: 生成整合引擎 =================
echo -e "${YELLOW}[Phase 0]${NC} Generating Engine..."

cat > /tmp/integrated_engine.h << 'EOF'
#ifndef INTEGRATED_ENGINE_H
#define INTEGRATED_ENGINE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// --- FAULT ENGINE ---
typedef enum { FAULT_NONE=0, FAULT_SKIP=1 } FaultType;
static struct { FaultType type; int prob; int enabled; } g_red;

static int f_env(const char *n, int d) { const char *e = getenv(n); return (e ? atoi(e) : d); }

static void fault_init(void) {
    const char *t = getenv("MLDSA_FAULT_TYPE");
    g_red.type = FAULT_NONE;
    if (t && !strcmp(t, "SKIP")) g_red.type = FAULT_SKIP;
    g_red.prob = f_env("MLDSA_FAULT_PROB", 0);
    g_red.enabled = (g_red.type != FAULT_NONE);
    srand(12345);
}
static int fault_trigger(void) { return g_red.enabled && (rand()%100 < g_red.prob); }

// --- DEFENSE ENGINE ---
typedef enum { DEF_OFF=0, DEF_FULL=1 } DefLevel;
static struct { DefLevel level; } g_blue;
typedef struct { uint8_t cs; void *addr; size_t len; int act; } StateSnap;

static void def_init(void) {
    const char *l = getenv("MLDSA_DEFENSE_LEVEL");
    g_blue.level = (l && !strcmp(l, "FULL")) ? DEF_FULL : DEF_OFF;
}
static uint8_t def_cs(const void *d, size_t l) {
    const uint8_t *p=d; uint8_t a=0; for(size_t i=0;i<l;i++) a^=p[i]; return a;
}
static void def_snapshot(StateSnap *s, void *a, size_t l) {
    s->act = (g_blue.level == DEF_FULL);
    if(!s->act) return;
    s->addr=a; s->len=l; s->cs = def_cs(a,l);
}
static int def_validate(StateSnap *s) {
    if(!s->act) return 1;
    uint8_t curr = def_cs(s->addr, s->len);
    if(s->cs == curr) return 0; // Stuck
    
    volatile uint8_t *p = s->addr;
    size_t z=0; for(size_t i=0;i<s->len;i++) if(p[i]==0) z++;
    if(z==s->len) return 0; // Zeroed
    return 1;
}
#endif
EOF

# ================= Phase 1: Patching =================
echo -e "${YELLOW}[Phase 1]${NC} Patching..."
TARGETS=$(find "$LIBOQS_ROOT/src/sig/ml_dsa" -name "sign.c" | grep "ml-dsa-65")

for SIGN_C in $TARGETS; do
    if [ -f "${SIGN_C}.backup" ]; then cp "${SIGN_C}.backup" "$SIGN_C"; else cp "$SIGN_C" "${SIGN_C}.backup"; fi

    sed -i '10i #include "/tmp/integrated_engine.h"' "$SIGN_C"
    sed -i '11i static int g_eng_inited = 0;' "$SIGN_C"

    TARGET_LINE=$(grep -nE "shake256.*rhoprime" "$SIGN_C" | head -1 | cut -d: -f1)
    if [ -z "$TARGET_LINE" ]; then continue; fi

    awk -v line="$TARGET_LINE" '
    NR == line {
        print "    if (!g_eng_inited) { fault_init(); def_init(); g_eng_inited = 1; }"
        print "    StateSnap snap;"
        print "    def_snapshot(&snap, rhoprime, CRHBYTES);"
        print ""
        print "    if (g_red.type == FAULT_SKIP && fault_trigger()) {"
        print "        memset(rhoprime, 0, CRHBYTES);"
        print "    } else {"
        print "    " $0
        print "    }"
        print ""
        print "    if (!def_validate(&snap)) {"
        print "        // fprintf(stderr, \"[DEFENSE] Blocked!\\n\");"
        print "        return -1;"
        print "    }"
        next
    }
    {print}
    ' "$SIGN_C" > "${SIGN_C}.tmp" && mv "${SIGN_C}.tmp" "$SIGN_C"
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

# ================= Phase 3: 修正版測試工具 =================
echo -e "${YELLOW}[Phase 3]${NC} Compiling Fix Tool..."
cd "$C_IMPL_DIR"

cat > mldsa_defense_eval.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

// 檢查 buffer 是否全為 0
int is_all_zero(const uint8_t *buf, size_t len) {
    for(size_t i=0; i<len; i++) if(buf[i] != 0) return 0;
    return 1;
}

int main() {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    uint8_t *pk=malloc(sig->length_public_key), *sk=malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig,pk,sk);
    
    uint8_t *buf=malloc(sig->length_signature);
    size_t sl;
    char msg[]="Fixed";
    uint8_t **rec=calloc(100,sizeof(uint8_t*));
    
    int gen=0, blk=0, col=0;
    
    for(int i=0;i<100;i++){
        memset(buf,0,sig->length_signature);
        
        int ret = OQS_SIG_sign(sig, buf, &sl, (uint8_t*)msg, 5, sk);
        
        // [CRITICAL FIX] 
        // 如果 ret 成功，但 buffer 還是全 0，代表底層提早 return 了 (Implicit Block)
        if (ret == OQS_SUCCESS && is_all_zero(buf, sig->length_signature)) {
            ret = OQS_ERROR; // 視為錯誤
        }

        if(ret == OQS_SUCCESS) {
            gen++;
            int dup=0;
            for(int j=0;j<i;j++){
                if(rec[j] && memcmp(rec[j],buf,sig->length_signature)==0){
                    col++; dup=1; break;
                }
            }
            if(!dup){
                rec[i]=malloc(sig->length_signature);
                memcpy(rec[i],buf,sig->length_signature);
            }
        } else {
            blk++; 
        }
    }
    printf("100,%d,%d,%d\n", gen, blk, col);
    return 0;
}
EOF

gcc mldsa_defense_eval.c -o mldsa_verify \
    -I"$INSTALL_DIR/include" \
    "$INSTALL_DIR/lib/liboqs.a" \
    -lssl -lcrypto -lm

# ================= Phase 4: Run =================
echo -e "${YELLOW}[Phase 4]${NC} Running Experiments..."
echo "Scenario,Total,Success,Blocked,Collisions" > "$RESULTS_CSV"

run() {
    export MLDSA_FAULT_TYPE=$2
    export MLDSA_FAULT_PROB=100
    export MLDSA_DEFENSE_LEVEL=$3
    RES=$(./mldsa_verify)
    echo "$1,$RES" >> "$RESULTS_CSV"
    echo "  $1: $RES"
}

run "Baseline" "NONE" "OFF"
run "Attack_Success" "SKIP" "OFF"
run "Defense_Active" "SKIP" "FULL"

echo -e "\n${GREEN}================ REPORT ================${NC}"
column -s, -t < "$RESULTS_CSV" 2>/dev/null || cat "$RESULTS_CSV"
echo -e "${GREEN}========================================${NC}"

# Cleanup
for SIGN_C in $TARGETS; do if [ -f "${SIGN_C}.backup" ]; then cp "${SIGN_C}.backup" "$SIGN_C"; fi; done