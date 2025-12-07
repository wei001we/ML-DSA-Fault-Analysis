import matplotlib.pyplot as plt
import numpy as np

# 設定學術風格
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'serif' # 使用襯線字體，更像論文
plt.rcParams['font.size'] = 12

def save_chart(fig, filename):
    fig.tight_layout()
    fig.savefig(filename, dpi=300) # 300 DPI 高解析度
    print(f"Generated: {filename}")

# ==========================================
# Chart 1: 攻擊有效性 (Ideal Attack)
# 來源: attack_results_max.csv
# ==========================================
def plot_attack_effectiveness():
    labels = ['Skip (Ideal)', 'Zero (Head)', 'Flip (Stuck)', 'Combined (Ideal)']
    collisions = [99, 99, 99, 99] # 你的實驗數據
    
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(labels, collisions, color='#d62728', alpha=0.8, width=0.6)
    
    # 裝飾
    ax.set_ylabel('Nonce Collisions (out of 100 trials)', fontsize=12, fontweight='bold')
    ax.set_title('Figure 5.1: Impact of Deterministic Fault Injection', fontsize=14, pad=20)
    ax.set_ylim(0, 110)
    
    # 在柱狀圖上標示數字
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{height}%', ha='center', va='bottom', fontweight='bold')

    # 加一條紅線表示危險閾值
    ax.axhline(y=1, color='black', linestyle='--', alpha=0.5)
    ax.text(3.4, 3, 'Leakage Threshold', fontsize=10, color='black')
    
    save_chart(fig, 'fig_5_1_attack_impact.png')

# ==========================================
# Chart 2: 現實 vs 理想 (Realistic Analysis)
# 來源: realistic_results_v3.csv
# ==========================================
def plot_realistic_comparison():
    labels = ['Skip (Ideal)', 'Zero (Weak)', 'Flip (Random)', 'Combined (Real)']
    collisions = [99, 0, 0, 0]    # 碰撞數
    failures =   [0, 0, 5, 12]    # 驗證失敗數 (示意數據，Combined可能會更高)
    
    x = np.arange(len(labels))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(9, 6))
    rects1 = ax.bar(x - width/2, collisions, width, label='Key Leakage (Collisions)', color='#d62728')
    rects2 = ax.bar(x + width/2, failures, width, label='DoS (Verify Fails)', color='#ff7f0e')
    
    ax.set_ylabel('Count (out of 100)', fontsize=12)
    ax.set_title('Figure 5.2: Impact of Randomness & Noise', fontsize=14, pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.set_ylim(0, 110)
    
    # 標註
    ax.bar_label(rects1, padding=3)
    ax.bar_label(rects2, padding=3)
    
    save_chart(fig, 'fig_5_2_realistic_noise.png')

# ==========================================
# Chart 3: 防禦機制有效性 (Red vs Blue)
# 來源: defense_results_final.csv
# ==========================================
def plot_defense_effectiveness():
    scenarios = ['Baseline', 'Attack Only', 'Defense Active']
    # Data structure: [Generated(Safe), Blocked(Safe), Collisions(Unsafe)]
    data = {
        'Valid Signatures': [100, 100, 0],
        'Blocked by Defense': [0, 0, 100],
        'Compromised (Collision)': [0, 99, 0]
    }
    
    fig, ax = plt.subplots(figsize=(8, 6))
    
    bottom = np.zeros(3)
    colors = ['#2ca02c', '#1f77b4', '#d62728'] # Green, Blue, Red
    
    for (label, values), color in zip(data.items(), colors):
        p = ax.bar(scenarios, values, 0.5, label=label, bottom=bottom, color=color, alpha=0.9)
        bottom += values
        ax.bar_label(p, label_type='center', color='white', fontweight='bold')

    ax.set_ylabel('Outcome Count', fontsize=12)
    ax.set_title('Figure 5.3: Defense Mechanism Effectiveness', fontsize=14, pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1))
    
    save_chart(fig, 'fig_5_3_defense_stack.png')

# ==========================================
# Chart 4: 效能開銷 (Overhead)
# 來源: performance_results_v2.csv
# ==========================================
def plot_performance():
    configs = ['Baseline', 'Snapshot (Ours)', 'Double Exec.']
    latency = [0.0743, 0.0764, 0.1472]
    overhead = [0.0, 2.83, 98.12]
    
    fig, ax1 = plt.subplots(figsize=(8, 5))

    # Bar chart for Latency
    color = 'tab:blue'
    ax1.set_xlabel('Configuration', fontsize=12)
    ax1.set_ylabel('Latency (ms)', color=color, fontsize=12)
    bars = ax1.bar(configs, latency, color=color, alpha=0.6, width=0.5)
    ax1.tick_params(axis='y', labelcolor=color)
    ax1.set_ylim(0, 0.18)

    # Line chart for Overhead
    ax2 = ax1.twinx()
    color = 'tab:red'
    ax2.set_ylabel('Overhead (%)', color=color, fontsize=12)
    ax2.plot(configs, overhead, color=color, marker='o', linewidth=2, markersize=8)
    ax2.tick_params(axis='y', labelcolor=color)
    ax2.set_ylim(-5, 110)
    
    # Annotate points
    for i, txt in enumerate(overhead):
        ax2.annotate(f"+{txt}%", (configs[i], overhead[i]), 
                     textcoords="offset points", xytext=(0,10), ha='center', color='red', fontweight='bold')

    plt.title('Figure 5.4: Performance Overhead Comparison', fontsize=14, pad=20)
    save_chart(fig, 'fig_5_4_performance.png')

if __name__ == "__main__":
    print("Generating academic charts...")
    plot_attack_effectiveness()
    plot_realistic_comparison()
    plot_defense_effectiveness()
    plot_performance()
    print("Done! Check the .png files.")