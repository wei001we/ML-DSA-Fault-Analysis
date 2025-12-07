# ML-DSA Fault Injection & SLIC Defense Framework

This repository contains the research implementation for **"The Cliff Effect of ML-DSA: Quantifying Determinism Boundaries and Low-Overhead Runtime Integrity."**

## 🚀 Key Highlights
- **Cliff Effect Discovery**: Demonstrated that 1-bit entropy reduces attack success from 99% to 0%.
- **SLIC Architecture**: A lightweight defense mechanism with **<1% overhead** (vs 100% in traditional redundancy).
- **Cross-Architecture Support**: Compatible with AVX2 and Reference implementations.

## 📊 Key Results

### 1. The Cliff Effect (Attack Sensitivity)
![Cliff Effect](images/fig1_cliff_effect.png)
*Fig 1. Sensitivity analysis showing attack degradation under non-deterministic faults.*

### 2. Performance Overhead
![Performance](images/fig2_performance.png)
*Fig 2. SLIC incurs only 0.75% overhead compared to 100% in redundancy.*

## 📂 Project Structure
- `src/`: Core implementation of fault injection and SLIC defense.
- `scripts/`: Automated benchmarking scripts.
- `docs/`: Full technical report.

## 🛠️ How to Run
```bash
# Example command
./scripts/run_performance_benchmark.sh