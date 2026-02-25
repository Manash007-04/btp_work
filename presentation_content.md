# AURA Malware Scanner: Technical Pitch Deck (Pure Content)
*Advancing Static Analysis Through Hybrid AI Architectures*

---

## Slide 1: Mission & System Overview
**Project Concept**: AURA (Advanced Universal Risk Analysis)
**Objective**: Implementing a multi-layered detection pipeline that identifies malicious intent in PE (Portable Executable) binaries using structural and content-based biometrics.
**Core Proposition**: Moving beyond "fixed signatures" to "behavioral structuralism"—detecting malware by its fundamental building blocks rather than a known hash.

---

## Slide 2: Technical Timeline & Progress
### Phase 0: Baseline Development
- Implementation of standard ML classifiers: Random Forest (RF), Support Vector Machines (SVM), and Decision Trees (DT).
- Extraction of surface-level metadata (File size, number of sections).

### Phase 1 & 2: Neural Advancement (Current State)
- **Deep Neural Network (DNN)**: Custom-built 5-layer MLP optimized for high-dimensional feature spaces.
- **Enhanced Extraction Core**: Refactored to analyze 30+ sophisticated structural metrics.
- **Biometric Features**: Integration of Shannon Entropy, API Density, and Hidden File Attribute flags.
- **Interfacing**: FastAPI-powered inference engine with a dedicated Glassmorphism frontend.

---

## Slide 3: The Hybrid Engine Logic
The system evaluates files through a **Concurrent Dual-Vetting Process**:

1. **Neural Inference (The Context Engine)**:
   - Input: 28 Normalized structural features.
   - Processing: DNN analyzes non-linear correlations between header fields.
   - Output: Sigmoid probability score (0.00 to 1.00).

2. **Zero-Feature Heuristic (The Obfuscation Trigger)**:
   - Logic: Detects "Stripped Headers" or "Packed Payloads" by counting missing data fields.
   - Threshold: **8+ Zeroed Features** trigger an automatic malicious verdict.
   - Purpose: Direct countermeasure against malware designed to "blind" static extractors.

**Final Decision Logic**: `Verdict = (DNN_Score > 0.5) OR (Heuristic_Triggered == True)`
*Achieved 99.4% Accuracy on APT1 (Advanced Persistent Threat) dataset.*

---

## Slide 4: Deep Feature Map (Structural Biometrics)
AURA categorizes features into three investigative buckets:

- **1. Structural Entropy**:
  - Full-file Shannon Entropy + Section-wise Max Entropy.
  - High Entropy (>7.2) strongly correlates with encrypted malware payloads or custom packers.

- **2. Behavioral Strings & API Ratios**:
  - Scanning for malicious Win32 APIs: `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`.
  - **Suspicious API Ratio**: Number of high-risk imports / Total imports.

- **3. Quantitative Metrics**:
  - **Import Density**: Ratio of library functions to file size.
  - **Section Alignment Analysis**: Detecting anomalies in file padding and initialized data sizes.

---

## Slide 5: Performance Benchmarking
Results from validation against **600+ real-world APT samples**:

| Metric | Accuracy | F1-Score |
| :--- | :--- | :--- |
| **Decision Tree (Baseline)** | 100.0% | 1.00 |
| **AURA DNN (Context)** | 99.39% | 0.99 |
| **Random Forest** | 99.51% | 0.99 |

*Note: The high F1-Score across all models validates the system's ability to minimize "False Negatives" (undetected malware).*

---

## Slide 6: Roadmap: Phase 3 (Content + Context Integration)
The evolution to a **Holistic Global Detection System**:

1. **Byte Histogram Integration**:
   - Analyzing the full 256-byte frequency distribution as a primary feature.
   - Immunity: Cannot be bypassed by header obfuscation or metadata stripping.

2. **Convolutional 1D Analysis (CNN-Seq)**:
   - Using neural networks to identify sequences of bytes (local code patterns) rather than global statistics.

3. **Dynamic Sandbox Feedback**:
   - Automated routing of "Borderline" files (0.4 - 0.6 probability) to a virtual execution environment for dynamic behavior analysis.

---

## Slide 7: Scalability & Production Readiness
- **Backend Architecture**: Asynchronous FastAPI service designed for sub-ms inference.
- **Microservices Path**: Containerization (Docker) + Orchestration (Kubernetes) to handle multi-gigabyte daily scanning loads.
- **Real-time API**: Modular structure allows internal enterprise applications to "plug-and-play" the AURA scanning engine.

---
---

# Eraser.io Visualization Prompts

*Copy-paste these into Eraser.io to generate the diagrams for your slides.*

### 1. System Architecture Diagram
> Generate a high-level system architecture for a "Malware Detection Web App". Show a browser (Frontend) sending a file to a FastAPI (Backend). Inside the Backend, show a "Feature Extractor" module pipes data to two parallel boxes: "Neural Network (DNN)" and "Zero-Feature Heuristic". Show both boxes merging into a "Verdict Decision" block that returns JSON results to the UI. Use a modern, technical aesthetic.

### 2. Hybrid Logic Flowchart
> Create a logic flowchart for a detection engine. Start Node: "File Uploaded". Step 1: "Extract 28 Structural Features". From here, split into two parallel paths. Path A: "DNN Inference" -> "Malicious Probability > 0.5?". Path B: "Count Zero Features" -> "Count >= 8?". Show an OR gate collecting outcomes from both paths. If either is "Yes", go to "Result: Malicious". If both are "No", go to "Result: Safe".

### 3. Feature Intelligence Map
> Generate a mind-map diagram titled "AURA Feature Engineering". Branches: 
> 1. "Structural Entropy" with sub-nodes "Full File", "Section Max", "Packer Detection". 
> 2. "API Intelligence" with sub-nodes "Risk Ratio", "Injection Strings", "Import Density". 
> 3. "Metadata" with sub-nodes "Section Alignment", "Header Characteristics", "File Age". 
> Use a clean, professional layout.
