# Malware Detection System - Reproduction Guide

This guide provides step-by-step instructions to reproduce the model training outcomes and validate the system using shuffled datasets.

## Phase 1: Environment Setup

1.  **Install Python 3.x**: Ensure you have Python installed (Python 3.10+ recommended).
2.  **Install Required Libraries**:
    Open your terminal/command prompt and run:
    ```bash
    pip install pandas numpy tensorflow scikit-learn joblib matplotlib seaborn pefile
    ```

## Phase 2: Dataset Preparation

1.  **Locate Source Files**:
    Ensure the following files are in your project directory:
    - `btp2_malware_features.csv` (Original training data)
    - `APT1_features_btp2.csv` (Original APT1 test data)
2.  **Shuffle the Data**:
    Run the following Python snippet to create the shuffled versions used for fair training:
    ```python
    import pandas as pd
    
    # Shuffle Training Data
    df = pd.read_csv('btp2_malware_features.csv')
    df.sample(frac=1, random_state=42).reset_index(drop=True).to_csv('btp2_malware_features_shuffled.csv', index=False)
    
    # Shuffle Test Data
    df_apt1 = pd.read_csv('APT1_features_btp2.csv')
    df_apt1.sample(frac=1, random_state=42).reset_index(drop=True).to_csv('APT1_features_shuffled.csv', index=False)
    ```

## Phase 3: Model Training & Evaluation

1.  **Open the Unified Pipeline**:
    Open the `malware_detection_pipeline.ipynb` notebook in Jupyter or your IDE.
2.  **Execution Sequence**:
    - **Step 3.1 (Imports & Config)**: Run the first cell to load libraries and set file paths.
    - **Step 3.2 (Data Loading)**: Load the `btp2_malware_features_shuffled.csv`.
    - **Step 3.3 (Training)**: Execute the training blocks for the **DNN** and **Baseline ML Models** (Random Forest, SVM, etc.).
    - **Step 3.4 (Heuristic Rule)**: Ensure the 8+ zero-feature heuristic logic is active.
    - **Step 3.5 (Evaluation)**: Run the evaluation cell targeting `APT1_features_shuffled.csv`.

## Phase 4: Reviewing Results

1.  **Metric Analysis**:
    The notebook will output a comparison table (Accuracy, F1-Score). Look for the `Final Results on Shuffled APT1` section.
2.  **Visualization**:
    - Check the `model_graphs/` folder for generated confusion matrices.
    - Review the **ROC Curve** to see the performance trade-off between sensitivity and specificity.
3.  **Heuristic Impact**:
    Confirm the impact of the heuristic rule by observing the final prediction merging logic: `np.maximum(ml_pred, heuristic_pred)`.

---
**Note**: The system is designed to be end-to-end. Once the datasets are in place, running the entire notebook sequentially will generate all artifacts and metrics.
