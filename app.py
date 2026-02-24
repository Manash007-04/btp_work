import os
import pefile
import math
import numpy as np
import pandas as pd
import joblib
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse, JSONResponse
import tensorflow as tf

app = FastAPI(title="AntiGravity Scanner API")

# Configuration
MODEL_PATH = "best_context_dnn.h5"
SCALER_PATH = "scaler_context.pkl"
ZERO_FEATURE_THRESHOLD = 8

# Globals
dnn_model = None
scaler = None

@app.on_event("startup")
def load_models():
    global dnn_model, scaler
    try:
        dnn_model = tf.keras.models.load_model(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("[+] Models loaded successfully.")
    except Exception as e:
        print(f"[-] Error loading models: {e}")

# The specific context columns used in training
CONTEXT_COLS = [
    'FileSize','Entropy','Imports_Count','Machine','SizeOfOptionalHeader',
    'Characteristics','NumberOfSections','TimeDateStamp','MajorLinkerVersion',
    'SizeOfCode','SizeOfInitializedData','SizeOfUninitializedData',
    'AddressOfEntryPoint','BaseOfCode','ImageBase','SectionAlignment',
    'FileAlignment','MajorOperatingSystemVersion','SizeOfImage',
    'SizeOfHeaders','CheckSum','Subsystem','DllCharacteristics',
    'SizeOfStackReserve','SizeOfHeapCommit','NumberOfRvaAndSizes',
    'Entropy_Mean','Entropy_Max'
]

def extract_features_from_bytes(file_bytes):
    features = {col: 0 for col in CONTEXT_COLS}
    if not file_bytes:
        return features
        
    features['FileSize'] = len(file_bytes)
    
    # Entropy
    byte_array = np.frombuffer(file_bytes, dtype=np.uint8)
    byte_counts = np.bincount(byte_array, minlength=256)
    p_x = byte_counts / len(file_bytes)
    p_x = p_x[p_x > 0] 
    features['Entropy'] = float(-np.sum(p_x * np.log2(p_x)))
    
    # PE specific
    if file_bytes.startswith(b'MZ'):
        try:
            pe = pefile.PE(data=file_bytes, fast_load=True)
            features['Machine'] = pe.FILE_HEADER.Machine
            features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
            features['Characteristics'] = pe.FILE_HEADER.Characteristics
            features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections
            features['TimeDateStamp'] = pe.FILE_HEADER.TimeDateStamp
            features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
            features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
            features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
            features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
            features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
            features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
            
            if pe.sections:
                section_entropies = [s.get_entropy() for s in pe.sections]
                if section_entropies:
                    features['Entropy_Mean'] = float(np.mean(section_entropies))
                    features['Entropy_Max'] = float(np.max(section_entropies))
                
            pe.parse_data_directories()
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                features['Imports_Count'] = len(pe.DIRECTORY_ENTRY_IMPORT)
                
            pe.close()
        except Exception as e:
            print(f"Error parsing PE: {e}")
            pass
            
    # ensure everything is standard python types (float/int) for JSON encoding
    for k, v in features.items():
        if isinstance(v, (np.int32, np.int64)):
            features[k] = int(v)
        elif isinstance(v, (np.float32, np.float64)):
            features[k] = float(v)
            
    return features


@app.get("/")
def get_index():
    return FileResponse("index.html")

@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    if dnn_model is None or scaler is None:
        return JSONResponse({"error": "Models not loaded. Wait for startup."}, status_code=500)
        
    contents = await file.read()
    features = extract_features_from_bytes(contents)
    
    # Apply Heuristic
    df = pd.DataFrame([features])
    zero_counts = int((df == 0).sum(axis=1).values[0])
    heuristic_flag = int(zero_counts >= ZERO_FEATURE_THRESHOLD)
    
    # Scale & Predict
    df_scaled = scaler.transform(df)
    dnn_prob = float(dnn_model.predict(df_scaled, verbose=0)[0][0])
    dnn_pred = int(dnn_prob > 0.5)
    
    final_pred = max(dnn_pred, heuristic_flag)
    
    return JSONResponse({
        "status": "success",
        "filename": file.filename,
        "is_malicious": bool(final_pred),
        "dnn_confidence": dnn_prob,
        "heuristic_triggered": bool(heuristic_flag),
        "zero_features_count": zero_counts,
        "extracted_features": features
    })
