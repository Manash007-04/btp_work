import os
import pefile
import pandas as pd
import numpy as np
import math
import re
import time
from datetime import datetime

# --- CONFIGURATION ---
MALWARE_FOLDER = r"C:\Users\AdminVM\Desktop\malware_samples"
BENIGN_FOLDER = r"C:\Users\AdminVM\Desktop\benign_samples_for_apt1"
OUTPUT_CSV_FILE = r"C:\Users\AdminVM\Desktop\Enhanced_Static_Features.csv"

SUSPICIOUS_KEYWORDS = [
    'cmd', 'powershell', 'CreateRemoteThread', 'VirtualAlloc',
    'WriteProcessMemory', 'WinExec', 'system32', 'regsvr32', 'rundll32'
]

EXECUTABLE_EXTENSIONS = ['.exe', '.dll', '.bat', '.ps1']
# --- END OF CONFIGURATION ---

def extract_metadata(file_path):
    """Extracts general file metadata features."""
    try:
        stats = os.stat(file_path)
        file_size = stats.st_size
        log_file_size = math.log10(file_size) if file_size > 0 else 0
        
        _, ext = os.path.splitext(file_path)
        filename = os.path.basename(file_path)
        
        # File Age in days
        creation_time = stats.st_ctime
        current_time = time.time()
        file_age_days = (current_time - creation_time) / (24 * 3600)
        
        # Hidden attribute (Windows specific)
        import ctypes
        FILE_ATTRIBUTE_HIDDEN = 0x02
        attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
        hidden_flag = 1 if attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN) else 0
        
        is_exec_ext = 1 if ext.lower() in EXECUTABLE_EXTENSIONS else 0
        
        return {
            'file_size': file_size,
            'log_file_size': log_file_size,
            'file_extension_len': len(ext),
            'filename_length': len(filename),
            'file_age_days': file_age_days,
            'hidden_attribute_flag': hidden_flag,
            'is_executable_extension': is_exec_ext
        }
    except Exception:
        return {k: 0 for k in ['file_size', 'log_file_size', 'file_extension_len', 'filename_length', 'file_age_days', 'hidden_attribute_flag', 'is_executable_extension']}

def calculate_entropy(file_bytes):
    """Computes Shannon entropy and returns entropy value + high entropy flag."""
    if not file_bytes:
        return 0.0, 0
    
    byte_counts = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
    p_x = byte_counts / len(file_bytes)
    p_x = p_x[p_x > 0]
    entropy = -np.sum(p_x * np.log2(p_x))
    
    high_entropy_flag = 1 if entropy > 7.2 else 0
    return float(entropy), high_entropy_flag

def extract_strings_and_patterns(file_bytes):
    """Regex based detection for URLs, IPs, and suspicious keywords."""
    if not file_bytes:
        return 0, 0, 0
    
    # Safely decode or just search in bytes
    try:
        content = file_bytes.decode('utf-8', errors='ignore')
    except:
        content = ""

    # URL detection
    urls = re.findall(r'https?://[^\s<>"]+|ftp://[^\s<>"]+|[a-zA-Z0-9.-]+\.[a-z]{2,4}', content)
    url_count = len(urls)
    
    # IPv4 detection
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', content)
    ip_count = len(ips)
    
    # Suspicious keywords
    keyword_count = 0
    for word in SUSPICIOUS_KEYWORDS:
        keyword_count += content.count(word)
        
    return url_count, ip_count, keyword_count

def extract_pe_features(file_path, file_bytes):
    """Parses PE header for structural features if file starts with MZ."""
    pe_data = {
        'number_of_sections': 0,
        'number_of_imported_DLLs': 0,
        'total_imported_functions': 0,
        'suspicious_api_import_count': 0,
        'suspicious_api_ratio': 0.0
    }
    
    if not file_bytes.startswith(b'MZ'):
        return pe_data

    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe_data['number_of_sections'] = pe.FILE_HEADER.NumberOfSections
        
        pe.parse_data_directories()
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            pe_data['number_of_imported_DLLs'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            
            total_funcs = 0
            susp_funcs = 0
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    total_funcs += 1
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        if any(kw in func_name for kw in SUSPICIOUS_KEYWORDS):
                            susp_funcs += 1
            
            pe_data['total_imported_functions'] = total_funcs
            pe_data['suspicious_api_import_count'] = susp_funcs
            pe_data['suspicious_api_ratio'] = susp_funcs / total_funcs if total_funcs > 0 else 0
        
        pe.close()
    except:
        pass
    
    return pe_data

def extract_all_features(file_path):
    """Unified function to extract all features from a file."""
    try:
        # 1. Metadata
        features = extract_metadata(file_path)
        
        # 2. Content (Read first 10MB to be safe/efficient)
        MAX_READ = 10 * 1024 * 1024
        with open(file_path, 'rb') as f:
            byte_data = f.read(MAX_READ)
            
        if not byte_data:
            return None
            
        # 3. Entropy
        entropy_val, high_entropy_flag = calculate_entropy(byte_data)
        features['entropy'] = entropy_val
        features['high_entropy_flag'] = high_entropy_flag
        
        # 4. Strings and Patterns
        url_c, ip_c, kw_c = extract_strings_and_patterns(byte_data)
        features['url_count'] = url_c
        features['ip_count'] = ip_c
        features['suspicious_keyword_count'] = kw_c
        
        # 5. PE Features
        pe_feats = extract_pe_features(file_path, byte_data)
        features.update(pe_feats)
        
        # 6. Combined Structural Patterns
        features['size_entropy_ratio'] = features['entropy'] / features['log_file_size'] if features['log_file_size'] > 0 else 0
        features['suspicious_density'] = features['suspicious_keyword_count'] / features['file_size'] if features['file_size'] > 0 else 0
        features['import_density'] = features['total_imported_functions'] / features['number_of_sections'] if features['number_of_sections'] > 0 else 0
        
        return features
    except Exception as e:
        print(f"[-] Error parsing {file_path}: {e}")
        return None

if __name__ == "__main__":
    all_data = []
    
    for folder, label in [(MALWARE_FOLDER, 1), (BENIGN_FOLDER, 0)]:
        if not os.path.exists(folder):
            print(f"[!] Folder not found: {folder}")
            continue
            
        print(f"[+] Processing {folder}...")
        files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
        
        for i, filepath in enumerate(files):
            feat = extract_all_features(filepath)
            if feat:
                feat['filename'] = os.path.basename(filepath)
                feat['Label'] = label
                all_data.append(feat)
            
            if i % 10 == 0:
                print(f"    - Processed {i}/{len(files)} files...", end='\r')
        print()

    if all_data:
        df = pd.DataFrame(all_data)
        # Ensure 'filename' and 'Label' are at the front
        cols = ['filename', 'Label'] + [c for c in df.columns if c not in ['filename', 'Label']]
        df = df[cols]
        df.to_csv(OUTPUT_CSV_FILE, index=False)
        print(f"[+] Successfully saved {len(df)} samples to {OUTPUT_CSV_FILE}")
    else:
        print("[!] No data extracted.")