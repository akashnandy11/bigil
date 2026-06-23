import os
import math
import hashlib
import threading
from app.models import IOC, Evidence, EvidenceChain, Alert, AuditLog
from app import db
from datetime import datetime

# Global scanner state
scanner_state = {
    'is_running': False,
    'scanned_files': 0,
    'total_files': 0,
    'threats': [],
    'current_file': '',
    'error': None,
    'target_dir': ''
}
state_lock = threading.Lock()

# Suspicious extensions (ransomware typical)
RANSOMWARE_EXTS = {
    '.locked', '.crypto', '.crypt', '.ecc', '.exx', '.abc', '.kraken', '.oshirist',
    '.wannacry', '.wcry', '.ryuk', '.locky', '.cerber', '.gandcrab', '.sodinokibi',
    '.revil', '.darkside', '.crypted', '.enc', '.encrypted'
}

# Ransom note patterns
RANSOM_NOTE_NAMES = {
    'readme_decrypt.txt', 'decrypt_instructions.html', 'readme_decrypt.html',
    'restore_files.txt', 'how_to_decrypt.txt', 'help_decrypt.txt', 'help_decrypt.png'
}

def calculate_entropy(filepath):
    """Calculate Shannon entropy of a file to detect potential encryption/ransomware."""
    try:
        if not os.path.exists(filepath):
            return 0.0
        
        file_size = os.path.getsize(filepath)
        if file_size == 0:
            return 0.0
        
        # Read max first 1MB for speed
        read_size = min(file_size, 1024 * 1024)
        with open(filepath, 'rb') as f:
            data = f.read(read_size)
            
        if not data:
            return 0.0
            
        entropy = 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
            
        for count in counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception:
        return 0.0

def compute_file_hashes(filepath):
    """Compute MD5 and SHA256 hashes of a file."""
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except Exception:
        return None, None

def run_background_scan(target_dir, app):
    """Recursive directory scanner target_dir running inside app context."""
    global scanner_state
    
    with app.app_context():
        try:
            # Gather files first
            files_to_scan = []
            for root, dirs, filenames in os.walk(target_dir):
                # Avoid virtual environment and git folders
                if any(ignored in root.lower() for ignored in ['venv', '.git', '__pycache__', 'node_modules']):
                    continue
                for fname in filenames:
                    files_to_scan.append(os.path.join(root, fname))
                    # Cap at 1000 files to prevent lockup
                    if len(files_to_scan) >= 1000:
                        break
                if len(files_to_scan) >= 1000:
                    break

            with state_lock:
                scanner_state['total_files'] = len(files_to_scan)
                scanner_state['scanned_files'] = 0
                scanner_state['threats'] = []
                scanner_state['is_running'] = True
                scanner_state['error'] = None

            for filepath in files_to_scan:
                with state_lock:
                    if not scanner_state['is_running']:
                        break
                    scanner_state['current_file'] = filepath

                fname = os.path.basename(filepath)
                fname_lower = fname.lower()
                ext = os.path.splitext(fname_lower)[1]
                
                threat = None
                
                # 1. Ransom note check
                if fname_lower in RANSOM_NOTE_NAMES:
                    threat = {
                        'filepath': filepath,
                        'filename': fname,
                        'type': 'Ransom Note Document',
                        'severity': 'critical',
                        'description': 'Detected a file with a name characteristic of ransomware notes.',
                        'details': f'Matches known ransom note filename: {fname}'
                    }
                
                # 2. Ransomware Extension Check
                elif ext in RANSOMWARE_EXTS:
                    threat = {
                        'filepath': filepath,
                        'filename': fname,
                        'type': 'Ransomware Encrypted File',
                        'severity': 'critical',
                        'description': 'File extension matches known ransomware encryption extensions.',
                        'details': f'Suspicious extension: {ext}'
                    }
                
                # 3. Double Extension Check (e.g. invoice.pdf.exe)
                elif len(fname.split('.')) > 2:
                    parts = fname.split('.')
                    # If final extension is executable/script and inner is document/image
                    if parts[-1].lower() in ['exe', 'bat', 'cmd', 'vbs', 'ps1', 'scr', 'lnk'] and parts[-2].lower() in ['pdf', 'docx', 'xlsx', 'txt', 'jpg', 'png']:
                        threat = {
                            'filepath': filepath,
                            'filename': fname,
                            'type': 'Double Extension Spoofing',
                            'severity': 'high',
                            'description': 'Executable masquerading as a document using multiple extensions.',
                            'details': f'Double extension structure: .{parts[-2]}.{parts[-1]}'
                        }

                # 4. Entropy calculation and high-entropy detection (for non-media, non-archive formats)
                if not threat:
                    # Only do for text, source code, document, database or executable styles
                    # Avoid standard images, archives, video formats which are high entropy by design
                    if ext not in ['.zip', '.rar', '.7z', '.tar', '.gz', '.png', '.jpg', '.jpeg', '.mp4', '.mp3', '.pdf', '.docx', '.xlsx']:
                        entropy = calculate_entropy(filepath)
                        if entropy > 7.8:
                            threat = {
                                'filepath': filepath,
                                'filename': fname,
                                'type': 'High Entropy File (Suspected Ransomware)',
                                'severity': 'high',
                                'description': 'Extremely high data entropy suggests the file contents may be encrypted.',
                                'details': f'Entropy score: {entropy}/8.0'
                            }

                # 5. Check hash matching against local database IOCs
                if not threat:
                    md5_h, sha256_h = compute_file_hashes(filepath)
                    if sha256_h:
                        ioc_match = IOC.query.filter((IOC.value == sha256_h) | (IOC.value == md5_h)).first()
                        if ioc_match:
                            threat = {
                                'filepath': filepath,
                                'filename': fname,
                                'type': 'Known Malware IOC Match',
                                'severity': ioc_match.severity or 'high',
                                'description': f'File hash matches a known malicious Indicator of Compromise (IOC) in BIGIL database.',
                                'details': f'Matched IOC: {ioc_match.value} (Actor: {ioc_match.threat_actor or "Unknown"})'
                            }

                if threat:
                    # Compute size
                    try:
                        threat['size'] = os.path.getsize(filepath)
                    except Exception:
                        threat['size'] = 0
                    
                    # Compute hashes if not already done
                    if 'md5' not in threat or 'sha256' not in threat:
                        md5_h, sha256_h = compute_file_hashes(filepath)
                        threat['md5'] = md5_h or 'N/A'
                        threat['sha256'] = sha256_h or 'N/A'
                        
                    with state_lock:
                        scanner_state['threats'].append(threat)

                with state_lock:
                    scanner_state['scanned_files'] += 1

        except Exception as e:
            with state_lock:
                scanner_state['error'] = str(e)
        finally:
            with state_lock:
                scanner_state['is_running'] = False

def start_scan(target_dir, app):
    """Start scan thread."""
    global scanner_state
    with state_lock:
        if scanner_state['is_running']:
            return False
        scanner_state['is_running'] = True
        scanner_state['target_dir'] = target_dir
        scanner_state['scanned_files'] = 0
        scanner_state['total_files'] = 0
        scanner_state['threats'] = []
        scanner_state['error'] = None

    t = threading.Thread(target=run_background_scan, args=(target_dir, app))
    t.daemon = True
    t.start()
    return True

def stop_scan():
    """Cancel execution."""
    global scanner_state
    with state_lock:
        scanner_state['is_running'] = False
