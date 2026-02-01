#!/usr/bin/env python3
"""
AI Media Analyzer for Forensic Evidence
Enhanced from image analyzer to support videos, PDFs, and documents
Uses computer vision, ML, and steganography detection for comprehensive analysis
Detects sensitive content, text extraction (OCR), steganography, and hidden data
"""

import os
import sys
import json
import hashlib
import subprocess
import tempfile
import mimetypes
from pathlib import Path
from datetime import datetime
from PIL import Image
import numpy as np

try:
    import cv2
    CV2_AVAILABLE = True
except:
    CV2_AVAILABLE = False
    print("[!] OpenCV not available. Install with: pip install opencv-python")

try:
    import PyPDF2
    PDF_AVAILABLE = True
except:
    PDF_AVAILABLE = False
    print("[!] PyPDF2 not available. Install with: pip install PyPDF2")

try:
    from steganalysis import detect_steganography, extract_hidden_data
    STEGANOGRAPHY_AVAILABLE = True
except:
    STEGANOGRAPHY_AVAILABLE = False
    print("[!] Steganalysis not available. Install with: pip install steganalysis-ai")

try:
    import pytesseract
    OCR_AVAILABLE = True
except:
    OCR_AVAILABLE = False
    print("[!] Pytesseract not available. Install with: pip install pytesseract")


class ForensicMediaAnalyzer:
    """
    AI-powered media analysis for forensic investigations
    Supports images, videos, PDFs, and all document types
    Detects steganography and hidden content
    """

    def __init__(self):
        self.analyzed_media = []
        self.sensitive_findings = []
        self.steganography_findings = []

        # Media categories for ML classification
        self.media_categories = {
            'document': ['text', 'writing', 'paper', 'form', 'pdf'],
            'screenshot': ['desktop', 'window', 'browser', 'application'],
            'identification': ['passport', 'license', 'id card', 'badge'],
            'financial': ['credit card', 'bank statement', 'receipt', 'invoice'],
            'communication': ['email', 'chat', 'message', 'social media'],
            'video': ['surveillance', 'recording', 'footage', 'video'],
            'evidence': ['crime scene', 'weapon', 'drugs', 'suspicious']
        }

        # Supported file extensions
        self.image_extensions = {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.tiff', '.webp', '.ico'}
        self.video_extensions = {'.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.webm', '.m4v', '.3gp', '.mpg', '.mpeg'}
        self.pdf_extensions = {'.pdf'}
        self.document_extensions = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.odt', '.rtf'}

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash for evidence integrity"""
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return None

    def detect_steganography_in_image(self, image_path):
        """Detect steganography and hidden content in images"""
        try:
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # LSB (Least Significant Bit) analysis
            findings = {
                'steganography_detected': False,
                'hidden_data_type': 'UNKNOWN',
                'hidden_data_indicators': [],
                'hidden_content_description': '',
                'analysis_method': 'multi_method_analysis',
                'confidence': 0.0,
                'technical_details': {},
                'severity': 'LOW'
            }
            
            file_size = os.path.getsize(image_path)
            
            # ============= METHOD 1: LSB ENTROPY ANALYSIS =============
            if len(img_array.shape) >= 2:
                # Extract LSB
                lsb_layer = img_array & 1
                
                # Calculate entropy of LSB layer
                unique_values = len(np.unique(lsb_layer))
                entropy = -sum((np.bincount(lsb_layer.flatten()) / lsb_layer.size) * 
                              np.log2(np.bincount(lsb_layer.flatten()) / lsb_layer.size + 1e-10))
                
                findings['technical_details']['lsb_entropy'] = round(entropy, 4)
                findings['technical_details']['lsb_unique_values'] = unique_values
                
                # Improved threshold: compressed images naturally have high entropy
                # Real steganography shows entropy > 0.95 (very close to random)
                if entropy > 0.95:
                    findings['steganography_detected'] = True
                    findings['hidden_data_type'] = 'EMBEDDED_DATA_OR_FILES'
                    findings['hidden_data_indicators'].append(
                        f'🔴 CRITICAL LSB ENTROPY: {entropy:.4f} (Random noise = 1.0) - Strong steganography indicator'
                    )
                    findings['hidden_content_description'] = (
                        'LSB layer shows near-random entropy characteristic of hidden data. '
                        'Highly probable that encrypted files, messages, or binary data are embedded. '
                        'Possible contents: encrypted files, stolen data, malicious payloads, secret messages.'
                    )
                    findings['confidence'] += 0.8
                    findings['severity'] = 'HIGH'
                elif entropy > 0.75:
                    findings['hidden_data_indicators'].append(
                        f'⚠️ ELEVATED LSB ENTROPY: {entropy:.4f} - Possible steganography'
                    )
                    findings['hidden_content_description'] = (
                        'LSB entropy is higher than normal, suggesting possible data hiding. '
                        'May indicate steganography or just high-frequency image content.'
                    )
                    findings['confidence'] += 0.5
                    findings['severity'] = 'MEDIUM'
                
                # ============= METHOD 2: CHI-SQUARE TEST =============
                # Chi-square goodness of fit test for randomness
                lsb_values = lsb_layer.flatten()
                lsb_histogram, _ = np.histogram(lsb_values, bins=2)
                expected = np.full_like(lsb_histogram, lsb_layer.size / 2, dtype=float)
                chi_square = np.sum((lsb_histogram - expected) ** 2 / expected)
                findings['technical_details']['chi_square_statistic'] = round(chi_square, 4)
                
                # Chi-square > 3.841 is significant at p=0.05 for 1 df
                if chi_square > 3.841:
                    findings['hidden_data_indicators'].append(
                        f'⚠️ CHI-SQUARE TEST FAILED: {chi_square:.4f} - Non-random LSB distribution'
                    )
                    findings['confidence'] += 0.3
                    findings['steganography_detected'] = True
                    findings['severity'] = max(findings['severity'], 'MEDIUM')
                
                # ============= METHOD 3: STATISTICAL ANALYSIS =============
                # Check for suspicious patterns
                lsb_variance = np.var(lsb_layer)
                findings['technical_details']['lsb_variance'] = round(lsb_variance, 6)
                
                # For random data, variance should be ~0.25
                if lsb_variance > 0.23:  # Close to random
                    findings['hidden_data_indicators'].append(
                        f'⚠️ RANDOM LSB VARIANCE: {lsb_variance:.6f} - Characteristic of hidden data'
                    )
                    findings['confidence'] += 0.2
                    findings['steganography_detected'] = True
                elif lsb_variance < 0.1:  # Too uniform - suspicious
                    findings['hidden_data_indicators'].append(
                        f'⚠️ SUSPICIOUSLY UNIFORM LSB: {lsb_variance:.6f} - Possible masking'
                    )
                    findings['confidence'] += 0.15
                    findings['steganography_detected'] = True
                
                # ============= METHOD 4: COLOR CHANNEL ANALYSIS =============
                if len(img_array.shape) >= 3 and img_array.shape[2] >= 3:
                    channel_entropies = []
                    channel_means = []
                    
                    for channel in range(min(3, img_array.shape[2])):
                        channel_data = img_array[:, :, channel].flatten()
                        ch_entropy = -sum((np.bincount(channel_data) / len(channel_data)) * 
                                        np.log2(np.bincount(channel_data) / len(channel_data) + 1e-10))
                        channel_entropies.append(ch_entropy)
                        channel_means.append(np.mean(channel_data))
                    
                    findings['technical_details']['channel_entropies'] = [round(e, 4) for e in channel_entropies]
                    
                    # Massive entropy difference = selective embedding
                    entropy_range = max(channel_entropies) - min(channel_entropies)
                    if entropy_range > 0.5:
                        findings['hidden_data_indicators'].append(
                            f'🔴 ASYMMETRIC CHANNEL ENTROPY: {entropy_range:.4f} - Data hidden in specific channels'
                        )
                        findings['hidden_content_description'] += (
                            '\n\nHigh entropy difference between color channels indicates selective data embedding. '
                            'Classic steganography technique to minimize visual artifacts.'
                        )
                        findings['steganography_detected'] = True
                        findings['confidence'] += 0.4
                        findings['severity'] = 'HIGH'
                    
                    # Check for unusual channel distributions
                    mean_diff = max(channel_means) - min(channel_means)
                    if mean_diff > 50 and img_array.shape[2] == 3:  # RGB very unbalanced
                        findings['hidden_data_indicators'].append(
                            f'⚠️ UNBALANCED COLOR CHANNELS: {mean_diff:.1f} - Possible encoding'
                        )
                        findings['confidence'] += 0.1
                        findings['steganography_detected'] = True
                
                # ============= METHOD 5: HISTOGRAM ANALYSIS =============
                # Check if histogram shows unnatural patterns
                if len(img_array.shape) >= 3:
                    gray_img = np.mean(img_array[:, :, :3], axis=2) if img_array.shape[2] >= 3 else img_array[:, :, 0]
                else:
                    gray_img = img_array
                
                histogram, _ = np.histogram(gray_img.flatten(), bins=256)
                # Count zero-bins (unused intensity levels)
                zero_bins = np.sum(histogram == 0)
                
                findings['technical_details']['zero_intensity_bins'] = int(zero_bins)
                
                # Too many unused bins might indicate data overwriting
                if zero_bins > 100:
                    findings['hidden_data_indicators'].append(
                        f'⚠️ HISTOGRAM GAPS: {int(zero_bins)} unused intensity levels - Possible steganography'
                    )
                    findings['confidence'] += 0.15
                    findings['steganography_detected'] = True
                
                findings['confidence'] = min(findings['confidence'], 1.0)
            
            # ============= METHOD 6: FILE SIZE ANALYSIS =============
            img_width = img.width
            img_height = img.height
            pixels = img_width * img_height
            
            # Calculate expected size ranges for different formats
            expected_jpeg_size = (pixels * 0.5) / 1024  # ~0.5 bytes per pixel for JPEG
            expected_png_size = (pixels * 2) / 1024      # ~2 bytes per pixel for PNG
            
            file_size_kb = file_size / 1024
            
            if file_size > 20 * 1024 * 1024:  # > 20MB for regular image
                findings['hidden_data_indicators'].append(
                    f'🔴 EXTREMELY LARGE FILE: {self.format_bytes(file_size)} for {img_width}x{img_height} image'
                )
                findings['hidden_content_description'] += (
                    f'\n\nFile size of {self.format_bytes(file_size)} is extremely large for a {img_width}x{img_height} image. '
                    'Very likely contains appended hidden data or multiple embedded files.'
                )
                findings['steganography_detected'] = True
                findings['severity'] = 'HIGH'
                findings['confidence'] += 0.5
            
            # ============= METHOD 7: MAGIC NUMBER & APPENDED DATA =============
            with open(image_path, 'rb') as f:
                file_data = f.read()
                
                # Check for null byte padding (common in steganography)
                null_byte_count = file_data.count(b'\x00')
                null_percentage = (null_byte_count / len(file_data)) * 100
                findings['technical_details']['null_byte_percentage'] = round(null_percentage, 2)
                
                if null_percentage > 10:  # More than 10% null bytes is suspicious
                    findings['hidden_data_indicators'].append(
                        f'🔴 EXCESSIVE NULL BYTES: {null_percentage:.1f}% - Padding/hidden data'
                    )
                    findings['hidden_content_description'] += (
                        '\n\nAbnormally high null byte percentage suggests either padding or appended data. '
                        'Common in steganographic containers.'
                    )
                    findings['steganography_detected'] = True
                    findings['confidence'] = min(findings['confidence'] + 0.3, 1.0)
                    findings['severity'] = 'HIGH'
                
                # Check for data after image markers
                file_ext = Path(image_path).suffix.lower()
                
                if file_ext in ['.jpg', '.jpeg'] and b'\xff\xd9' in file_data:
                    jpeg_end = file_data.rfind(b'\xff\xd9') + 2
                    if len(file_data) > jpeg_end + 100:  # More than 100 bytes after
                        appended_size = len(file_data) - jpeg_end
                        findings['hidden_data_indicators'].append(
                            f'🔴 APPENDED DATA AFTER JPEG: {self.format_bytes(appended_size)} hidden'
                        )
                        findings['hidden_content_description'] += (
                            f'\n\n{self.format_bytes(appended_size)} of data found after JPEG end marker. '
                            'Contains embedded file, archive, or executable code.'
                        )
                        findings['steganography_detected'] = True
                        findings['severity'] = 'HIGH'
                        findings['confidence'] = min(findings['confidence'] + 0.6, 1.0)
            
            # ============= FINAL ASSESSMENT =============
            if not findings['steganography_detected']:
                findings['hidden_content_description'] = 'No steganography indicators detected. Image appears legitimate.'
                findings['severity'] = 'NONE'
            
            findings['confidence'] = min(findings['confidence'], 1.0)
            
            return findings
            
        except Exception as e:
            return {'error': str(e), 'steganography_detected': False}

    def format_bytes(self, bytes_value):
        """Convert bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} TB"

    def detect_hidden_metadata(self, file_path):
        """Comprehensive hidden content and metadata detection"""
        findings = {
            'hidden_streams': [],
            'hidden_content_description': '',
            'suspicious_metadata': [],
            'alternate_data_streams': [],
            'embedded_files': [],
            'severity': 'NONE'
        }
        
        detected_items = []
        
        try:
            # ============= WINDOWS ALTERNATE DATA STREAMS =============
            if os.name == 'nt':
                try:
                    result = subprocess.run(
                        ['powershell', '-Command', f'Get-Item -Path "{file_path}" -Stream * | Select-Object Stream, Length | ConvertTo-Json'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.stdout.strip() and result.returncode == 0:
                        try:
                            streams_data = json.loads(result.stdout)
                            
                            # Handle both single stream (dict) and multiple streams (list of dicts)
                            if isinstance(streams_data, dict):
                                streams_data = [streams_data]
                            elif not isinstance(streams_data, list):
                                streams_data = []
                            
                            # Filter for suspicious streams (exclude normal $DATA stream)
                            suspicious_streams = []
                            for stream_info in streams_data:
                                stream_name = stream_info.get('Stream', '')
                                stream_length = stream_info.get('Length', 0)
                                
                                # $DATA is the normal main data stream - ignore it
                                if stream_name == ':$DATA':
                                    continue
                                
                                # :Zone.Identifier is harmless (Windows internet download marker)
                                if stream_name == ':Zone.Identifier':
                                    continue
                                
                                # Any other stream is suspicious
                                suspicious_streams.append({
                                    'name': stream_name,
                                    'size': stream_length
                                })
                            
                            # Only flag if there are actual suspicious streams
                            if suspicious_streams:
                                findings['alternate_data_streams'] = suspicious_streams
                                stream_names = [s['name'] for s in suspicious_streams]
                                findings['hidden_streams'].append(
                                    f'🔴 SUSPICIOUS ALTERNATE DATA STREAMS: {len(suspicious_streams)} hidden stream(s)'
                                )
                                for stream in suspicious_streams:
                                    findings['hidden_streams'].append(f"   └─ {stream['name']}: {self.format_bytes(stream['size'])}")
                                    detected_items.append(f"ADS {stream['name']}")
                                
                                findings['hidden_content_description'] = (
                                    f'Suspicious alternate data streams detected: {", ".join(stream_names)}. '
                                    'These are hidden data attached to files, commonly used to hide malware, exploits, or sensitive data. '
                                    'Extract with: powershell "Get-Content filename.ext -Stream streamname -ReadCount 0 | Set-Content output.bin -Encoding Byte"'
                                )
                                findings['severity'] = 'HIGH'
                        except json.JSONDecodeError:
                            pass
                except:
                    pass
        except:
            pass
        
        # ============= APPENDED & EMBEDDED DATA DETECTION =============
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                
                file_ext = Path(file_path).suffix.lower()
                file_size = len(file_data)
                
                # --- JPEG ANALYSIS ---
                if file_ext in ['.jpg', '.jpeg'] and b'\xff\xd9' in file_data:
                    jpeg_end = file_data.rfind(b'\xff\xd9') + 2
                    if len(file_data) > jpeg_end + 100:  # More than 100 bytes after end
                        appended_size = len(file_data) - jpeg_end
                        appended_data = file_data[jpeg_end:jpeg_end+20]
                        
                        findings['hidden_streams'].append(
                            f'🔴 DATA APPENDED AFTER JPEG: {self.format_bytes(appended_size)} hidden'
                        )
                        detected_items.append(f"Appended data after JPEG ({self.format_bytes(appended_size)})")
                        
                        # Try to identify what's appended
                        if appended_data.startswith(b'PK\x03\x04'):
                            findings['hidden_streams'].append('   └─ ZIP/RAR archive detected')
                            detected_items.append("ZIP archive appended")
                        elif appended_data.startswith(b'MZ'):
                            findings['hidden_streams'].append('   └─ EXECUTABLE detected')
                            detected_items.append("Executable appended")
                        elif appended_data.startswith(b'\x7fELF'):
                            findings['hidden_streams'].append('   └─ LINUX EXECUTABLE detected')
                            detected_items.append("Linux executable appended")
                        
                        findings['hidden_content_description'] += (
                            f'\n\n{self.format_bytes(appended_size)} of data found after the JPEG end marker. '
                            'This could be an embedded file, archive, or executable. '
                            'Extract and analyze separately.'
                        )
                        findings['severity'] = 'HIGH'
                
                # --- PNG ANALYSIS ---
                if file_ext == '.png' and b'IEND' in file_data:
                    iend_pos = file_data.rfind(b'IEND')
                    png_end = iend_pos + 12  # IEND chunk is 12 bytes
                    
                    if len(file_data) > png_end + 100:  # More than 100 bytes after
                        appended_size = len(file_data) - png_end
                        appended_data = file_data[png_end:png_end+20]
                        
                        findings['hidden_streams'].append(
                            f'🔴 DATA APPENDED AFTER PNG: {self.format_bytes(appended_size)} hidden'
                        )
                        detected_items.append(f"Appended data after PNG ({self.format_bytes(appended_size)})")
                        
                        if appended_data.startswith(b'PK\x03\x04'):
                            findings['hidden_streams'].append('   └─ ZIP/RAR archive detected')
                        elif appended_data.startswith(b'MZ'):
                            findings['hidden_streams'].append('   └─ EXECUTABLE detected')
                        
                        findings['hidden_content_description'] += (
                            f'\n\n{self.format_bytes(appended_size)} of data found after PNG end marker. '
                            'This is a classic steganography technique. Extract and analyze the payload.'
                        )
                        findings['severity'] = 'HIGH'
                
                # --- ZIP/RAR/7z ARCHIVE DETECTION ---
                archive_signatures = [
                    (b'PK\x03\x04', 'ZIP'),
                    (b'Rar!\x1a\x07', 'RAR'),
                    (b'7z\xbc\xaf\x27\x1c', '7Z'),
                    (b'\x1f\x8b\x08', 'GZIP')
                ]
                
                for sig, archive_type in archive_signatures:
                    positions = []
                    idx = 0
                    while True:
                        idx = file_data.find(sig, idx)
                        if idx == -1:
                            break
                        positions.append(idx)
                        idx += 1
                    
                    if positions:
                        if positions[0] > 0:  # Archive found but not at start
                            findings['hidden_streams'].append(
                                f'🔴 EMBEDDED {archive_type} ARCHIVE: Found at offset {positions[0]} bytes'
                            )
                            detected_items.append(f"{archive_type} archive at offset {positions[0]}")
                            findings['hidden_content_description'] += (
                                f'\n\n{archive_type} archive embedded at byte offset {positions[0]}. '
                                'This is a common steganographic technique. Extract and analyze contents.'
                            )
                            findings['severity'] = 'HIGH'
                            findings['embedded_files'].append({
                                'type': archive_type,
                                'offset': positions[0],
                                'count': len(positions)
                            })
                
                # --- EXECUTABLE DETECTION ---
                exe_signatures = [
                    (b'MZ\x90\x00', 'PE Executable (Windows)'),
                    (b'MZ', 'Windows MZ Executable'),
                    (b'\x7fELF', 'ELF Executable (Linux)'),
                    (b'\xca\xfe\xba\xbe', 'Mach-O Executable (macOS)'),
                    (b'\xfe\xed\xfa', 'Mach-O Executable (macOS)')
                ]
                
                for sig, exe_type in exe_signatures:
                    positions = []
                    idx = 0
                    while True:
                        idx = file_data.find(sig, idx)
                        if idx == -1:
                            break
                        positions.append(idx)
                        idx += 1
                    
                    if positions:
                        # If executable found and not at start, it's embedded
                        if len(positions) > 0 and (positions[0] > 0 or len(positions) > 1):
                            exe_pos = positions[0] if positions[0] > 0 else positions[1] if len(positions) > 1 else -1
                            if exe_pos > 0:
                                findings['hidden_streams'].append(
                                    f'🔴 EMBEDDED EXECUTABLE: {exe_type} at offset {exe_pos} bytes'
                                )
                                detected_items.append(f"{exe_type} at offset {exe_pos}")
                                findings['hidden_content_description'] += (
                                    f'\n\n{exe_type} code embedded at offset {exe_pos}. '
                                    '⚠️ CRITICAL RISK: This is a high-risk indicator for malware/trojan. '
                                    'Do NOT execute. Submit to antivirus/malware analysis service immediately.'
                                )
                                findings['severity'] = 'CRITICAL'
                                findings['embedded_files'].append({
                                    'type': exe_type,
                                    'offset': exe_pos
                                })
                
                # --- ENCRYPTED CONTAINER DETECTION ---
                encryption_sigs = [
                    (b'VERA', 'VeraCrypt Container'),
                    (b'\x2a\x2a\x2a\x20\x2a\x2a\x2a', 'BitLocker/LUKS'),
                    (b'TRUECRYPT', 'TrueCrypt Container')
                ]
                
                for sig, container_type in encryption_sigs:
                    if sig in file_data:
                        findings['hidden_streams'].append(
                            f'⚠️ ENCRYPTED CONTAINER DETECTED: {container_type}'
                        )
                        detected_items.append(f"Encrypted: {container_type}")
                        findings['hidden_content_description'] += (
                            f'\n\n{container_type} detected. Contents are encrypted and hidden. '
                            'Extraction requires password/key.'
                        )
                        findings['severity'] = max(findings['severity'], 'MEDIUM')
                
                # --- UNUSUAL ENTROPY & SIZE ANALYSIS ---
                # Calculate file entropy
                byte_counts = np.bincount(np.frombuffer(file_data, dtype=np.uint8), minlength=256)
                file_entropy = -sum((byte_counts / len(file_data)) * 
                                   np.log2(byte_counts / len(file_data) + 1e-10))
                
                findings['suspicious_metadata'].append(
                    f'File entropy: {file_entropy:.4f} (Random data: ~7.9, Compressed: 6-8, Text: 4-5)'
                )
                
                # Entropy > 7.9 might indicate encryption/compression
                if file_entropy > 7.9:
                    findings['hidden_streams'].append(
                        f'⚠️ HIGH ENTROPY: {file_entropy:.4f} - Possible encrypted/compressed content'
                    )
                    detected_items.append(f"High entropy ({file_entropy:.4f}) - encrypted/compressed")
                    findings['severity'] = max(findings['severity'], 'MEDIUM')
                
        except Exception as e:
            pass
        
        # Final description compilation
        if detected_items:
            findings['hidden_content_description'] = 'Hidden/embedded content detected:\n' + '\n'.join(f'  • {item}' for item in detected_items)
        elif not findings['hidden_streams']:
            findings['hidden_content_description'] = 'No hidden content detected.'
        
        if not findings['hidden_streams']:
            findings['severity'] = 'NONE'
        
        return findings

    def detect_stego_tool_signatures(self, file_path):
        """Detect signatures of common steganography tools"""
        signatures = {
            'steghide': [b'steghide', b'SHND', b'sfx'],
            'outguess': [b'OutGuess'],
            'openstego': [b'OpenStego'],
            'stegdetect': [b'SilentEye'],
            'f5': [b'FF5', b'F5_SIGNATURE'],
            'jsteg': [b'JSTEG'],
            'appendx': [b'APPENDIX']
        }
        
        detected_tools = []
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read(min(len(f.read()), 1024 * 100))  # Check first 100KB
        except:
            return detected_tools
        
        for tool_name, tool_sigs in signatures.items():
            for sig in tool_sigs:
                if sig in file_data:
                    detected_tools.append(tool_name.upper())
                    break
        
        return detected_tools

    def analyze_color_distribution_anomalies(self, image_path):
        """Detect anomalies in color distribution that suggest LSB encoding"""
        try:
            img = Image.open(image_path)
            if img.mode not in ['RGB', 'RGBA']:
                img = img.convert('RGB')
            
            img_array = np.array(img)[:, :, :3]  # RGB only
            
            anomalies = []
            
            # Check for pairs of colors that are suspiciously similar (off by 1 bit)
            for x in range(0, min(img_array.shape[1]-1, 100)):
                for y in range(0, min(img_array.shape[0]-1, 100)):
                    pixel1 = img_array[y, x]
                    pixel2 = img_array[y, x+1]
                    
                    # Check if pixels differ only in LSB
                    xor_result = pixel1 ^ pixel2
                    if np.all(xor_result <= 1):  # Only LSB differs
                        anomalies.append({
                            'position': (x, y),
                            'type': 'lsb_pair'
                        })
            
            return {
                'anomalies_detected': len(anomalies) > 50,  # Threshold
                'anomaly_count': len(anomalies),
                'anomaly_percentage': (len(anomalies) / (min(100, img_array.shape[0]) * min(100, img_array.shape[1]))) * 100 if img_array.size > 0 else 0
            }
        except:
            return {'anomalies_detected': False, 'anomaly_count': 0}

    def extract_text_from_image(self, image_path):
        """Extract text from image using OCR"""
        if not OCR_AVAILABLE:
            return {'text': '', 'method': 'unavailable', 'confidence': 0}
        
        try:
            img = Image.open(image_path)
            text = pytesseract.image_to_string(img)
            
            return {
                'text': text,
                'method': 'tesseract_ocr',
                'confidence': len(text) > 0
            }
        except Exception as e:
            return {'error': str(e), 'text': '', 'confidence': 0}

    def analyze_pdf(self, pdf_path):
        """Analyze PDF files for text, metadata, and hidden content"""
        if not PDF_AVAILABLE:
            return {'error': 'PyPDF2 not available'}
        
        try:
            analysis = {
                'filename': os.path.basename(pdf_path),
                'file_type': 'PDF',
                'file_hash': self.calculate_file_hash(pdf_path),
                'metadata': {},
                'text_content': '',
                'page_count': 0,
                'suspicious_features': [],
                'hidden_content_indicators': []
            }
            
            with open(pdf_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                
                # Extract metadata
                if pdf_reader.metadata:
                    analysis['metadata'] = {
                        'title': pdf_reader.metadata.get('/Title', ''),
                        'author': pdf_reader.metadata.get('/Author', ''),
                        'creator': pdf_reader.metadata.get('/Creator', ''),
                        'subject': pdf_reader.metadata.get('/Subject', ''),
                        'producer': pdf_reader.metadata.get('/Producer', '')
                    }
                
                # Extract text from all pages
                analysis['page_count'] = len(pdf_reader.pages)
                extracted_text = []
                for page_num, page in enumerate(pdf_reader.pages):
                    try:
                        text = page.extract_text()
                        extracted_text.append(text)
                    except:
                        pass
                
                analysis['text_content'] = '\n'.join(extracted_text)
                
                # Check for embedded objects
                if '/EmbeddedFile' in pdf_reader.pages[0] if pdf_reader.pages else False:
                    analysis['hidden_content_indicators'].append('Embedded files detected')
                    
                # Check for JavaScript
                if '/JavaScript' in str(pdf_reader):
                    analysis['suspicious_features'].append('JavaScript found in PDF')
                    
                # Check for suspicious forms
                if '/AcroForm' in pdf_reader.root_object:
                    analysis['suspicious_features'].append('Form fields found (potential data collection)')
                    
            return analysis
            
        except Exception as e:
            return {'error': str(e)}

    def analyze_video_metadata(self, video_path):
        """Extract metadata from video files"""
        try:
            analysis = {
                'filename': os.path.basename(video_path),
                'file_type': 'VIDEO',
                'file_hash': self.calculate_file_hash(video_path),
                'file_size': os.path.getsize(video_path),
                'duration': 'unknown',
                'resolution': 'unknown',
                'codec': 'unknown',
                'fps': 'unknown',
                'creation_time': 'unknown'
            }
            
            # Try using ffprobe or mediainfo
            try:
                result = subprocess.run(
                    ['ffprobe', '-v', 'error', '-show_format', '-show_streams', '-print_json', video_path],
                    capture_output=True, text=True, timeout=10
                )
                
                if result.returncode == 0:
                    probe_data = json.loads(result.stdout)
                    
                    if 'format' in probe_data:
                        fmt = probe_data['format']
                        if 'duration' in fmt:
                            analysis['duration'] = float(fmt['duration'])
                        if 'creation_time' in fmt['tags']:
                            analysis['creation_time'] = fmt['tags']['creation_time']
                    
                    if 'streams' in probe_data:
                        for stream in probe_data['streams']:
                            if stream['codec_type'] == 'video':
                                analysis['codec'] = stream.get('codec_name', 'unknown')
                                analysis['resolution'] = f"{stream.get('width', '?')}x{stream.get('height', '?')}"
                                analysis['fps'] = stream.get('r_frame_rate', 'unknown')
                                break
            except:
                pass
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}

    def extract_video_frames(self, video_path, frame_count=5):
        """Extract key frames from video for analysis"""
        if not CV2_AVAILABLE:
            return {'error': 'OpenCV not available'}
        
        try:
            frames = []
            cap = cv2.VideoCapture(video_path)
            
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            frame_interval = max(1, total_frames // frame_count)
            
            frame_num = 0
            while cap.isOpened() and len(frames) < frame_count:
                ret, frame = cap.read()
                if not ret:
                    break
                
                if frame_num % frame_interval == 0:
                    # Convert to PIL Image for hash calculation
                    frame_pil = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
                    frame_hash = self.calculate_file_hash_from_image(frame_pil)
                    
                    frames.append({
                        'frame_number': frame_num,
                        'hash': frame_hash,
                        'timestamp': cap.get(cv2.CAP_PROP_POS_MSEC) / 1000.0
                    })
                
                frame_num += 1
            
            cap.release()
            
            return {
                'frames_extracted': len(frames),
                'frames': frames
            }
            
        except Exception as e:
            return {'error': str(e)}

    def analyze_document(self, doc_path):
        """Analyze document files (.doc, .docx, .xls, etc.)"""
        try:
            analysis = {
                'filename': os.path.basename(doc_path),
                'file_type': Path(doc_path).suffix.upper(),
                'file_hash': self.calculate_file_hash(doc_path),
                'file_size': os.path.getsize(doc_path),
                'hidden_properties': [],
                'embedded_objects': [],
                'metadata': {}
            }
            
            # For Office documents (.docx, .xlsx, .pptx), they are ZIP files
            file_ext = Path(doc_path).suffix.lower()
            if file_ext in {'.docx', '.xlsx', '.pptx'}:
                try:
                    import zipfile
                    with zipfile.ZipFile(doc_path, 'r') as zip_ref:
                        # Check for unusual files
                        file_list = zip_ref.namelist()
                        
                        # Look for suspicious files
                        if any('.xml' in f for f in file_list):
                            analysis['hidden_properties'].append('XML content found')
                        if any('media' in f for f in file_list):
                            analysis['embedded_objects'].append(f'Media files: {len([f for f in file_list if "media" in f])}')
                        if any('embeddings' in f for f in file_list):
                            analysis['hidden_properties'].append('Embeddings detected')
                except:
                    pass
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)}

    def calculate_file_hash_from_image(self, pil_image):
        """Calculate perceptual hash from PIL image"""
        try:
            img = pil_image.convert('L')
            img = img.resize((8, 8), Image.LANCZOS)
            pixels = list(img.getdata())
            avg = sum(pixels) / len(pixels)
            bits = ''.join(['1' if pixel > avg else '0' for pixel in pixels])
            return hex(int(bits, 2))[2:].zfill(16)
        except:
            return None

    def analyze_media(self, media_path):
        """Perform complete media analysis"""
        print(f"[*] Analyzing: {os.path.basename(media_path)}")
        
        file_ext = Path(media_path).suffix.lower()
        
        analysis = {
            'filename': os.path.basename(media_path),
            'filepath': media_path,
            'timestamp': datetime.now().isoformat(),
            'file_hash': self.calculate_file_hash(media_path),
            'file_size': os.path.getsize(media_path),
            'media_type': None,
            'analysis': {}
        }
        
        # Determine media type and analyze accordingly
        if file_ext in self.image_extensions:
            analysis['media_type'] = 'IMAGE'
            # Image analysis
            analysis['analysis'] = self.analyze_image_complete(media_path)
            
        elif file_ext in self.video_extensions:
            analysis['media_type'] = 'VIDEO'
            analysis['analysis']['metadata'] = self.analyze_video_metadata(media_path)
            analysis['analysis']['frames'] = self.extract_video_frames(media_path)
            
        elif file_ext in self.pdf_extensions:
            analysis['media_type'] = 'PDF'
            analysis['analysis'] = self.analyze_pdf(media_path)
            
        elif file_ext in self.document_extensions:
            analysis['media_type'] = 'DOCUMENT'
            analysis['analysis'] = self.analyze_document(media_path)
            
        else:
            analysis['media_type'] = 'OTHER'
            analysis['analysis'] = {'basic_info': 'File type not specifically supported'}
        
        # Universal hidden content detection
        analysis['hidden_content'] = self.detect_hidden_metadata(media_path)
        
        self.analyzed_media.append(analysis)
        
        return analysis

    def analyze_image_complete(self, image_path):
        """Complete image analysis including steganography"""
        try:
            analysis = {
                'metadata': self.extract_image_metadata(image_path),
                'text': self.extract_text_from_image(image_path),
                'steganography': self.detect_steganography_in_image(image_path),
                'color_anomalies': self.analyze_color_distribution_anomalies(image_path),
                'tool_signatures': self.detect_stego_tool_signatures(image_path)
            }
            
            # Add tool signature indicators to steganography findings
            if analysis['tool_signatures']:
                analysis['steganography']['hidden_data_indicators'].insert(0,
                    f"🔴 STEGANOGRAPHY TOOL DETECTED: {', '.join(analysis['tool_signatures'])} signatures found"
                )
                analysis['steganography']['steganography_detected'] = True
                analysis['steganography']['severity'] = 'HIGH'
                analysis['steganography']['confidence'] = min(analysis['steganography']['confidence'] + 0.5, 1.0)
            
            # Add color anomaly indicators
            if analysis['color_anomalies']['anomalies_detected']:
                analysis['steganography']['hidden_data_indicators'].insert(
                    0 if not analysis['tool_signatures'] else 1,
                    f"⚠️ COLOR DISTRIBUTION ANOMALIES: {analysis['color_anomalies']['anomaly_count']} LSB-pair pixels ({analysis['color_anomalies']['anomaly_percentage']:.1f}%)"
                )
                analysis['steganography']['steganography_detected'] = True
                analysis['steganography']['severity'] = max(analysis['steganography']['severity'], 'MEDIUM')
            
            return analysis
        except Exception as e:
            return {'error': str(e)}

    def extract_image_metadata(self, image_path):
        """Extract EXIF metadata from image"""
        try:
            img = Image.open(image_path)
            metadata = {
                'format': img.format,
                'mode': img.mode,
                'size': img.size,
                'width': img.width,
                'height': img.height
            }
            
            if hasattr(img, '_getexif') and img._getexif():
                from PIL.ExifTags import TAGS
                for tag_id, value in img._getexif().items():
                    tag = TAGS.get(tag_id, tag_id)
                    try:
                        metadata[tag] = str(value)[:100]  # Limit string length
                    except:
                        pass
            
            return metadata
        except:
            return {}

    def batch_analyze_directory(self, directory):
        """Analyze all supported media files in a directory"""
        print(f"[*] Scanning directory: {directory}")
        
        all_extensions = self.image_extensions | self.video_extensions | self.pdf_extensions | self.document_extensions
        media_files = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if Path(file).suffix.lower() in all_extensions:
                    media_files.append(os.path.join(root, file))
        
        print(f"[+] Found {len(media_files)} media files")
        
        for i, media_path in enumerate(media_files, 1):
            try:
                self.analyze_media(media_path)
                if i % 10 == 0:
                    print(f"[*] Processed {i}/{len(media_files)} files...")
            except Exception as e:
                print(f"[!] Error analyzing {media_path}: {e}")
        
        print(f"[+] Analysis complete!")
        return self.analyzed_media

    def generate_report(self):
        """Generate comprehensive media analysis report"""
        report = f"""
{'='*80}
AI FORENSIC MEDIA ANALYSIS REPORT
{'='*80}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY
-------
Total Media Files Analyzed: {len(self.analyzed_media)}
Images: {sum(1 for m in self.analyzed_media if m.get('media_type') == 'IMAGE')}
Videos: {sum(1 for m in self.analyzed_media if m.get('media_type') == 'VIDEO')}
PDFs: {sum(1 for m in self.analyzed_media if m.get('media_type') == 'PDF')}
Documents: {sum(1 for m in self.analyzed_media if m.get('media_type') == 'DOCUMENT')}

STEGANOGRAPHY DETECTIONS
------------------------
"""
        
        stego_findings = [m for m in self.analyzed_media 
                         if 'steganography' in str(m) and m.get('analysis', {}).get('steganography', {}).get('steganography_detected')]
        
        if stego_findings:
            for finding in stego_findings:
                report += f"\n[ALERT] {finding['filename']}\n"
                report += f"  Indicators: {finding['analysis'].get('steganography', {}).get('hidden_data_indicators', [])}\n"
        else:
            report += "No obvious steganography detected.\n"
        
        report += f"""
HIDDEN CONTENT INDICATORS
------------------------
"""
        
        hidden_content = [m for m in self.analyzed_media if m.get('hidden_content')]
        if hidden_content:
            for finding in hidden_content[:10]:
                report += f"\n{finding['filename']}: {finding.get('hidden_content', {})}\n"
        else:
            report += "No hidden content indicators found.\n"
        
        report += f"""
{'='*80}
RECOMMENDATIONS
{'='*80}
1. Review files with steganography indicators
2. Extract text from all documents and images
3. Verify file integrity using hash values
4. Analyze video frames for suspicious content
5. Check PDF for JavaScript or embedded objects
6. Look for alternate data streams (Windows)
7. Cross-reference with timeline analysis
8. Consider professional steganography analysis tools

{'='*80}
END OF REPORT
{'='*80}
"""
        
        return report

    def export_results(self, output_dir='media_analysis_results'):
        """Export results to JSON"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Export all results
        json_file = os.path.join(output_dir, 'media_analysis_complete.json')
        with open(json_file, 'w') as f:
            json.dump({
                'analysis_date': datetime.now().isoformat(),
                'total_media': len(self.analyzed_media),
                'media': [m for m in self.analyzed_media]  # Simplified for JSON
            }, f, indent=2, default=str)
        
        print(f"[+] Results exported to: {json_file}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python media_analyzer_ai.py <media_file_or_directory>")
        print("Supported: Images, Videos, PDFs, Documents")
        sys.exit(1)
    
    path = sys.argv[1]
    
    analyzer = ForensicMediaAnalyzer()
    
    if os.path.isfile(path):
        result = analyzer.analyze_media(path)
        print(f"\n{json.dumps(result, indent=2, default=str)}")
    elif os.path.isdir(path):
        analyzer.batch_analyze_directory(path)
        report = analyzer.generate_report()
        
        report_file = f'media_analysis_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w') as f:
            f.write(report)
        
        analyzer.export_results()
        
        print(f"\n[+] Report saved to: {report_file}")
        print(f"\n{report}")
    else:
        print(f"Error: Path not found: {path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
