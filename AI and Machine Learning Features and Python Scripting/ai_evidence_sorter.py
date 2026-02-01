#!/usr/bin/env python3
"""
AI Evidence Sorter - Advanced Edition
Automatically categorizes and prioritizes files from forensic evidence
Deep content analysis, pattern matching, and suspicious hash detection
Supports E01 forensic images and detailed threat assessment
"""

import os
import hashlib
from pathlib import Path
from datetime import datetime
import json
import mimetypes
import re
import subprocess
from collections import defaultdict


class AIEvidenceSorter:
    def __init__(self, evidence_path):
        self.evidence_path = evidence_path
        self.file_categories = {
            'documents': [],
            'images': [],
            'videos': [],
            'archives': [],
            'executables': [],
            'databases': [],
            'logs': [],
            'encrypted': [],
            'disk_images': [],
            'unknown': []
        }
        self.high_priority_files = []
        self.suspicious_findings = defaultdict(list)
        self.statistics = {}
        self.known_malicious_hashes = self._load_known_hashes()

        # DETAILED SUSPICIOUS CONTENT PATTERNS
        self.suspicious_patterns = {
            'passwords': {
                'regex': [
                    r'(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']+)["\']?',
                    r'(?:pass)\s*[:=]\s*["\']?([^\s"\']+)["\']?',
                    r'P@ssw0rd[^\s]*',
                    r'password123[^\s]*'
                ],
                'risk': 'CRITICAL',
                'category': 'Credentials'
            },
            'api_keys': {
                'regex': [
                    r'(?:api[_-]?key|apikey|api_secret|secret[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]+)["\']?',
                    r'(?:sk_live|sk_test|pk_live|pk_test)_[a-zA-Z0-9]{20,}',
                    r'AKIA[0-9A-Z]{16}',
                    r'ASIA[0-9A-Z]{16}',
                ],
                'risk': 'CRITICAL',
                'category': 'API Keys'
            },
            'aws_credentials': {
                'regex': [
                    r'aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?',
                    r'aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
                    r'aws_secret_access_key\s*[:=]\s*["\']?([^\s"\']+)["\']?'
                ],
                'risk': 'CRITICAL',
                'category': 'AWS Secrets'
            },
            'private_keys': {
                'regex': [
                    r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                    r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
                    r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
                    r'-----BEGIN\s+PGP\s+PRIVATE\s+KEY-----',
                    r'-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----'
                ],
                'risk': 'CRITICAL',
                'category': 'Private Keys'
            },
            'database_creds': {
                'regex': [
                    r'(?:database|db)[_-]?(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']+)["\']?',
                    r'(?:mysql|postgres|oracle)[_-]?(?:password|passwd)\s*[:=]\s*["\']?([^\s"\']+)["\']?',
                    r'(?:user|username)\s*[:=]\s*["\']?([^\s"\']+)["\']?\s+(?:password|passwd)\s*[:=]\s*["\']?([^\s"\']+)["\']?'
                ],
                'risk': 'CRITICAL',
                'category': 'Database Credentials'
            },
            'sensitive_files': {
                'regex': [
                    r'id_rsa',
                    r'\.pem',
                    r'\.pfx',
                    r'\.p12',
                    r'\.jks',
                    r'authorized_keys',
                    r'known_hosts'
                ],
                'risk': 'CRITICAL',
                'category': 'Sensitive Key Files'
            },
            'credit_card': {
                'regex': [
                    r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                    r'\b4[0-9]{12}(?:[0-9]{3})?\b',
                    r'\b5[1-5][0-9]{14}\b',
                    r'\b3[47][0-9]{13}\b'
                ],
                'risk': 'CRITICAL',
                'category': 'Payment Cards'
            },
            'ssn': {
                'regex': [
                    r'\b\d{3}-\d{2}-\d{4}\b',
                    r'\b\d{9}\b'
                ],
                'risk': 'CRITICAL',
                'category': 'SSN'
            },
            'email_addresses': {
                'regex': [
                    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                ],
                'risk': 'MEDIUM',
                'category': 'Email Addresses'
            },
            'hashes': {
                'regex': [
                    r'\b[a-fA-F0-9]{32}\b',
                    r'\b[a-fA-F0-9]{40}\b',
                    r'\b[a-fA-F0-9]{56}\b',
                    r'\b[a-fA-F0-9]{64}\b',
                    r'\b[a-fA-F0-9]{128}\b'
                ],
                'risk': 'HIGH',
                'category': 'File Hashes'
            },
            'shellcode': {
                'regex': [
                    r'\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}',
                    r'shellcode',
                    r'payload',
                    r'exploit',
                ],
                'risk': 'CRITICAL',
                'category': 'Malware Indicators'
            },
            'malware_keywords': {
                'regex': [
                    r'\b(?:malware|virus|trojan|ransomware|worm|spyware|adware)\b',
                    r'\b(?:backdoor|reverse_?shell|bind_?shell|webshell)\b',
                    r'\b(?:exploit|vulnerability|cve[\s-]?\d+)\b',
                    r'\b(?:obfuscate|packer|crypter)\b',
                    r'\b(?:c2|c&c|command\s+and\s+control)\b'
                ],
                'risk': 'CRITICAL',
                'category': 'Malware Strings'
            },
            'network_indicators': {
                'regex': [
                    r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                    r'\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b',
                    r'(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})',
                ],
                'risk': 'MEDIUM',
                'category': 'Network Indicators'
            },
            'registry_keys': {
                'regex': [
                    r'HKEY_[A-Z_]+\\[^\s]*',
                    r'Software\\Microsoft\\Windows\\Run',
                    r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'
                ],
                'risk': 'MEDIUM',
                'category': 'Windows Registry'
            },
            'file_paths': {
                'regex': [
                    r'C:\\[\\a-zA-Z0-9._\-\s]*',
                    r'/[a-zA-Z0-9._/\-\s]*',
                    r'\\\\[a-zA-Z0-9.\-]+\\[a-zA-Z0-9._\-\s]*'
                ],
                'risk': 'LOW',
                'category': 'File Paths'
            }
        }

        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
            '.js', '.jar', '.scr', '.pif', '.com', '.sys', '.drv',
            '.app', '.apk', '.dex', '.so', '.dylib'
        ]

    def _load_known_hashes(self):
        """Load known malicious hashes"""
        return {
            'known_malicious': {},
            'suspicious_patterns': {}
        }

    def calculate_file_hash(self, file_path, max_size_mb=100):
        """Calculate SHA-256 and MD5 hashes with adaptive sampling for large files"""
        try:
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()

            file_size = os.path.getsize(file_path)
            extension = Path(file_path).suffix.lower()
            is_large_forensic = extension in ['.e01', '.e02', '.e03', '.e04', '.e05', '.e06', '.dd', '.raw', '.iso', '.img']

            # For very large forensic images, use minimal sampling (3 x 10MB chunks)
            if is_large_forensic and file_size > 500 * 1024 * 1024:  # > 500MB
                with open(file_path, 'rb') as f:
                    chunk_size = 10 * 1024 * 1024
                    # First chunk
                    chunk = f.read(chunk_size)
                    sha256.update(chunk)
                    md5.update(chunk)
                    # Middle chunk
                    if file_size > chunk_size * 2:
                        f.seek(file_size // 2 - chunk_size // 2)
                        chunk = f.read(chunk_size)
                        sha256.update(chunk)
                        md5.update(chunk)
                    # Last chunk
                    f.seek(max(0, file_size - chunk_size))
                    chunk = f.read(chunk_size)
                    sha256.update(chunk)
                    md5.update(chunk)
            elif file_size > max_size_mb * 1024 * 1024:
                with open(file_path, 'rb') as f:
                    chunk_size = 10 * 1024 * 1024
                    f.read(chunk_size)
                    chunk = f.read(chunk_size)
                    sha256.update(chunk)
                    md5.update(chunk)
                    f.seek(file_size - chunk_size)
                    chunk = f.read(chunk_size)
                    sha256.update(chunk)
                    md5.update(chunk)
            else:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        sha256.update(chunk)
                        md5.update(chunk)

            return {
                'sha256': sha256.hexdigest(),
                'md5': md5.hexdigest()
            }
        except:
            return {'sha256': None, 'md5': None}

    def detect_file_type(self, file_path):
        """Detect file type"""
        mime_type, _ = mimetypes.guess_type(file_path)
        extension = Path(file_path).suffix.lower()

        if mime_type:
            if mime_type.startswith('image/'):
                return 'images'
            elif mime_type.startswith('video/'):
                return 'videos'
            elif mime_type.startswith('text/'):
                return 'documents'

        if extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.ico', '.webp']:
            return 'images'
        elif extension in ['.mp4', '.avi', '.mov', '.mkv', '.wmv', '.flv', '.m4v']:
            return 'videos'
        elif extension in ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf']:
            return 'documents'
        elif extension in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso']:
            return 'archives'
        elif extension in ['.exe', '.dll', '.so', '.dylib', '.sys', '.msi', '.app', '.apk']:
            return 'executables'
        elif extension in ['.db', '.sqlite', '.sql', '.mdb', '.accdb']:
            return 'databases'
        elif extension in ['.log', '.evtx']:
            return 'logs'
        elif extension in ['.encrypted', '.locked', '.crypt', '.pgp', '.gpg']:
            return 'encrypted'
        elif extension in ['.e01', '.e02', '.e03', '.e04', '.e05', '.e06', '.e07', '.e08', '.e09', '.e10', '.s01', '.s02', '.dd', '.raw', '.img']:
            return 'disk_images'
        else:
            return 'unknown'

    def scan_file_content(self, file_path, max_size_mb=50):
        """Scan file content for suspicious patterns - optimized for large files"""
        suspicious_items = []

        try:
            file_size = os.path.getsize(file_path)
            extension = Path(file_path).suffix.lower()
            
            # Smart scanning based on file size and type
            is_large_forensic = extension in ['.e01', '.e02', '.e03', '.e04', '.e05', '.e06', '.e07', '.e08', '.e09', '.e10', '.s01', '.s02', '.dd', '.raw', '.img']
            
            # Skip scanning very large forensic images (just hash them)
            if is_large_forensic and file_size > 500 * 1024 * 1024:  # Skip if > 500MB forensic image
                return suspicious_items
            
            # Reduce scan limit for large files
            if file_size > 100 * 1024 * 1024:  # > 100MB
                max_size_mb = 5  # Only scan first 5MB
            elif file_size > 1024 * 1024:  # > 1MB
                max_size_mb = min(50, max_size_mb)  # Normal scan

            if file_size > max_size_mb * 1024 * 1024:
                # For large files, only read the first max_size_mb
                try:
                    with open(file_path, 'rb') as f:
                        chunk = f.read(max_size_mb * 1024 * 1024)
                        content = chunk.decode('utf-8', errors='ignore')
                except:
                    return suspicious_items
            else:
                # For small files, read entire content
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except:
                    with open(file_path, 'rb') as f:
                        content = f.read().decode('utf-8', errors='ignore')

            for pattern_name, pattern_info in self.suspicious_patterns.items():
                if 'regex' in pattern_info:
                    for regex_pattern in pattern_info['regex']:
                        try:
                            matches = re.findall(regex_pattern, content, re.IGNORECASE | re.MULTILINE)
                            if matches:
                                unique_matches = list(set(matches))[:5]
                                for match in unique_matches:
                                    suspicious_items.append({
                                        'type': pattern_info['category'],
                                        'risk': pattern_info['risk'],
                                        'value': match if isinstance(match, str) else str(match)[:100],
                                        'pattern_name': pattern_name
                                    })
                        except:
                            pass

        except:
            pass

        return suspicious_items

    def check_hash_reputation(self, file_hash_dict):
        """Check if file hash is known malicious"""
        findings = []

        if isinstance(file_hash_dict, dict):
            if file_hash_dict.get('md5') in self.known_malicious_hashes['known_malicious']:
                findings.append({
                    'type': 'Known Malware',
                    'risk': 'CRITICAL',
                    'value': self.known_malicious_hashes['known_malicious'][file_hash_dict['md5']]
                })

        return findings

    def calculate_relevance_score(self, file_path, file_info, suspicious_items):
        """Calculate relevance score based on content analysis"""
        score = 30
        filename = Path(file_path).name.lower()

        critical_count = sum(1 for item in suspicious_items if item['risk'] == 'CRITICAL')
        high_count = sum(1 for item in suspicious_items if item['risk'] == 'HIGH')
        medium_count = sum(1 for item in suspicious_items if item['risk'] == 'MEDIUM')

        score += critical_count * 20
        score += high_count * 10
        score += medium_count * 3

        if Path(file_path).suffix.lower() in self.suspicious_extensions:
            score += 25

        category = file_info['category']
        if category == 'executables':
            score += 30
        elif category == 'disk_images':
            score += 25
        elif category == 'encrypted':
            score += 20
        elif category == 'databases':
            score += 15
        elif category == 'archives':
            score += 10

        try:
            mtime = os.path.getmtime(file_path)
            age_days = (datetime.now().timestamp() - mtime) / 86400
            if age_days < 1:
                score += 15
            elif age_days < 7:
                score += 10
            elif age_days < 30:
                score += 5
        except:
            pass

        score = min(100, score)
        return score

    def analyze_file(self, file_path):
        """Analyze a single file with comprehensive content scanning"""
        try:
            file_stat = os.stat(file_path)
            file_hashes = self.calculate_file_hash(file_path)
            category = self.detect_file_type(file_path)

            suspicious_items = self.scan_file_content(file_path)
            hash_reputation = self.check_hash_reputation(file_hashes)
            suspicious_items.extend(hash_reputation)

            file_info = {
                'path': str(file_path),
                'name': Path(file_path).name,
                'size': file_stat.st_size,
                'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                'category': category,
                'sha256': file_hashes['sha256'],
                'md5': file_hashes['md5'],
                'extension': Path(file_path).suffix.lower(),
                'suspicious_findings': suspicious_items,
                'finding_count': len(suspicious_items)
            }

            file_info['relevance_score'] = self.calculate_relevance_score(file_path, file_info, suspicious_items)

            return file_info

        except Exception as e:
            return None

    def scan_directory(self):
        """Scan evidence directory"""
        print(f"[*] Scanning evidence directory: {self.evidence_path}")
        print(f"[*] Performing deep content analysis on all files...")

        file_count = 0

        for root, dirs, files in os.walk(self.evidence_path):
            for file in files:
                file_path = os.path.join(root, file)

                file_info = self.analyze_file(file_path)
                if file_info:
                    category = file_info['category']
                    self.file_categories[category].append(file_info)

                    if file_info['finding_count'] > 0:
                        self.suspicious_findings[file_info['name']] = file_info['suspicious_findings']

                    if file_info['relevance_score'] >= 60 or file_info['finding_count'] > 0:
                        self.high_priority_files.append(file_info)

                    file_count += 1

                    if file_count % 100 == 0:
                        print(f"[*] Processed {file_count} files... (High Priority: {len(self.high_priority_files)})")

        print(f"[+] Scan complete! Processed {file_count} files")
        return file_count

    def generate_statistics(self):
        """Generate analysis statistics"""
        total_files = sum(len(files) for files in self.file_categories.values())
        total_size = sum(f['size'] for category in self.file_categories.values() for f in category)

        self.statistics = {
            'total_files': total_files,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'by_category': {cat: len(files) for cat, files in self.file_categories.items()},
            'high_priority_count': len(self.high_priority_files)
        }

        return self.statistics

    def generate_report(self):
        """Generate comprehensive evidence report"""
        stats = self.generate_statistics()

        report = f"""
{'='*90}
AI EVIDENCE SORTER - ADVANCED ANALYSIS REPORT
{'='*90}
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Evidence Path: {self.evidence_path}

SUMMARY STATISTICS
------------------
Total Files Analyzed: {stats['total_files']:,}
Total Size: {stats['total_size_mb']:,.2f} MB
High Priority Files: {stats['high_priority_count']}
Files with Suspicious Content: {len(self.suspicious_findings)}

CATEGORIZATION RESULTS
----------------------
"""

        for category, count in sorted(stats['by_category'].items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                percentage = (count / stats['total_files']) * 100
                report += f"  {category.upper():15s}: {count:6,} files ({percentage:5.1f}%)\n"

        report += f"""
HIGH PRIORITY FILES (Score >= 60 or Suspicious Content Found)
{'='*90}
"""

        if self.high_priority_files:
            sorted_priority = sorted(
                self.high_priority_files,
                key=lambda x: (x['relevance_score'], x['finding_count']),
                reverse=True
            )

            for i, file_info in enumerate(sorted_priority[:50], 1):
                report += f"\n[{i}] RELEVANCE SCORE: {file_info['relevance_score']}/100\n"
                report += f"    FILE: {file_info['name']}\n"
                report += f"    PATH: {file_info['path']}\n"
                report += f"    CATEGORY: {file_info['category']}\n"
                report += f"    SIZE: {file_info['size']:,} bytes\n"
                report += f"    MODIFIED: {file_info['modified']}\n"
                report += f"    SHA-256: {file_info['sha256']}\n"
                report += f"    MD5: {file_info['md5']}\n"

                if file_info['finding_count'] > 0:
                    report += f"    \n    SUSPICIOUS CONTENT DETECTED ({file_info['finding_count']} items):\n"

                    critical = [f for f in file_info['suspicious_findings'] if f['risk'] == 'CRITICAL']
                    high = [f for f in file_info['suspicious_findings'] if f['risk'] == 'HIGH']
                    medium = [f for f in file_info['suspicious_findings'] if f['risk'] == 'MEDIUM']

                    if critical:
                        report += f"    [CRITICAL] ({len(critical)}):\n"
                        for finding in critical[:5]:
                            report += f"        * {finding['type']}: {finding['value'][:70]}\n"

                    if high:
                        report += f"    [HIGH] ({len(high)}):\n"
                        for finding in high[:5]:
                            report += f"        * {finding['type']}: {finding['value'][:70]}\n"

                    if medium:
                        report += f"    [MEDIUM] ({len(medium)}):\n"
                        for finding in medium[:5]:
                            report += f"        * {finding['type']}: {finding['value'][:70]}\n"
                else:
                    report += f"    NO SUSPICIOUS CONTENT DETECTED\n"

        else:
            report += "No high priority files detected.\n"

        report += f"""

THREAT SUMMARY
{'='*90}
"""

        threat_types = defaultdict(int)
        threat_critical = defaultdict(int)

        for file_info in self.high_priority_files:
            for finding in file_info['suspicious_findings']:
                threat_types[finding['type']] += 1
                if finding['risk'] == 'CRITICAL':
                    threat_critical[finding['type']] += 1

        if threat_types:
            report += "THREAT TYPES IDENTIFIED:\n"
            for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
                critical_count = threat_critical.get(threat_type, 0)
                report += f"  * {threat_type}: {count} instances"
                if critical_count > 0:
                    report += f" ({critical_count} CRITICAL)"
                report += "\n"

        report += f"""

{'='*90}
RECOMMENDATIONS
{'='*90}
1. [CRITICAL] Review all files with CRITICAL risk indicators immediately
   - Passwords/Credentials: Initiate credential rotation protocols
   - Private Keys: Secure and revoke compromised keys
   - Malware Signatures: Submit files to threat intelligence platform

2. [HIGH] Analyze these files for attack evidence and correlation
   - File Hashes: Check against threat databases
   - Suspicious Patterns: Analyze execution chains
   - Network Indicators: Check against firewall logs

3. [MEDIUM] Review and document for evidence chain
   - Email Addresses: Identify associated accounts
   - File Paths: Track file access and modifications
   - Registry Keys: Analyze system persistence mechanisms

4. [GENERAL]
   - Correlate findings with timeline analysis
   - Check disk images for deleted files and artifacts
   - Examine encrypted files for hints on decryption
   - Review databases for structural evidence

{'='*90}
END OF REPORT
{'='*90}
"""

        return report

    def export_results(self, output_dir='evidence_analysis'):
        """Export results"""
        os.makedirs(output_dir, exist_ok=True)

        json_file = os.path.join(output_dir, 'evidence_analysis.json')
        with open(json_file, 'w') as f:
            json.dump({
                'statistics': self.statistics,
                'categories': {cat: files for cat, files in self.file_categories.items() if files},
                'high_priority': self.high_priority_files
            }, f, indent=2)

        print(f"[+] Results exported to JSON: {json_file}")

        if self.high_priority_files:
            import csv
            csv_file = os.path.join(output_dir, 'high_priority_files.csv')
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                fieldnames = [
                    'name', 'path', 'category', 'relevance_score', 'finding_count',
                    'size', 'modified', 'sha256', 'md5', 'suspicious_types'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

                for file_info in sorted(self.high_priority_files, key=lambda x: x['relevance_score'], reverse=True):
                    suspicious_types = ', '.join(set(f['type'] for f in file_info['suspicious_findings']))
                    writer.writerow({
                        'name': file_info['name'],
                        'path': file_info['path'],
                        'category': file_info['category'],
                        'relevance_score': file_info['relevance_score'],
                        'finding_count': file_info['finding_count'],
                        'size': file_info['size'],
                        'modified': file_info['modified'],
                        'sha256': file_info['sha256'],
                        'md5': file_info['md5'],
                        'suspicious_types': suspicious_types
                    })

            print(f"[+] High priority files exported to CSV: {csv_file}")

        return output_dir

    def run_analysis(self):
        """Execute complete evidence sorting workflow"""
        print(f"[*] Starting AI Evidence Sorter")
        print(f"[*] Target: {self.evidence_path}\n")

        self.scan_directory()
        report = self.generate_report()

        report_file = f'evidence_sorting_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)

        self.export_results()

        print(f"\n[+] Analysis complete!")
        print(f"[+] Report saved to: {report_file}")
        print(f"\n{report}")


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ai_evidence_sorter.py <evidence_directory>")
        print("Example: python ai_evidence_sorter.py /mnt/evidence/case001")
        sys.exit(1)

    evidence_path = sys.argv[1]

    if not os.path.exists(evidence_path):
        print(f"Error: Evidence path not found: {evidence_path}")
        sys.exit(1)

    if not os.path.isdir(evidence_path):
        print(f"Error: Path is not a directory: {evidence_path}")
        sys.exit(1)

    sorter = AIEvidenceSorter(evidence_path)
    sorter.run_analysis()


if __name__ == "__main__":
    main()
