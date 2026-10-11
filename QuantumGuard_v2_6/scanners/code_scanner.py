"""
Source Code Cryptographic Asset Scanner.
Performs AST parsing for Python and structural regex inspection across
JavaScript/TypeScript, Go, Java, C/C++, and Rust.
"""
import os
import ast
import re
from typing import List, Optional
from database.models import CryptoAsset, AssetType, ExposureLevel

class CodeScanner:
    SUPPORTED_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs",
        ".go", ".java", ".c", ".cpp", ".h", ".hpp", ".rs", ".php"
    }

    def scan_file(self, file_path: str) -> List[CryptoAsset]:
        assets = []
        if not os.path.exists(file_path):
            return assets

        ext = os.path.splitext(file_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            return assets

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return assets

        if not content.strip():
            return assets

        # 1. Specialized AST Scanner for Python
        if ext == ".py":
            py_assets = self._scan_python_ast(content, file_path)
            assets.extend(py_assets)

        # 2. Multi-language pattern detection
        pattern_assets = self._scan_code_patterns(content, file_path, ext)
        
        # Deduplicate by line number and algorithm
        seen = set((a.line_number, a.algorithm) for a in assets)
        for pa in pattern_assets:
            if (pa.line_number, pa.algorithm) not in seen:
                assets.append(pa)
                seen.add((pa.line_number, pa.algorithm))

        return assets

    def _scan_python_ast(self, content: str, file_path: str) -> List[CryptoAsset]:
        assets = []
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError:
            # Fall back to regex if file has syntax error
            return assets

        lines = content.splitlines()

        class CryptoVisitor(ast.NodeVisitor):
            def visit_Call(this, node: ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    # also get full attribute if possible
                    if isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"

                line_no = node.lineno
                line_text = lines[line_no - 1] if line_no <= len(lines) else ""

                # RSA Key Generation
                if "generate_private_key" in func_name or "RSA.generate" in func_name or "generate_key" in func_name:
                    # check if rsa or ec
                    key_size = 2048
                    algo = "RSA"
                    for kw in node.keywords:
                        if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                            key_size = kw.value.value
                        elif kw.arg == "curve":
                            algo = "ECDSA"
                    
                    if "ec" in line_text.lower():
                        algo = "ECDSA"

                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                    assets.append(CryptoAsset(
                        name=f"Python KeyGen: {algo}",
                        asset_type=AssetType.SOURCE_CODE.value,
                        location=file_path,
                        line_number=line_no,
                        algorithm=f"{algo}-{key_size}" if algo == "RSA" else algo,
                        key_size=key_size if algo == "RSA" else 256,
                        purpose="Asymmetric Key Generation / Key Exchange",
                        exposure_level=ExposureLevel.INTERNAL_NETWORK.value,
                        data_shelf_life_years=10.0,
                        code_snippet=snippet,
                        raw_metadata={"framework": "Python hazmat/PyCryptodome", "func": func_name}
                    ))

                # Symmetric Ciphers
                elif "AES" in func_name or "TripleDES" in func_name or "Blowfish" in func_name:
                    algo = "AES-128"
                    if "TripleDES" in func_name:
                        algo = "3DES"
                    elif "AES" in func_name:
                        if "256" in line_text:
                            algo = "AES-256"
                        elif "192" in line_text:
                            algo = "AES-192"
                    
                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                    assets.append(CryptoAsset(
                        name=f"Python Symmetric: {algo}",
                        asset_type=AssetType.SOURCE_CODE.value,
                        location=file_path,
                        line_number=line_no,
                        algorithm=algo,
                        key_size=128 if algo == "AES-128" else (256 if algo == "AES-256" else 112),
                        purpose="Data Encryption at Rest / in Transit",
                        exposure_level=ExposureLevel.AT_REST_STORAGE.value,
                        data_shelf_life_years=8.0,
                        code_snippet=snippet,
                        raw_metadata={"framework": "cryptography.hazmat.ciphers", "func": func_name}
                    ))

                # Hashes
                elif any(h in func_name.lower() for h in ["sha1", "md5"]):
                    algo = "SHA-1" if "sha1" in func_name.lower() else "MD5"
                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                    assets.append(CryptoAsset(
                        name=f"Python Hash: {algo}",
                        asset_type=AssetType.SOURCE_CODE.value,
                        location=file_path,
                        line_number=line_no,
                        algorithm=algo,
                        key_size=160 if algo == "SHA-1" else 128,
                        purpose="Integrity / Hashing",
                        exposure_level=ExposureLevel.INTERNAL_NETWORK.value,
                        data_shelf_life_years=3.0,
                        code_snippet=snippet,
                        raw_metadata={"framework": "hashlib", "func": func_name}
                    ))

                this.generic_visit(node)

        visitor = CryptoVisitor()
        try:
            visitor.visit(tree)
        except Exception:
            pass

        return assets

    def _scan_code_patterns(self, content: str, file_path: str, ext: str) -> List[CryptoAsset]:
        assets = []
        lines = content.splitlines()

        # Regular expression patterns for cryptographic usage
        PATTERNS = [
            # RSA
            (r'(?:RSA|rsa)\.(?:generate|generateKeyPair|new_keys|importKey|GenerateKey)', "RSA-2048", 2048, "RSA Key Generation", AssetType.SOURCE_CODE.value),
            (r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']', "RSA-2048", 2048, "Java RSA KeyPairGenerator", AssetType.SOURCE_CODE.value),
            (r'crypto\.generateKeyPairSync\s*\(\s*["\']rsa["\']', "RSA-2048", 2048, "Node.js RSA KeyPair", AssetType.SOURCE_CODE.value),
            (r'EVP_PKEY_RSA|RSA_generate_key_ex', "RSA-2048", 2048, "OpenSSL C/C++ RSA Generation", AssetType.SOURCE_CODE.value),
            
            # ECC / ECDSA / ECDH
            (r'ECDSA|ECDH|secp256r1|prime256v1|crypto/ecdsa|crypto/elliptic', "ECDSA-P256", 256, "Elliptic Curve Cryptography", AssetType.SOURCE_CODE.value),
            (r'KeyPairGenerator\.getInstance\s*\(\s*["\']EC["\']', "ECDSA-P256", 256, "Java EC KeyPairGenerator", AssetType.SOURCE_CODE.value),
            (r'crypto\.createECDH\s*\(', "ECDH-P256", 256, "Node.js ECDH Key Agreement", AssetType.SOURCE_CODE.value),
            
            # Diffie-Hellman
            (r'crypto\.createDiffieHellman|DH_new|DiffieHellman', "Diffie-Hellman", 2048, "Diffie-Hellman Key Exchange", AssetType.SOURCE_CODE.value),

            # JWT / Signatures
            (r'["\']alg["\']\s*:\s*["\'](RS256|RS384|RS512|ES256|ES384)["\']', "JWT-RS256", 2048, "JWT Asymmetric Signature", AssetType.SOURCE_CODE.value),
            (r'algorithm\s*=\s*["\'](RS256|RS384|RS512|ES256)["\']', "JWT-RS256", 2048, "JWT Asymmetric Token Signing", AssetType.SOURCE_CODE.value),
            
            # Legacy Ciphers
            (r'DES_cblock|TripleDES|DES3|DES\.new|3DES', "3DES", 112, "Legacy Triple-DES", AssetType.SOURCE_CODE.value),
            (r'crypto\.createCipher(?:iv)?\s*\(\s*["\']des', "DES", 56, "Deprecated DES Cipher", AssetType.SOURCE_CODE.value),
            
            # AES 128 vs 256
            (r'["\']aes-128-(?:gcm|cbc|ctr)["\']|AES_128', "AES-128", 128, "AES-128 Symmetric Cipher", AssetType.SOURCE_CODE.value),
            (r'["\']aes-256-(?:gcm|cbc|ctr)["\']|AES_256', "AES-256", 256, "AES-256 Grover-Resistant Cipher", AssetType.SOURCE_CODE.value),

            # Post-Quantum Primitives (Safe!)
            (r'ML-KEM|Kyber768|kyber|ML-DSA|Dilithium|SLH-DSA|SPHINCS\+|X25519Kyber', "ML-KEM-768", 768, "NIST Post-Quantum Cryptography", AssetType.SOURCE_CODE.value)
        ]

        for idx, line in enumerate(lines, start=1):
            line_strip = line.strip()
            # skip pure comments
            if line_strip.startswith(("//", "#", "/*", "*", "<!--")):
                continue

            for pattern, algo_name, key_size, purpose, asset_type in PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Adjust exposure based on keywords in line/path
                    exposure = ExposureLevel.INTERNAL_NETWORK.value
                    if any(pub in file_path.lower() for pub in ["api", "auth", "gateway", "controller", "route", "public"]):
                        exposure = ExposureLevel.PUBLIC_INTERNET.value

                    # Extract context snippet (3 lines)
                    start_idx = max(0, idx - 2)
                    end_idx = min(len(lines), idx + 1)
                    snippet = "\n".join(lines[start_idx:end_idx])

                    assets.append(CryptoAsset(
                        name=f"{ext[1:].upper()} Crypto: {algo_name}",
                        asset_type=asset_type,
                        location=file_path,
                        line_number=idx,
                        algorithm=algo_name,
                        key_size=key_size,
                        purpose=purpose,
                        exposure_level=exposure,
                        data_shelf_life_years=10.0,
                        code_snippet=snippet,
                        raw_metadata={"language": ext[1:], "matched_pattern": pattern}
                    ))
                    break # one finding per line

        return assets
