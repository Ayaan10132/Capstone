import magic 
import json
import pefile
import pyexifinfo 
import hashlib
import ssdeep
import os

class FileInfo:
    def __init__(self, filepath):
        self.filepath = filepath
        try:
            self.pe = pefile.PE(self.filepath)
        except:
            self.pe = None

    def calculate_hashes(self):
        """Calculate all hashes at once for efficiency"""
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        with open(self.filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                
        return {
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest()
        }
        
    def get_size(self):
        return os.path.getsize(self.filepath)

    def run(self):    
        results = {}
        content = open(self.filepath, 'rb').read()  
        results = {
        'MD5'  : hashlib.md5(content).hexdigest(),
        'SHA1'  : hashlib.sha1(content).hexdigest(),
        'SHA251' : hashlib.sha256(content).hexdigest(),
        'sha512'  : hashlib.sha512(content).hexdigest(),    
        'Magic': self.F_Magic(),
        'SSDeep': self.PE_ssdeep(),
        'Type': self.F_Mimetype(),
        'File TYpe': self.F_FileType(),
        #'exiftool_Report': self.F_Exif(),
                                            }
        return results 

    def PE_ssdeep(self):
        try:
            return ssdeep.hash_from_file(self.filepath)
        except ImportError:
            pass
        return ''

    def F_Magic(self):
        return magic.from_file(self.filepath)    


    def F_Mimetype(self):
        return magic.from_file(self.filepath, mime=True) 

    def F_FileType(self):         
        return pyexifinfo.fileType(self.filepath).encode()



    def F_Exif(self):

        exif_report = pyexifinfo.get_json(self.filepath)
        if exif_report:
            exif_report_cleaned = {
                key: value
                for key, value in exif_report[0].items()
                if not (key.startswith("File") or key.startswith("SourceFile"))
            }
            
        return  json.dumps(exif_report_cleaned) 

    def F_Hash(self):
        hashes = {}
        content = open(self.filepath, 'rb').read()  
        #hashlib.md5(open(f, 'rb').read()).hexdigest()
        hashes["Hash_md5"]  = hashlib.md5(content).hexdigest()
        hashes["Hash_sha1"]  = hashlib.sha1(content).hexdigest()
        hashes["Hash_sha251"]  = hashlib.sha256(content).hexdigest()
        hashes["Hash_sha512"]  = hashlib.sha512(content).hexdigest()
        return hashes

    # Add convenience methods that use calculate_hashes()
    def md5(self):
        return self.calculate_hashes()['md5']
        
    def sha1(self):
        return self.calculate_hashes()['sha1']
        
    def sha256(self):
        return self.calculate_hashes()['sha256']
        
    # Add size methods
    def size(self):
        """Return file size in bytes"""
        return os.path.getsize(self.filepath)
        
    def get_size(self):
        """Alias for size() for backward compatibility"""
        return self.size()
        
    def get_hashes(self):
        """Calculate MD5, SHA1, SHA256 hashes and get file type."""
        hashes = {}
        
        try:
            with open(self.filepath, 'rb') as f:
                content = f.read()
                
                # Calculate hashes
                hashes['MD5'] = hashlib.md5(content).hexdigest()
                hashes['SHA1'] = hashlib.sha1(content).hexdigest()
                hashes['SHA256'] = hashlib.sha256(content).hexdigest()
                
                # Get basic file type
                if content.startswith(b'MZ'):
                    hashes['Type'] = 'PE/EXE'
                elif content.startswith(b'%PDF'):
                    hashes['Type'] = 'PDF'
                else:
                    hashes['Type'] = 'Unknown'
                    
            return hashes
            
        except Exception as e:
            print(f"Error calculating hashes: {str(e)}")
            return None
