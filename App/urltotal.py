import json
from App._config import GetConfig 
from virustotal_python import Virustotal
from pprint import pprint
from base64 import urlsafe_b64encode


class VTotalAPI(): 


	def __init__(self,url):
		self.VirusTotal_API_key =  GetConfig().__api__("Virustotal")["KEY"]
		self.url  = url
	 

	

	def run(self):
		try:
			vtotal = Virustotal(API_KEY=self.VirusTotal_API_key)
			resp = vtotal.request("url/scan", params={"url": self.url}, method="POST")
			url_resp = resp.json()
			scan_id = url_resp["scan_id"]
			analysis_resp = vtotal.request("url/report", params={"resource": scan_id})
			b = analysis_resp.json()
			results = {}  # Initialize as dict instead of set
			
			# Convert any set results to dictionary
			# Example:
			# results['status'] = 'malicious/benign'
			# results['score'] = score
			# results['detections'] = detections
			
			return results  # Return dict instead of set
			
		except Exception as e:
			return {'error': str(e)}  # Return error as dict


