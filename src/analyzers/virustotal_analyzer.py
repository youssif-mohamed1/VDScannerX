import time
import requests
from config import Config
from src.utils.json_saver import JSONSaver

class VirusTotalAnalyzer:
    def __init__(self):
        self.api_key = Config.VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def get_report(self, file_hash):
        url = f"{self.base_url}/files/{file_hash}"
        response = requests.get(url, headers=self.headers)
        
        if response.status_code == 200:
            json_response = response.json()
            # Save the raw API response
            JSONSaver.save_api_response(json_response, 'virustotal')
            return self._summarize_results(json_response['data']['attributes'])
        return None

    def _summarize_results(self, attributes):
        stats = attributes.get('last_analysis_stats', {})
        return {
            'hash': attributes.get('sha256', 'N/A'),
            'type': attributes.get('type_description', 'Unknown'),
            'size': attributes.get('size', 'N/A'),
            'first_seen': attributes.get('first_submission_date', 'N/A'),
            'last_seen': attributes.get('last_analysis_date', 'N/A'),
            'malicious_count': stats.get('malicious', 0),
            'total_engines': sum(stats.values()),
            'names': attributes.get('names', []),
            'analysis_results': attributes.get('last_analysis_results', {}),
            'analysis_stats': stats,
            'undetected_count': stats.get('undetected', 0)
        } 