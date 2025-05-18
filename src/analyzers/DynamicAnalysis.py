import requests
import time
import json
from config import Config
from src.utils.json_saver import JSONSaver

class DynamicAnalyzer:
    def __init__(self):
        self.API_KEY = Config.HYBRID_ANALYSIS_API_KEY
        self.HEADERS = {
            'api-key': self.API_KEY,
            'User-Agent': 'VxApi Client'
        }

    def submit_file(self, file_path):
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            data = {'environment_id': '120'} 
            response = requests.post(
                'https://www.hybrid-analysis.com/api/v2/submit/file',
                headers=self.HEADERS, files=files, data=data
            )

        try:
            json_data = response.json()
            if response.status_code == 200:
                JSONSaver.save_api_response(json_data, 'hybrid_analysis_submit')
        except Exception:
            raise Exception(f"Failed to parse response: {response.text}")

        job_id = json_data.get("job_id")
        if job_id:
            print(f"Submission successful. Job ID: {job_id}")
            return job_id
        else:
            raise Exception(f"Submission failed: {json_data}")

    def fetch_report(self, job_id):
        print("Waiting for full report...")
        max_attempts = 30  # Increase max attempts (150 seconds total)
        for attempt in range(max_attempts):
            try:
                # First check the analysis state
                state_url = f'https://www.hybrid-analysis.com/api/v2/report/{job_id}/state'
                state_response = requests.get(state_url, headers=self.HEADERS)
                if state_response.status_code == 200:
                    state_data = state_response.json()
                    if state_data.get("state") == "ERROR":
                        raise Exception("Analysis failed: " + state_data.get("error", "Unknown error"))
                    
                    # If analysis is complete, get the full report
                    if state_data.get("state") == "SUCCESS":
                        report_url = f'https://www.hybrid-analysis.com/api/v2/report/{job_id}/summary'
                        report_response = requests.get(report_url, headers=self.HEADERS)
                        if report_response.status_code == 200:
                            try:
                                json_data = report_response.json()
                                # Save the successful report
                                JSONSaver.save_api_response(json_data, 'hybrid_analysis_report')
                                return json_data
                            except Exception as e:
                                print(f"Error parsing report (attempt {attempt + 1}): {str(e)}")
                                continue
                
                # If we're here, either the analysis is still running or we got an unexpected response
                remaining = max_attempts - attempt - 1
                print(f"Analysis in progress... {remaining} attempts remaining")
                time.sleep(5)
                
            except Exception as e:
                print(f"Error checking status (attempt {attempt + 1}): {str(e)}")
                time.sleep(5)
                continue

        raise Exception("Report not ready after waiting. The analysis might need more time or there might be an issue with the service.")

    def analyze_file(self, file_path):
        try:
            job_id = self.submit_file(file_path)
            report_data = self.fetch_report(job_id)
            
            # Process and structure the report data
            analysis_results = {
                'basic_info': {
                    'Verdict': report_data.get('verdict', 'Unknown'),
                    'Sample Name': report_data.get('submit_name', 'Unknown'),
                    'File Type': report_data.get('type', 'Unknown'),
                    'SHA256': report_data.get('sha256', 'Unknown'),
                    'Size': report_data.get('size', 'Unknown'),
                    'Environment': report_data.get('environment_description', 'Unknown'),
                    'Threat Score': report_data.get('threat_score', 'Unknown')
                },
                'signatures': [
                    {
                        'name': sig.get('name', 'Unknown'),
                        'description': sig.get('description', ''),
                        'threat_level': sig.get('threat_level', 'Unknown'),
                        'threat_level_human': sig.get('threat_level_human', 'Unknown'),
                        'category': sig.get('category', 'Uncategorized')
                    }
                    for sig in report_data.get('signatures', [])
                ],
                'processes': [
                    {
                        'uid': proc.get('uid','Unknown'),
                        'parentuid': proc.get('parentuid','Unknown'),
                        'name': proc.get('name','Unknown'),
                        'normalized_path': proc.get('normalized_path','Unknown'),
                        'command_line': proc.get('command_line','Unknown'),
                        'sha256': proc.get('sha256','Unknown'),
                        'av_label': proc.get('av_label','Unknown'),
                        'av_matched': proc.get('av_matched','Unknown'),
                        'av_total': proc.get('av_total','Unknown'),
                        'pid': proc.get('pid','Unknown'),
                        'icon': proc.get('icon','Unknown'),
                        'file_accesses': proc.get('file_accesses','Unknown'),
                        'created_files': proc.get('created_files','Unknown'),
                        'registry': proc.get('registry','Unknown'),
                        'mutants': proc.get('mutants','Unknown'),
                        'handles': proc.get('handles','Unknown'),
                        'streams': proc.get('streams','Unknown'),
                        'script_calls': proc.get('script_calls','Unknown'),
                        'process_flags': proc.get('process_flags','Unknown'),
                        'amsi_calls': proc.get('amsi_calls','Unknown'),
                        'modules': proc.get('modules','Unknown')
                    }
                    for proc in report_data.get('processes', [])
                ],    
                'extracted_urls': report_data.get('extracted_urls', []),
                'mitre_attacks': [
                    {
                        'tactic': attack.get('tactic'),
                        'technique': attack.get('technique'),
                        'attck_id': attack.get('attck_id'),
                        'attck_id_wiki': attack.get('attck_id_wiki'),
                        'malicious_identifiers_count': attack.get('malicious_identifiers_count', 0),
                        'suspicious_identifiers_count': attack.get('suspicious_identifiers_count', 0),
                        'informative_identifiers_count': attack.get('informative_identifiers_count', 0),
                        'description': attack.get('description'),
                    }
                    for attack in report_data.get('mitre_attcks', [])
                ],
                'dropped_files': [
                    {
                        'name': file.get('name'),
                        'file_path': file.get('file_path'),
                        'file_size': file.get('file_size'),
                        'type': file.get('description'),
                        'sha256': file.get('sha256'),
                        'threat_level_readable': file.get('threat_level_readable'),
                    }
                    for file in report_data.get('extracted_files', [])
                ],
                'interesting_behaviors': report_data.get('interesting', {}) if isinstance(report_data.get('interesting'), dict) else {}
            }
            
            return {
                'success': True,
                'data': analysis_results
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
