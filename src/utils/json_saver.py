import os
import json
import time
from config import Config

class JSONSaver:
    @staticmethod
    def save_api_response(response_data, api_name):
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"{api_name}_response_{timestamp}.json"
        filepath = os.path.join(Config.OUTPUT_JSON, filename)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(response_data, f, indent=4, ensure_ascii=False)
        
        return filepath

    @staticmethod
    def load_json_response(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f) 