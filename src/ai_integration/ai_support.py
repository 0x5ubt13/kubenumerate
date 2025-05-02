import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning

import os

class Chatbot:
    def __init__(self, url=None, key=None):
        self.url = url
        if url is None:
            with open(os.path.expanduser("~") + "/ai_url.txt", "r") as f:
                self.url = f.read().strip()
        
        self.key = key
        if key is None:
            with open(os.path.expanduser("~") + "/api_key.txt", "r") as f:
                self.key = f.read().strip()

    def chat(self, user_input):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        messages = [
            {"role": "system", "content": user_input}
        ]

        payload = {"model": "gpt-4o", "messages": messages}
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"}
        
        response = requests.post(self.url, json=payload, headers=headers, verify=False)
        if response.status_code == 200:
            return response.json().get("choices", [{}])[0].get("message", {}).get("content", "No response content found.")
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return "Error: Unable to connect to the chatbot."

