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
            # ["role": "system", "content": "You are a pentester doing an assessment. Given the 'true' values, write high level issues explaining "],
            {"role": "system", "content": "You are a highly technical quality assurance professional working in a UK-based cyber security consultancy. You will be provided individual issue text to QA for penetration testing reports, these will be part of a larger report which contains a number of issues. Respond concisely and clearly and limit the length of the reply. Include ideas on how to improve the text, or fix errors or ambiguity. Do not provide full example text to replace the input, you are to advise and give ideas only. Do not repeat or summarise the text back to the user, it is not required. Your output will be used as a comment in a Word document, and should be appropriate for such usage"},
            {"role": "user", "content": user_input}
        ]

        payload = {"model": "gpt-4o", "messages": messages}
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"}
        
        response = requests.post(self.url, json=payload, headers=headers, verify=False)
        if response.status_code == 200:
            return response.json().get("choices", [{}])[0].get("message", {}).get("content", "No response content found.")
            # return response.json()
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return "Error: Unable to connect to the chatbot."