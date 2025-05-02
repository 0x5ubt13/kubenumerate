from ai_support import Chatbot
import os

def main():
    chatbot = Chatbot()

    with open(os.path.expanduser("~") + "/transcript_test.txt") as f:
        user_input = [line for line in f]

    print(chatbot.chat(user_input))

if __name__ == "__main__":
    main()