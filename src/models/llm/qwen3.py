from openai import OpenAI

from config import settings
from httpx import Timeout


class Qwen3:
    def __init__(self):
        self.client = OpenAI(base_url=settings.base_url_chat, api_key=settings.api_key_chat, timeout=Timeout(timeout=120.0, connect=60.0))

    def send_request(self, system_prompt, user_prompt):
        response = self.client.chat.completions.create(
            model=settings.qwen_qa,
            messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}],
            temperature=settings.temperature,
            stream=False,  # Set to True if the provider supports streaming output.
        )

        return self.result_handler(response)

    def send_request_poml(self, poml_content):
        response = self.client.chat.completions.create(
            **poml_content, model=settings.qwen_qa, temperature=settings.temperature, stream=False
        )
        return self.result_handler(response)

    def result_handler(self, response):
        result = response.choices[0].message.content
        result = result.split("</think>")[1].strip()
        return result


qwen = Qwen3()
