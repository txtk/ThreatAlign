from openai import OpenAI

from config import settings


class XM:
    def __init__(self):
        self.client = OpenAI(base_url=settings.xm_url, api_key=settings.xm_api_key)

    def send_request_poml(self, poml_content):
        response = self.client.chat.completions.create(
            **poml_content,
            model=settings.xm_model_name,
            temperature=settings.temperature,
            stream=False,
            extra_body={"thinking": {
                "type": "enabled",
            }},
        )
        return self.result_handler(response)

    def result_handler(self, response):
        result = response.choices[0].message.content
        # result = result.split("</think>")[1].strip()
        return result

xm = XM()



