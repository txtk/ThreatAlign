from openai import OpenAI

from config import settings


class GLM:
    def __init__(self):
        self.client = OpenAI(base_url=settings.zhipu_url, api_key=settings.zhipu_api_key)

    def send_request_poml(self, poml_content):
        response = self.client.chat.completions.create(
            **poml_content,
            model=settings.zhipu_model_name,
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

glm = GLM()

