from openai import OpenAI

from config import settings


class SC:
    def __init__(self, api_key, key_index: int = 0):
        self.client = OpenAI(base_url=settings.sc_url, api_key=api_key)
        self.key_label = f"silicon_key_{key_index + 1}"

    def send_request_poml(self, poml_content):
        response = self.client.chat.completions.create(
            **poml_content,
            model=settings.sc_model_name,
            temperature=settings.temperature,
            stream=False,
            extra_body={"thinking": {
                # "type": "enabled",
                "type": "disabled",
            }},
        )
        return self.result_handler(response)

    def result_handler(self, response):
        result = response.choices[0].message.content
        return result

scs = []
for index, i in enumerate(settings.sc_api_key):
    sc = SC(api_key=i, key_index=index)
    scs.append(sc)
