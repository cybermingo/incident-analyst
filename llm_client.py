import os
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()


class LLMClient:
    def __init__(self) -> None:
        self._client = AsyncOpenAI(
            api_key=os.environ["GROQ_API_KEY"],
            base_url=os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1"),
        )
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-20b")
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", 4096))
        self.temperature = float(os.getenv("LLM_TEMPERATURE", 0.2))

    async def chat(self, system_prompt: str, user_prompt: str) -> str:
        response = await self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        content = response.choices[0].message.content
        if not content:
            raise RuntimeError("Model returned an empty response")
        return content


llm_client = LLMClient()
