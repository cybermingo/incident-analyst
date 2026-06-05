import os
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

class LLMClient:
    def __init__(self):
        api_key = os.getenv("GROQ_API_KEY")
        base_url = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
        model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
        
        if not api_key:
            # Fail fast with clear message
            raise RuntimeError("GROQ_API_KEY not set in environment. Check your .env file!")
            
  
        self.client = AsyncOpenAI(
            api_key=api_key, 
            base_url=base_url,
            timeout=10.0,      
            max_retries=0      
        )
        
        self.model = model
        self.temp = float(os.getenv("LLM_TEMPERATURE", "0.2"))
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "2048"))

    async def chat(self, system, user):
        out = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role":"system","content":system},
                      {"role":"user","content":user}],
            temperature=self.temp,
            max_tokens=self.max_tokens
        )
        return out.choices[0].message.content

llm_client = LLMClient()