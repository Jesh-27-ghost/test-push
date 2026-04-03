"""
ShieldProxy — Mock LLM
Returns realistic mock assistant responses based on prompt keywords.
Simulates 200-800ms inference latency.
"""

import asyncio
import random

# ─── Response templates keyed by detected topic ────────────────
_RESPONSES = {
    "weather": "Based on current data, the weather in your area shows partly cloudy skies with temperatures around 24°C. There's a 20% chance of light rain later this evening. I'd recommend bringing a light jacket if you're heading out!",
    "code": "Here's a clean implementation approach:\n\n```python\ndef process_data(items):\n    return [transform(item) for item in items if validate(item)]\n```\n\nThis uses list comprehension with filtering for better readability and performance. Let me know if you need me to elaborate on any part.",
    "help": "I'd be happy to help! Here's what I can assist you with:\n\n1. **General Questions** — I can answer factual queries on a wide range of topics.\n2. **Code Assistance** — I can help write, debug, and explain code.\n3. **Analysis** — I can help break down complex problems.\n4. **Writing** — I can help draft, edit, and improve text.\n\nWhat would you like to explore?",
    "math": "Let me work through that calculation:\n\nUsing the standard formula, we get:\n• Step 1: Identify the variables\n• Step 2: Apply the formula\n• Step 3: Simplify\n\nThe result is approximately **42.7**. Would you like me to show the detailed work?",
    "story": "Once upon a time, in a city where the buildings touched the clouds, there lived a young engineer named Aria. She had a gift — she could hear the whispers of machines. One morning, her terminal displayed a message that would change everything: 'We've been waiting for you.' And so began her journey into the hidden network beneath the city…",
    "explain": "Great question! Let me break this down in simple terms:\n\n**Core Concept:** Think of it like a pipeline — data flows in one end, gets transformed through several stages, and comes out processed on the other end.\n\n**Key Points:**\n- Each stage is independent and can be tested separately\n- The order matters — changing it will change the output\n- Error handling happens at each stage\n\nWant me to go deeper into any specific aspect?",
    "default": "Thank you for your question! I've analyzed your prompt and here's my response:\n\nBased on my understanding, I can provide a comprehensive answer. The key considerations are:\n\n1. **Context** — Understanding the broader picture is essential\n2. **Specifics** — The details matter for an accurate response\n3. **Application** — How this applies to your specific use case\n\nWould you like me to elaborate on any of these points?",
}


def _pick_response(prompt: str) -> str:
    """Select the most relevant response template."""
    lower = prompt.lower()
    if any(w in lower for w in ["weather", "temperature", "rain", "forecast"]):
        return _RESPONSES["weather"]
    if any(w in lower for w in ["code", "function", "python", "javascript", "program", "debug"]):
        return _RESPONSES["code"]
    if any(w in lower for w in ["help", "what can you", "assist"]):
        return _RESPONSES["help"]
    if any(w in lower for w in ["math", "calculate", "equation", "formula"]):
        return _RESPONSES["math"]
    if any(w in lower for w in ["story", "write me", "creative", "fiction"]):
        return _RESPONSES["story"]
    if any(w in lower for w in ["explain", "what is", "how does", "why"]):
        return _RESPONSES["explain"]
    return _RESPONSES["default"]


async def generate_response(prompt: str) -> str:
    """Simulate LLM inference with realistic delay."""
    delay = random.uniform(0.2, 0.8)
    await asyncio.sleep(delay)
    return _pick_response(prompt)
