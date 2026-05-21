import os
def generate_structured_classification(message_text: str, url: str):
    # Stubbed response for development. Replace with real Gemini call when ready.
    # Returns a small dict matching the expected schema.
    text = message_text.lower()
    score = 0.0
    if 'free' in text or 'crack' in text or '.exe' in url:
        score += 0.6
    if score > 0.5:
        return {"risk_level":"high","reason":"Contains download/crack indicators","confidence":0.9,"recommended_action":"block","iocs":[url]}
    elif score > 0.2:
        return {"risk_level":"medium","reason":"Some suspicious indicators","confidence":0.6,"recommended_action":"warn","iocs":[url]}
    else:
        return {"risk_level":"low","reason":"No strong indicators","confidence":0.3,"recommended_action":"allow","iocs":[]}
