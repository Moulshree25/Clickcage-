import os, re, asyncio
from dotenv import load_dotenv
load_dotenv()
import discord
from vt_client import VTClient
from heuristics import decision_engine_local

TOKEN = os.getenv('DISCORD_BOT_TOKEN')
if not TOKEN:
    print("DISCORD_BOT_TOKEN not set in environment or .env")
    # continue but bot won't run
intents = discord.Intents.default()
intents.message_content = True
client = discord.Client(intents=intents)
vt = VTClient()

@client.event
async def on_ready():
    print(f"[Bot] Logged in as {client.user} (id: {client.user.id})")

@client.event
async def on_message(message):
    if message.author == client.user:
        return
    print(f"DEBUG: I saw a message: {message.content}")
    text = message.content or ""
    urls = re.findall(r'(https?://[^\\s]+)', text)
    if not urls:
        return
    for url in urls:
        loop = asyncio.get_event_loop()
        vt_res = await loop.run_in_executor(None, vt.url_report, url)
        if vt_res.get("error"):
            print("VirusTotal Error:", vt_res["details"])
        try:
            from gemini_client import generate_structured_classification
            gem_res = await loop.run_in_executor(None, generate_structured_classification, text, url)
        except Exception:
            gem_res = None
        decision = decision_engine_local(vt_res, text, gem_res)
        print(f"DEBUG: Verdict: {decision['action']} | Reason: {decision['reason']}")
        if decision['action']=='BLOCK':
            try:
                await message.reply(f"⚠️ **Blocked** — This link appears malicious. Reason: {decision['reason']}")
                await message.delete()
            except Exception as ex:
                print("Action failed:", ex)
        elif decision['action']=='WARN':
            await message.reply(f"⚠️ **Warning:** This link may be suspicious. Reason: {decision['reason']}")

if __name__ == "__main__":
    if not TOKEN:
        print("Set DISCORD_BOT_TOKEN in .env and restart.")
    else:
        client.run(TOKEN)
