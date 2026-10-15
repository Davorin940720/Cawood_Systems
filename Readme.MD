Cawood‑AI Developer Guide – All Tools & How to Talk to the Assistant
This guide explains every tool that the Cawood‑AI integration exposes in your Home Assistant instance, and shows how you can converse with the built‑in conversation entity (conversation.cloud_api_gemma_4_31b) to make the assistant perform those actions.

Table of Contents
Intro – Who is Cawood‑AI?
Talking to the Assistant
Full Tool Cheat‑Sheet
Camera (Hikvision) Tools
Home Assistant Core Tools
File‑System Tools
Terminal & Browser Tools
Project & Email Tools
Custom Integration Calls
Meta & Helper Tools
Full Conversation Example
FAQ
1. Intro – Who is Cawood‑AI?
Cawood‑AI is a private AI assistant running inside your Home Assistant CSHv4 installation. It is backed by the OpenAI Cloud (the conversation.cloud_api_gemma_4_31b entity) and is equipped with a set of tool functions that let it read files, run commands, control devices, query cameras, and more. When you ask a question, the assistant decides which tool to call, executes it, and returns a concise answer.

2. Talking to the Assistant
The easiest way to interact is via the Conversation integration. You can type or speak a request, and Home Assistant will route it to the Gemma LLM.

Service call (UI / Scripts / Automations):
service: conversation.process
entity_id: conversation.cloud_api_gemma_4_31b
data:
  text: "Turn on the living‑room lights"
  agent_id: conversation.cloud_api_gemma_4_31b
  # Optional – capture the response in a variable
  response_variable: talk_reply
When response_variable is provided, the full JSON response is stored in a temporary variable that you can use in subsequent actions (e.g. a notify or input_text.set_value service).

Direct chat UI: Open Developer Tools → Services → conversation.process or use the sidebar “Talk to Assistant”.
From a script (Python HASS):
resp = await hass.services.async_call(
    "conversation",
    "process",
    {"text": "Give me the list of cameras", "agent_id": "conversation.cloud_api_gemma_4_31b"},
    blocking=True,
    return_response=True,
)
# resp will contain a dict with the LLM answer and any tool output
3. Full Tool Cheat‑Sheet
Below is a quick reference for every tool the assistant can use. Each entry shows the tool name, required parameters, and a tiny example.

Tool	Category	Parameters (required)	Example
camera_list	Camera	None (optional dvr)	list all cameras
camera_analyze	Camera	channel, frames (1‑5)	Analyze front‑door: {"channel":101,"frames":3}
camera_events	Camera	channel (optional), limit, since_hours	Show last hour of activity
camera_snapshot	Camera	channel	Get a still image
camera_known	Camera	None	List known people/objects
camera_teach	Camera	event_id, summary, threat_level	Teach a name
camera_questions	Camera	status, channel	List open questions
camera_answer	Camera	question_id, answer	Answer “Who is the child?”
camera_rules	Camera	None	Show threat rules
camera_set_rule	Camera	who, kind, level	Set unknown‑person‑night = high
ha_list_entities	HA Core	domain, area, query	Find all lights
ha_get_state	HA Core	entity_id	Get state of sensor.temp
ha_call_service	HA Core	domain, service, entity_id, data	Turn on light
integration_list	HA Core	None	List custom integrations
integration_call	HA Core	domain, service, data	Call artificial_intelligence.cai_hikvision_get_events
fs_list	Files	path	List config folder
fs_read	Files	path, offset	Read a file
fs_write	Files	path, content, mode	Create script
fs_mkdir	Files	path	Create folder
fs_move	Files	path, to	Rename file
fs_delete	Files	path, recursive	Delete folder
list_machines	Terminal	None	Show agents
run_command	Terminal	command, machine, cwd, timeout	Ping 8.8.8.8 on ha
python_run	Terminal	code, cwd, timeout, stdin	Simple script
python_hass	Terminal	code, timeout	Read all lights
browser	Terminal	action, url, selector, text, key, script, machine	Goto a page
project_list	Projects	None	List all projects
project_search	Projects	folder, query, budget	Search notes for “router”
project_share_email	Projects	folder, to, linkHours	Share project
email_send	Email	to, subject, body	Send alert
describe_capabilities	Meta	topic	Explain how browser works
Every tool can be called directly by the assistant when you phrase a request that matches its intent. For example, saying “Show me the last hour of activity on camera 101” will cause the assistant to invoke camera_events with channel=101 and since_hours=1.

4. Camera (Hikvision) Tools
The CCTV subsystem provides a full AI pipeline. Use the tools to get live analysis, historical events, and to teach the AI.

camera_list – Shows each camera, its number, name, detection state, and last AI summary.
camera_analyze – Capture 1‑5 frames now and get a structured analysis (people, vehicles, animals, threat level, recognised names). Example call:
service: artificial_intelligence.cai_hikvision_analyze
entity_id: camera.front_door
# In a script you would call ha_call_service with:
 data:
   channel: 101
   frames: 3
   question: "Is anyone at the gate?"
   notify: true
camera_events – Pull the log of AI analyses. You can filter by channel, since_hours, and limit.
camera_snapshot – Returns a base‑64 image of the latest frame (useful for dashboards).
camera_known – List all people/vehicles the AI has learned (use before answering “who is X?”.)
camera_teach – Correct a past analysis: give event_id, a proper summary, and optionally set threat_level and remember_threat.
camera_questions & camera_answer – The AI can ask you to identify an unknown person. List open questions with camera_questions and answer with camera_answer.
camera_rules & camera_set_rule – Define custom threat rules, e.g. “unknown person at night = high”.
5. Home Assistant Core Tools
These tools interact with the normal HA entity model (only exposed entities are visible to the voice assistant).

ha_list_entities – List entities with optional filters. Great for “What lights are on?”.
ha_get_state – Get the state and attributes of a specific entity or a CSV list of entities.
ha_call_service – Call any standard HA service (light.turn_on, switch.toggle, climate.set_temperature, etc.).
integration_list / integration_call – Discover custom integrations and invoke their services. For example, the artificial_intelligence integration provides cai_hikvision_get_events.
When a tool is not exposed via ha_* (e.g. device registry or hidden entities), use python_hass for direct hass object access.

6. File‑System Tools
All paths are relative to one of the base locations:

config – Home Assistant /config folder.
projects – All project folders.
_workspace – Scratch folder for temporary files.
smb:ShareName – Network shares.
Typical workflow:

# 1️⃣ List the config folder
service: artificial_intelligence.fs_list
entity_id: ''
data:
  path: "config"

# 2️⃣ Read a file (offset 0 for start)
service: artificial_intelligence.fs_read
entity_id: ''
data:
  path: "config/configuration.yaml"
  offset: 0

# 3️⃣ Write a new helper script
service: artificial_intelligence.fs_write
entity_id: ''
data:
  path: "_workspace/hello.py"
  content: "print('Hello from Home Assistant')"
  mode: "create"
7. Terminal & Browser Tools
list_machines – Shows the HA container (ha) and any registered agents (e.g., Cawood‑Linux).
run_command – Execute a shell command on a machine. Example:
service: artificial_intelligence.run_command
entity_id: ''
data:
  command: "df -h"
  machine: "ha"
  cwd: "/"
  timeout: 30
python_run – Run a one‑off Python script in an isolated process (no live hass object).
python_hass – Run Python inside Home Assistant with full hass access. Example – list all lights:
service: artificial_intelligence.python_hass
entity_id: ''
data:
  code: "return {e.entity_id: e.state for e in hass.states.async_all('light')}"
browser – Drive a real browser on an agent machine (click, type, read, screenshot). Useful for web‑automation tasks.
8. Project & Email Tools
project_list – List all stored knowledge projects.
project_search – Search through documents, PDFs, and notes in a project. Returns the most relevant passages.
project_share_email – Email a project (up to 5 recipients) with a temporary link.
email_send – Send a plain email via the server’s mail account. Useful for alerts.
9. Custom Integration Calls
The integration_list service enumerates all custom integrations you have installed (e.g., alarmo, alexa_media, browser_mod, gonzales, hikconnect, powercalc). After you know the domain and service name, call it with integration_call.

Example – arm the Alarmo alarm panel:

service: artificial_intelligence.integration_call
entity_id: ''
data:
  domain: alarmo
  service: arm
  data:
    entity_id: alarm_control_panel.alarm
    mode: "away"
    code: "1234"
10. Meta & Helper Tools
describe_capabilities – Ask the assistant to explain any tool group (e.g., topic: "cameras"). Great for debugging.
11. Full Conversation Example (5‑step chat)
Below is a complete script that asks the assistant to start a 2‑minute discussion about the universe, capture each answer, and finally dump the entire log into _workspace/universe_chat_log.txt.

# 1️⃣ Prompt the LLM – start the chat
- service: conversation.process
  entity_id: conversation.cloud_api_gemma_4_31b
  data:
    text: "Let's have a short conversation about how the universe was created. Ask me follow‑up questions as needed."
    response_variable: step1

# 2️⃣ Store the first reply
- service: input_text.set_value
  target:
    entity_id: input_text.chat_step_1
  data:
    value: "{{ step1.response.speech.plain.speech }}"

# 3️⃣ Ask the next question (use the previous answer as context)
- service: conversation.process
  entity_id: conversation.cloud_api_gemma_4_31b
  data:
    text: "{{ step1.response.speech.plain.speech }} What role did quantum fluctuations play?"
    response_variable: step2

- service: input_text.set_value
  target:
    entity_id: input_text.chat_step_2
  data:
    value: "{{ step2.response.speech.plain.speech }}"

# 4️⃣ Continue with three more prompts (dark matter, inflation, open questions)...
# (repeat the pattern above, changing the text each time)

# 5️⃣ Consolidate everything into a single text file
- service: artificial_intelligence.fs_write
  entity_id: ''
  data:
    path: "_workspace/universe_chat_log.txt"
    content: >-
      {{ states('input_text.chat_step_1') }}\n\n{{ states('input_text.chat_step_2') }}\n\n{{ states('input_text.chat_step_3') }}\n\n{{ states('input_text.chat_step_4') }}\n\n{{ states('input_text.chat_step_5') }}
    mode: "overwrite"
After the script runs, open https://cawood94.co.za/local/universe_chat_log.txt (once you move it to www as shown in step 5) to see the full transcript.

12. FAQ
Do I need to specify agent_id? Only when you want to use a non‑default conversation agent. For the built‑in Gemma model use conversation.cloud_api_gemma_4_31b.
Can I chain tools? Yes – the assistant can call multiple tools in one request. You can also call tools sequentially in an automation.
Where are the logs? All tool calls are logged in Home Assistant’s logbook and can be inspected via Developer Tools → Events → conversation.
How do I see the raw JSON response? Use the response_variable in a conversation.process call and reference {{ myvar}} in a template or notification.
Is there a rate‑limit? The cloud integration respects OpenAI’s limits. For heavy usage, consider the Plus or Pro plan.
Save this file as cawood_ai_guide.html in /config/www/ and open it at https://cawood94.co.za/local/cawood_ai_guide.html.
