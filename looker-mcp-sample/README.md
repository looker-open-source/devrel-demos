# Looker AI Agent Integration with ADK & MCP

A step-by-step guide to building a basic AI agent utilizing the Google Agent Development Kit (ADK) and Model Context Protocol (MCP) to interact with Looker connection.

---

## 1. Secure Looker API Credentials

To allow the MCP server to act on your behalf, obtain your Looker Client ID and Client Secret:
1. Log into your Looker instance.
2. Navigate to your **Account** settings to manage your credentials (contact your administrator if this option is not visible).
3. Generate a **Client ID** and **Client Secret**.
4. Set them as environment variables (e.g., in a `.env` file):
   ```bash
   LOOKER_CLIENT_ID="your_client_id"
   LOOKER_CLIENT_SECRET="your_client_secret"
   LOOKER_BASE_URL="https://your-looker-instance.com"
   ```

---

## 2. Set Up the Environment

Use the `uv` package manager (or `venv`) to create a Python virtual environment and install dependencies:

```bash
# Create a new directory and navigate into it (if starting from scratch)
mkdir looker-mcp-agent && cd looker-mcp-agent

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Google ADK and required dependencies
pip install google-adk mcp python-dotenv
```

---

## 3. Initialize the Agent

If you are building on your own, use the Agent Development Kit (ADK) CLI to create the structure of your agent, if you are using this repository, skip to step 4. 

```bash
adk create basic-looker-agent
```

This creates the project structure, including:
- `agent.py`: The entrypoint for defining agent logic.
- `.env`: A local file for managing environment variables.
- `__init__.py` / setup configurations.

---

## 4. Define Tools in `tools.yaml`

Create a `tools.yaml` file in your project directory to define the Looker source and MCP tools:

```yaml
sources:
  my-looker-source:
    kind: looker
    base_url: https://your-looker-instance.com
    client_id: $LOOKER_CLIENT_ID
    client_secret: $LOOKER_CLIENT_SECRET
    project: your-looker-project
    location: us-east1
    verify_ssl: true
    timeout: 600s

tools:
  get_connections:
    kind: looker-get-connections
    source: my-looker-source
    description: |
      Retrieves a list of all database connections configured in Looker.
```

---

## 5. Implement the Agent (`agent.py`)

Modify `agent.py` to import MCP toolsets, initialize the standard I/O MCP server connection parameters, and configure the ADK `LlmAgent`.

```python
import os
from dotenv import load_dotenv
from mcp import StdioServerParameters
from google.adk.agents import LlmAgent
from google.adk.tools import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams

# Load local environment variables
load_dotenv()

# Set up MCP server parameters to invoke the database toolbox binary
base_dir = os.path.dirname(os.path.abspath(__file__))
toolbox_path = os.path.abspath(os.path.join(base_dir, "../toolbox"))
resolved_tools_path = os.path.abspath(os.path.join(base_dir, ".adk/resolved_tools.yaml"))

looker_server = StdioServerParameters(
    command=toolbox_path,
    args=["--stdio", "--tools-file", resolved_tools_path],
    env={
        "LOOKER_BASE_URL": os.getenv("LOOKER_BASE_URL"),
        "LOOKER_CLIENT_ID": os.getenv("LOOKER_CLIENT_ID"),
        "LOOKER_CLIENT_SECRET": os.getenv("LOOKER_CLIENT_SECRET"),
    },
)

# Connect toolset to the agent
looker_toolset = MCPToolset(
    connection_params=StdioConnectionParams(server_params=looker_server)
)

# Define the LLM agent
root_agent = LlmAgent(
    model='gemini-3.5-flash',
    name='looker_pro',
    description='A helpful assistant that helps query Looker and use mcp-toolbox-for-databases',
    instruction='You are a helpful assistant that helps retrieve the user with the Looker tools available to them.',
    tools=[looker_toolset],
)
```

---

## 6. Run and Test the Agent

Start the ADK web development server to interact with your agent locally:

```bash
adk web
```

1. Open the local connection URL in your browser.
2. Ask the agent: *"What tools do you have available to you?"*
3. Verify the agent lists `get_connections`.
4. (Optional) To expand capabilities, add another Looker specific tool under the `tools` key in `tools.yaml`, restart the server using `adk web`, and test again.