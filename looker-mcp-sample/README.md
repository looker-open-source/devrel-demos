# Looker AI Agent Integration with ADK & MCP

A step-by-step guide to building a basic AI agent utilizing the Google Agent Development Kit (ADK) and Model Context Protocol (MCP) to interact with Looker connection.

## Phase 1: Basic Looker Agent Setup

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

---

## Phase 2: Analytics & Orchestration

In this phase, we add the **BigQuery Agent Analytics Plugin** to track performance and wrap the agent in an **App class** for better orchestration.

### 1. Google Cloud Configuration

To use BigQuery analytics, you must configure your Google Cloud environment:

1.  **Enable the BigQuery API:** Go to the Google Cloud Console and enable the BigQuery API for your project.
2.  **Assign IAM Roles:** Ensure your user account or service account has the following roles:
    *   `bigquery.jobuser` (`roles/bigquery.jobUser`): To run the jobs that log data.
    *   `bigquery.dataeditor` (`roles/bigquery.dataEditor`): To create the analytics dataset and tables.
3.  **Local Authentication:** Run the following command to authenticate your local terminal with Google Cloud:
    ```bash
    gcloud auth application-default login
    ```
4.  **Install Cloud Dependencies:**
    ```bash
    pip install google-cloud-bigquery
    ```
5.  **Environment Variable:** Add your Project ID to your `.env` file:
    ```bash
    GOOGLE_CLOUD_PROJECT="your-google-cloud-project-id"
    ```

### 2. Update `agent.py` with Analytics and the App Class

Modify your `agent.py` to import the plugin and the `App` class, then wrap your `root_agent`.

```python
import os
from dotenv import load_dotenv
from mcp import StdioServerParameters
from google.adk.agents import LlmAgent
from google.adk.tools import MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
# New imports for Phase 2
from google.adk.plugins.bigquery_agent_analytics_plugin import BigQueryAgentAnalyticsPlugin
from google.adk.apps import App

load_dotenv()

# ... (Keep looker_server and looker_toolset setup from Phase 1) ...

root_agent = LlmAgent(
    model='gemini-1.5-flash',
    name='looker_pro',
    description='Looker assistant',
    instruction='You are a helpful assistant that helps manipulate Looker with MCP tools.',
    tools=[looker_toolset],
)

# --- NEW IN PHASE 2 ---

# 1. Initialize the BigQuery Analytics Plugin
# This will automatically create a dataset (e.g., 'looker_agent_analytics') to log interactions.
analytics_plugin = BigQueryAgentAnalyticsPlugin(
    project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
    dataset_id="looker_agent_analytics",
)

# 2. Wrap your agent in an App
app = App(
    name="LookerAgentApp",
    root_agent=root_agent,
    plugins=[analytics_plugin],
)
```

### What is the `App` Class?
The `App` class is the top-level orchestrator in the Google ADK. While an `LlmAgent` handles the logic of a single assistant, the `App` manages the entire application lifecycle. It acts as a central hub that automatically hooks your plugins (like BigQuery analytics) into the agent's execution flow. This ensures that every prompt and response is logged without you having to write custom logging code inside your agent's tools or logic.