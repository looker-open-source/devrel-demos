import os
from dotenv import load_dotenv
from mcp import StdioServerParameters
from google.adk.agents import LlmAgent
from google.adk.tools import ToolContext, MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from google.adk.plugins.bigquery_agent_analytics_plugin import BigQueryAgentAnalyticsPlugin
from google.adk.apps import App

# =====================================================================
# ENVIRONMENT CONFIGURATION & VARIABLE LOADING
# =====================================================================
# Load configuration settings from the local `.env` file.

load_dotenv(dotenv_path=".env")

looker_client_id = os.getenv("LOOKER_CLIENT_ID")
looker_client_secret = os.getenv("LOOKER_CLIENT_SECRET")
looker_base_url = os.getenv("LOOKER_BASE_URL")

# =====================================================================
# CONFIGURING DATA COLLECTION FOR THE AGENTS
# =====================================================================
# Configure the BigQuery Agent Analytics Plugin.

plugin = BigQueryAgentAnalyticsPlugin(
    project_id=os.getenv("GOOGLE_CLOUD_PROJECT"),
    dataset_id="basic_looker_agent_analytics",
)

# =====================================================================
# CONFIGURING THE DATABASE/TOOL MCP SERVER (STDIO CONNECTION)
# =====================================================================
# Define standard I/O parameters for launching the `toolbox` server.

looker_server = StdioServerParameters(
    command="../toolbox",
    args=["--stdio", "--tools-file", "../tools.yaml"],
    env={
        "LOOKER_BASE_URL":looker_base_url,
        "LOOKER_CLIENT_ID": looker_client_id,
        "LOOKER_CLIENT_SECRET": looker_client_secret,
    },
)

# Wrap the MCP server parameters into a Toolset that the ADK agent can use.
looker_toolset = MCPToolset(
    connection_params=StdioConnectionParams(server_params=looker_server)
)

# =====================================================================
# INITIALIZING THE ADK AGENT WITH GEMINI 3.5 FLASH
# INITIALIZING THE ADK AGENT
# =====================================================================
# Initialize the core Looker agent (`LlmAgent`).
# - We use the highly capable `gemini-3.5-flash` model.
# - We use the model specified in the environment or default to gemini-1.5-flash.
# - We equip it with the `looker_toolset` configured above.
root_agent = LlmAgent(
    model='gemini-2.5-flash',
    name='looker_pro',
    description='A helpful assistant that connects to the Looker resources via mcp-toolbox-for-databases',
    instruction='You are a helpful assistant that helps write, edit, and improve high quality LookML files and manipulate Looker with MCP tools',
    tools=[looker_toolset],
)

# =====================================================================
# CONFIGURE TOP LEVEL APP WORKFLOW MANAGEMENT
# =====================================================================
# Wrap the agents in a top level container to manage lifecycle, configuration, and state for a collection of agents grouped by a root agent

app = App(
    name="LlmAgentDemo",
    root_agent=root_agent,
    plugins=[plugin],
)