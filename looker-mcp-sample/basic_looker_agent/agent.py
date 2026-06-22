import os
from dotenv import load_dotenv
from mcp import StdioServerParameters
from google.adk.agents import LlmAgent
from google.adk.tools import ToolContext, MCPToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams

# =====================================================================
# 1. ENVIRONMENT CONFIGURATION & VARIABLE LOADING
# =====================================================================
# Load configuration settings from the local `.env` file.

load_dotenv()

looker_client_id = os.getenv("LOOKER_CLIENT_ID")
looker_client_secret = os.getenv("LOOKER_CLIENT_SECRET")
looker_base_url = os.getenv("LOOKER_BASE_URL")

# =====================================================================
# 2. CONFIGURING THE DATABASE/TOOL MCP SERVER (STDIO CONNECTION)
# =====================================================================
# Define standard I/O parameters for launching the `toolbox` server.

looker_server = StdioServerParameters(
    command="../toolbox",
    args=["--stdio", "--tools-file", "../tools.yaml"],
    env={
        "LOOKER_BASE_URL": looker_base_url,
        "LOOKER_CLIENT_ID": looker_client_id,
        "LOOKER_CLIENT_SECRET": looker_client_secret
    },
)

# Wrap the MCP server parameters into a Toolset that the ADK agent can use.
looker_toolset = MCPToolset(
    connection_params=StdioConnectionParams(server_params=looker_server)
)

# =====================================================================
# 3. INITIALIZING THE ADK AGENT WITH GEMINI 3.5 FLASH
# =====================================================================
# Initialize the core Looker agent (`LlmAgent`).
# - We use the highly capable `gemini-3.5-flash` model.
# - We equip it with the `looker_toolset` configured above.
root_agent = LlmAgent(
    model='gemini-1.5-flash',
    name='looker_pro',
    description='A helpful assistant that connects to the Looker resources via mcp-toolbox-for-databases',
    instruction='You are a helpful assistant that helps write, edit, and improve high quality LookML files and manipulate Looker with MCP tools',
    tools=[looker_toolset],
)
