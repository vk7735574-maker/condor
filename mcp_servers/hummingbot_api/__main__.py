from mcp_servers._secrets_file import load_secrets_file

# Before the server module is imported: it builds its settings at import.
load_secrets_file()

from mcp_servers.hummingbot_api.server import main  # noqa: E402

main()
