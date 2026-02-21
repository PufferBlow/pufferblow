from __future__ import annotations

from dataclasses import dataclass

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Select, Static


@dataclass
class SetupWizardResult:
    """SetupWizardResult class."""
    mode: str
    database_name: str
    database_username: str
    database_password: str
    database_host: str
    database_port: str
    server_name: str
    server_description: str
    server_welcome_message: str
    owner_username: str
    owner_password: str


class SetupWizardApp(App[SetupWizardResult | None]):
    """SetupWizardApp class."""
    CSS = """
    Screen {
        background: #0a1325;
    }

    #root {
        width: 96%;
        max-width: 120;
        height: auto;
        margin: 1 2;
        border: round #2dd4bf;
        background: #101b33;
        padding: 1 2;
    }

    #title {
        text-style: bold;
        color: #a7f3d0;
        margin-bottom: 1;
    }

    .section {
        margin-top: 1;
        color: #93c5fd;
        text-style: bold;
    }

    Input, Select {
        margin-bottom: 1;
    }

    #status {
        color: #fcd34d;
        margin-top: 1;
        height: 2;
    }

    #actions {
        margin-top: 1;
        height: auto;
    }

    Button {
        min-width: 18;
        margin-right: 1;
    }
    """

    BINDINGS = [
        ("ctrl+s", "submit", "Run Setup"),
        ("ctrl+c", "quit", "Quit"),
    ]

    def __init__(self, has_existing_config: bool) -> None:
        """Initialize the instance."""
        super().__init__()
        self.has_existing_config = has_existing_config
        self.result: SetupWizardResult | None = None

    def compose(self) -> ComposeResult:
        """Compose."""
        yield Header(show_clock=True)
        with Container(id="root"):
            yield Static("PufferBlow Server Setup Wizard", id="title")
            with VerticalScroll():
                yield Static("Mode", classes="section")
                yield Select(
                    options=[
                        ("Full setup (database + server + owner)", "full"),
                        ("Server configuration only", "server_only"),
                        ("Update existing server info", "server_update"),
                    ],
                    value="full",
                    id="mode",
                    prompt="Select setup mode",
                )

                yield Static("Database", classes="section")
                yield Input(placeholder="Database name", id="database_name")
                yield Input(placeholder="Database username", id="database_username")
                yield Input(
                    placeholder="Database password",
                    password=True,
                    id="database_password",
                )
                yield Input(
                    placeholder="Database host (default: localhost)",
                    id="database_host",
                )
                yield Input(
                    placeholder="Database port (default: 5432)",
                    id="database_port",
                )

                yield Static("Server", classes="section")
                yield Input(placeholder="Server name", id="server_name")
                yield Input(placeholder="Server description", id="server_description")
                yield Input(
                    placeholder="Server welcome message",
                    id="server_welcome_message",
                )

                yield Static("Owner account", classes="section")
                yield Input(placeholder="Owner username", id="owner_username")
                yield Input(
                    placeholder="Owner password",
                    password=True,
                    id="owner_password",
                )

                with Horizontal(id="actions"):
                    yield Button("Run setup", variant="success", id="run")
                    yield Button("Cancel", variant="error", id="cancel")
                yield Static("", id="status")
        yield Footer()

    def on_mount(self) -> None:
        """On mount."""
        self.query_one("#database_host", Input).value = "localhost"
        self.query_one("#database_port", Input).value = "5432"
        self._sync_mode_fields()

    def on_select_changed(self, event: Select.Changed) -> None:
        """On select changed."""
        if event.select.id == "mode":
            self._sync_mode_fields()

    def action_submit(self) -> None:
        """Action submit."""
        self._submit()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """On button pressed."""
        if event.button.id == "cancel":
            self.exit(None)
            return
        if event.button.id == "run":
            self._submit()

    def _sync_mode_fields(self) -> None:
        """Sync mode fields."""
        mode = self.query_one("#mode", Select).value
        is_full = mode == "full"
        for field_id in [
            "#database_name",
            "#database_username",
            "#database_password",
            "#database_host",
            "#database_port",
            "#owner_username",
            "#owner_password",
        ]:
            self.query_one(field_id, Input).disabled = not is_full

        if not is_full and not self.has_existing_config:
            self.query_one("#status", Static).update(
                "No bootstrap database URI found. Use full setup mode first."
            )
        else:
            self.query_one("#status", Static).update("")

    def _submit(self) -> None:
        """Submit."""
        mode = str(self.query_one("#mode", Select).value)
        if mode in {"server_only", "server_update"} and not self.has_existing_config:
            self.query_one("#status", Static).update(
                "Bootstrap database URI missing. Switch to full setup mode."
            )
            return

        payload = SetupWizardResult(
            mode=mode,
            database_name=self.query_one("#database_name", Input).value.strip(),
            database_username=self.query_one("#database_username", Input).value.strip(),
            database_password=self.query_one("#database_password", Input).value,
            database_host=self.query_one("#database_host", Input).value.strip()
            or "localhost",
            database_port=self.query_one("#database_port", Input).value.strip()
            or "5432",
            server_name=self.query_one("#server_name", Input).value.strip(),
            server_description=self.query_one("#server_description", Input).value.strip(),
            server_welcome_message=self.query_one(
                "#server_welcome_message", Input
            ).value.strip(),
            owner_username=self.query_one("#owner_username", Input).value.strip(),
            owner_password=self.query_one("#owner_password", Input).value,
        )

        missing_server = [
            name
            for name, value in [
                ("server_name", payload.server_name),
                ("server_description", payload.server_description),
                ("server_welcome_message", payload.server_welcome_message),
            ]
            if not value
        ]
        if missing_server:
            self.query_one("#status", Static).update(
                f"Missing required server fields: {', '.join(missing_server)}"
            )
            return

        if mode == "full":
            missing_full = [
                name
                for name, value in [
                    ("database_name", payload.database_name),
                    ("database_username", payload.database_username),
                    ("database_password", payload.database_password),
                    ("owner_username", payload.owner_username),
                    ("owner_password", payload.owner_password),
                ]
                if not value
            ]
            if missing_full:
                self.query_one("#status", Static).update(
                    f"Missing required full setup fields: {', '.join(missing_full)}"
                )
                return

            if not payload.database_port.isdigit():
                self.query_one("#status", Static).update(
                    "database_port must be a valid integer."
                )
                return

        self.result = payload
        self.exit(payload)
