use std::env;
use std::fs::{self, File};
use std::io::{self};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::execute;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Terminal;

const BACKUP_DIR: &str = "/var/backups/firewall-manager";
const NFT_RULES_FILE: &str = "/etc/firewall-manager/nftables.rules";
const IPTABLES_RULES_FILE: &str = "/etc/firewall-manager/iptables.rules";
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "firewall_kit";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Nftables,
    Iptables,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Language {
    Es,
    En,
    ZhCn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActionId {
    Status,
    Init,
    ListPorts,
    AddPort,
    RemovePort,
    BackupAuto,
    BackupManual,
    Restore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PromptId {
    PreInitBackup,
    ConfirmInit,
    Port,
    Protocol,
    SourceOptional,
    CommentOptional,
    RuleNumber,
    BackupName,
    RestoreNumber,
    ConfirmRestore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UiLabel {
    Actions,
    Rules,
    Output,
    ValueLabel,
    DefaultLabel,
    PromptHelp,
    SelectAction,
    BackendSelected,
    DryRunMode,
    LanguageChanged,
    Backend,
    DryRun,
    Language,
    Keys,
    Focus,
    FocusActions,
    FocusRules,
    Root,
    NotRoot,
    NoAction,
    InputTitle,
    ErrorExec,
    ErrorCreateDir,
    InvalidEmpty,
    InvalidPort,
    InvalidNumber,
    InvalidYesNo,
    InvalidCidr,
    InvalidProto,
    NeedRoot,
    BackendUnavailable,
    TableMissing,
    BackupsAvailable,
    NoBackups,
    InvalidSelection,
    OperationCancelled,
    SnapshotSaved,
    SnapshotFailed,
    BackupCreated,
    BackupFailed,
    RestoreComplete,
    RestoreFailed,
    RuleAdded,
    RuleRemoved,
    NoRules,
    RuleDeleted,
}

impl Backend {
    fn label(self) -> &'static str {
        match self {
            Backend::Nftables => "nftables",
            Backend::Iptables => "iptables",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Validation {
    Any,
    NonEmpty,
    Port,
    YesNo,
    CidrOptional,
    Number,
    Proto,
}

struct PromptSpec {
    id: PromptId,
    default: Option<&'static str>,
    validation: Validation,
}

struct Action {
    id: ActionId,
    prompts: Vec<PromptSpec>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Focus {
    Actions,
    Rules,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    Prompting,
}

struct PromptState {
    action_index: usize,
    step_index: usize,
    values: Vec<String>,
    input: String,
    error: Option<String>,
}

struct App {
    actions: Vec<Action>,
    list_state: ListState,
    backend: Backend,
    language: Language,
    dry_run: bool,
    output: Vec<String>,
    output_scroll: u16,
    output_view_height: u16,
    auto_scroll: bool,
    last_scroll: Instant,
    last_manual_scroll: Option<Instant>,
    last_cmd: Option<String>,
    mode: Mode,
    prompt_state: Option<PromptState>,
    restore_candidates: Vec<PathBuf>,
    rules: Vec<RuleEntry>,
    rules_state: ListState,
    focus: Focus,
    is_root: bool,
    should_quit: bool,
}

struct RuleEntry {
    id: String,
    summary: String,
}

fn main() -> io::Result<()> {
    let mut app = App::new();
    if app.is_root && backend_available(app.backend) {
        app.refresh_rules(false);
    }
    let mut terminal = setup_terminal()?;
    let result = run_app(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    if let Err(err) = result {
        eprintln!("Error: {err}");
    }
    Ok(())
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> io::Result<()> {
    while !app.should_quit {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(150))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match app.mode {
                    Mode::Normal => handle_normal_keys(app, key.code),
                    Mode::Prompting => handle_prompt_keys(app, key.code),
                }
            }
        }
        app.auto_scroll_tick();
    }
    Ok(())
}

fn handle_normal_keys(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => match app.focus {
            Focus::Actions => app.select_prev(),
            Focus::Rules => app.select_prev_rule(),
        },
        KeyCode::Down | KeyCode::Char('j') => match app.focus {
            Focus::Actions => app.select_next(),
            Focus::Rules => app.select_next_rule(),
        },
        KeyCode::Left | KeyCode::Char('h') => {
            if app.focus == Focus::Actions {
                app.select_prev();
            }
        }
        KeyCode::Right => {
            if app.focus == Focus::Actions {
                app.select_next();
            }
        }
        KeyCode::PageUp => app.scroll_output(-5),
        KeyCode::PageDown => app.scroll_output(5),
        KeyCode::Char('b') => app.toggle_backend(),
        KeyCode::Char('d') => app.toggle_dry_run(),
        KeyCode::Char('l') => app.toggle_language(),
        KeyCode::Char('t') | KeyCode::Tab => app.toggle_focus(),
        KeyCode::Char('r') => app.refresh_rules(true),
        KeyCode::Char('x') => {
            if app.focus == Focus::Rules {
                app.delete_selected_rule();
            }
        }
        KeyCode::Enter => {
            if app.focus == Focus::Actions {
                app.start_action();
            }
        }
        _ => {}
    }
}

fn handle_prompt_keys(app: &mut App, code: KeyCode) {
    let Some(state) = app.prompt_state.as_mut() else {
        app.mode = Mode::Normal;
        return;
    };

    match code {
        KeyCode::Esc => {
            app.mode = Mode::Normal;
            app.prompt_state = None;
        }
        KeyCode::Backspace => {
            state.input.pop();
        }
        KeyCode::Enter => {
            app.advance_prompt();
        }
        KeyCode::Char(c) => {
            state.input.push(c);
        }
        _ => {}
    }
}

impl App {
    fn new() -> Self {
        let actions = build_actions();
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        let backend = detect_backend();
        let language = detect_language();
        let is_root = unsafe { libc::geteuid() == 0 };

        Self {
            actions,
            list_state,
            backend,
            language,
            dry_run: false,
            output: vec![ui_label(language, UiLabel::SelectAction).to_string()],
            output_scroll: 0,
            output_view_height: 0,
            auto_scroll: true,
            last_scroll: Instant::now(),
            last_manual_scroll: None,
            last_cmd: None,
            mode: Mode::Normal,
            prompt_state: None,
            restore_candidates: Vec::new(),
            rules: Vec::new(),
            rules_state: ListState::default(),
            focus: Focus::Rules,
            is_root,
            should_quit: false,
        }
    }

    fn select_prev(&mut self) {
        let idx = self.list_state.selected().unwrap_or(0);
        let new_idx = if idx == 0 {
            self.actions.len().saturating_sub(1)
        } else {
            idx - 1
        };
        self.list_state.select(Some(new_idx));
    }

    fn select_next(&mut self) {
        let idx = self.list_state.selected().unwrap_or(0);
        let new_idx = if idx + 1 >= self.actions.len() {
            0
        } else {
            idx + 1
        };
        self.list_state.select(Some(new_idx));
    }

    fn selected_action(&self) -> Option<&Action> {
        self.list_state
            .selected()
            .and_then(|idx| self.actions.get(idx))
    }

    fn select_prev_rule(&mut self) {
        if self.rules.is_empty() {
            return;
        }
        let idx = self.rules_state.selected().unwrap_or(0);
        let new_idx = if idx == 0 {
            self.rules.len().saturating_sub(1)
        } else {
            idx - 1
        };
        self.rules_state.select(Some(new_idx));
    }

    fn select_next_rule(&mut self) {
        if self.rules.is_empty() {
            return;
        }
        let idx = self.rules_state.selected().unwrap_or(0);
        let new_idx = if idx + 1 >= self.rules.len() {
            0
        } else {
            idx + 1
        };
        self.rules_state.select(Some(new_idx));
    }

    fn selected_rule(&self) -> Option<&RuleEntry> {
        self.rules_state
            .selected()
            .and_then(|idx| self.rules.get(idx))
    }

    fn scroll_output(&mut self, delta: i16) {
        let next = if delta.is_negative() {
            self.output_scroll.saturating_sub(delta.unsigned_abs() as u16)
        } else {
            self.output_scroll.saturating_add(delta as u16)
        };
        let max_scroll = self.max_output_scroll();
        self.output_scroll = next.min(max_scroll);
        self.last_manual_scroll = Some(Instant::now());
    }

    fn toggle_backend(&mut self) {
        self.backend = match self.backend {
            Backend::Nftables => Backend::Iptables,
            Backend::Iptables => Backend::Nftables,
        };
        self.rules.clear();
        self.rules_state.select(None);
        self.push_notice(format!(
            "{}: {}",
            ui_label(self.language, UiLabel::BackendSelected),
            self.backend.label()
        ));
    }

    fn toggle_dry_run(&mut self) {
        self.dry_run = !self.dry_run;
        self.push_notice(format!(
            "{}: {}",
            ui_label(self.language, UiLabel::DryRunMode),
            dry_run_state(self.language, self.dry_run)
        ));
    }

    fn toggle_language(&mut self) {
        self.language = match self.language {
            Language::Es => Language::En,
            Language::En => Language::ZhCn,
            Language::ZhCn => Language::Es,
        };
        self.push_notice(format!(
            "{}: {}",
            ui_label(self.language, UiLabel::LanguageChanged),
            language_name(self.language)
        ));
    }

    fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Actions => Focus::Rules,
            Focus::Rules => Focus::Actions,
        };
        self.output_scroll = 0;
        self.output.clear();
        self.output.push(format!(
            "{}: {}",
            ui_label(self.language, UiLabel::Focus),
            match self.focus {
                Focus::Actions => ui_label(self.language, UiLabel::FocusActions),
                Focus::Rules => ui_label(self.language, UiLabel::FocusRules),
            }
        ));
    }

    fn max_output_scroll(&self) -> u16 {
        if self.output_view_height == 0 {
            return 0;
        }
        let total = self.output.len() as u16;
        total.saturating_sub(self.output_view_height)
    }

    fn auto_scroll_tick(&mut self) {
        if self.mode != Mode::Normal || !self.auto_scroll {
            return;
        }
        let max_scroll = self.max_output_scroll();
        if max_scroll == 0 {
            self.output_scroll = 0;
            return;
        }
        if let Some(last_manual) = self.last_manual_scroll {
            if last_manual.elapsed() < Duration::from_secs(2) {
                return;
            }
        }
        if self.last_scroll.elapsed() >= Duration::from_millis(400) {
            self.output_scroll = if self.output_scroll >= max_scroll {
                0
            } else {
                self.output_scroll + 1
            };
            self.last_scroll = Instant::now();
        }
    }

    fn start_action(&mut self) {
        let idx = self.list_state.selected().unwrap_or(0);
        if idx >= self.actions.len() {
            return;
        }

        let action_id = self.actions[idx].id;
        if action_id == ActionId::Restore && !self.prepare_restore_list() {
            return;
        }
        let action = &self.actions[idx];
        let prompts = action_prompts(action);

        if prompts.is_empty() {
            self.run_action(idx, Vec::new());
            return;
        }

        let default_input = initial_input(self.language, &prompts[0]);
        self.prompt_state = Some(PromptState {
            action_index: idx,
            step_index: 0,
            values: Vec::new(),
            input: default_input,
            error: None,
        });
        self.mode = Mode::Prompting;
    }

    fn advance_prompt(&mut self) {
        let Some(state) = self.prompt_state.as_mut() else {
            self.mode = Mode::Normal;
            return;
        };
        let action = &self.actions[state.action_index];
        let prompts = action_prompts(action);
        if state.step_index >= prompts.len() {
            self.mode = Mode::Normal;
            self.prompt_state = None;
            return;
        }

        let spec = &prompts[state.step_index];
        match validate_input(self.language, &state.input, spec.default, spec.validation) {
            Ok(value) => {
                state.values.push(value);
                state.step_index += 1;
                state.error = None;
                if state.step_index >= prompts.len() {
                    let values = state.values.clone();
                    let idx = state.action_index;
                    self.mode = Mode::Normal;
                    self.prompt_state = None;
                    self.run_action(idx, values);
                } else {
                    state.input = initial_input(self.language, &prompts[state.step_index]);
                }
            }
            Err(err) => {
                state.error = Some(err);
            }
        }
    }

    fn run_action(&mut self, action_index: usize, prompt_values: Vec<String>) {
        let action_id = self.actions[action_index].id;
        self.last_cmd = Some(action_title(self.language, action_id).to_string());
        self.output_scroll = 0;

        if action_id == ActionId::Restore && !self.output.is_empty() {
            self.output.push(String::new());
        } else {
            self.output.clear();
            self.output
                .push(action_desc(self.language, action_id).to_string());
            self.output.push(String::new());
        }

        if !self.ensure_ready() {
            return;
        }

        self.execute_action(action_id, &prompt_values);
    }

    fn execute_action(&mut self, action_id: ActionId, prompt_values: &[String]) {
        match action_id {
            ActionId::Status => self.action_status(),
            ActionId::Init => self.action_init(prompt_values),
            ActionId::ListPorts => self.action_list_ports(),
            ActionId::AddPort => self.action_add_port(prompt_values),
            ActionId::RemovePort => self.action_remove_port(prompt_values),
            ActionId::BackupAuto => self.action_backup_auto(),
            ActionId::BackupManual => self.action_backup_manual(prompt_values),
            ActionId::Restore => self.action_restore(prompt_values),
        }
    }

    fn ensure_ready(&mut self) -> bool {
        if !self.is_root {
            self.output
                .push(ui_label(self.language, UiLabel::NeedRoot).to_string());
            return false;
        }

        if !backend_available(self.backend) {
            self.output.push(format!(
                "{}: {}",
                ui_label(self.language, UiLabel::BackendUnavailable),
                self.backend.label()
            ));
            return false;
        }

        true
    }

    fn prepare_restore_list(&mut self) -> bool {
        self.restore_candidates = list_backups();
        self.last_cmd = Some(action_title(self.language, ActionId::Restore).to_string());
        self.output_scroll = 0;
        self.output.clear();

        if self.restore_candidates.is_empty() {
            self.output
                .push(ui_label(self.language, UiLabel::NoBackups).to_string());
            return false;
        }

        self.output.push(format!(
            "{} {}:",
            ui_label(self.language, UiLabel::BackupsAvailable),
            BACKUP_DIR
        ));
        for (idx, path) in self.restore_candidates.iter().enumerate() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("-");
            self.output.push(format!("[{}] {}", idx + 1, name));
        }
        true
    }

    fn action_status(&mut self) {
        match self.backend {
            Backend::Nftables => {
                self.run_command("nft", &args_from(&["list", "ruleset"]));
            }
            Backend::Iptables => {
                self.run_command("iptables", &args_from(&["-L", "-n", "-v"]));
            }
        }
    }

    fn action_init(&mut self, prompt_values: &[String]) {
        let pre_backup = prompt_values
            .get(0)
            .map(|value| value == "si")
            .unwrap_or(false);
        let confirm = prompt_values
            .get(1)
            .map(|value| value == "si")
            .unwrap_or(false);

        if pre_backup {
            self.backup_auto_internal("pre_init");
        }

        if !confirm {
            self.output
                .push(ui_label(self.language, UiLabel::OperationCancelled).to_string());
            return;
        }

        for line in init_info_lines(self.language) {
            self.output.push(line.to_string());
        }
        self.output.push(String::new());

        match self.backend {
            Backend::Nftables => {
                if self.nft_table_exists() {
                    if !self.run_command(
                        "nft",
                        &args_from(&["delete", "table", NFT_FAMILY, NFT_TABLE]),
                    ) {
                        return;
                    }
                }

                if !self.run_command(
                    "nft",
                    &args_from(&["add", "table", NFT_FAMILY, NFT_TABLE]),
                ) {
                    return;
                }

                if !self.run_command(
                    "nft",
                    &args_from(&[
                        "add",
                        "chain",
                        NFT_FAMILY,
                        NFT_TABLE,
                        "input",
                        "{ type filter hook input priority 0; policy drop; }",
                    ]),
                ) {
                    return;
                }

                if !self.run_command(
                    "nft",
                    &args_from(&[
                        "add",
                        "chain",
                        NFT_FAMILY,
                        NFT_TABLE,
                        "forward",
                        "{ type filter hook forward priority 0; policy drop; }",
                    ]),
                ) {
                    return;
                }

                if !self.run_command(
                    "nft",
                    &args_from(&[
                        "add",
                        "chain",
                        NFT_FAMILY,
                        NFT_TABLE,
                        "output",
                        "{ type filter hook output priority 0; policy accept; }",
                    ]),
                ) {
                    return;
                }

                if !self.run_command(
                    "nft",
                    &args_from(&[
                        "add",
                        "rule",
                        NFT_FAMILY,
                        NFT_TABLE,
                        "input",
                        "ct",
                        "state",
                        "established,related",
                        "accept",
                    ]),
                ) {
                    return;
                }

                self.run_command(
                    "nft",
                    &args_from(&[
                        "add",
                        "rule",
                        NFT_FAMILY,
                        NFT_TABLE,
                        "input",
                        "iifname",
                        "lo",
                        "accept",
                    ]),
                );
            }
            Backend::Iptables => {
                if !self.run_command("iptables", &args_from(&["-F"])) {
                    return;
                }
                if !self.run_command("iptables", &args_from(&["-X"])) {
                    return;
                }
                if !self.run_command(
                    "iptables",
                    &args_from(&["-P", "INPUT", "DROP"]),
                ) {
                    return;
                }
                if !self.run_command(
                    "iptables",
                    &args_from(&["-P", "FORWARD", "DROP"]),
                ) {
                    return;
                }
                if !self.run_command(
                    "iptables",
                    &args_from(&["-P", "OUTPUT", "ACCEPT"]),
                ) {
                    return;
                }
                if !self.run_command(
                    "iptables",
                    &args_from(&[
                        "-A",
                        "INPUT",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "ESTABLISHED,RELATED",
                        "-j",
                        "ACCEPT",
                    ]),
                ) {
                    return;
                }
                self.run_command("iptables", &args_from(&["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"]));
            }
        }

        self.save_rules_snapshot();
        self.refresh_rules(false);
    }

    fn action_list_ports(&mut self) {
        self.focus = Focus::Rules;
        self.refresh_rules(true);
    }

    fn action_add_port(&mut self, prompt_values: &[String]) {
        let port = prompt_values.get(0).cloned().unwrap_or_default();
        let proto = prompt_values.get(1).cloned().unwrap_or_else(|| "tcp".to_string());
        let src = prompt_values.get(2).cloned().unwrap_or_default();
        let comment = prompt_values.get(3).cloned().unwrap_or_default();

        let protos: Vec<&str> = if proto == "both" {
            vec!["tcp", "udp"]
        } else {
            vec![proto.as_str()]
        };

        match self.backend {
            Backend::Nftables => {
                if !self.nft_table_exists() {
                    self.output
                        .push(ui_label(self.language, UiLabel::TableMissing).to_string());
                    return;
                }
                for p in protos {
                    let mut args = vec![
                        "add".to_string(),
                        "rule".to_string(),
                        NFT_FAMILY.to_string(),
                        NFT_TABLE.to_string(),
                        "input".to_string(),
                    ];
                    if !src.is_empty() {
                        args.push("ip".to_string());
                        args.push("saddr".to_string());
                        args.push(src.clone());
                    }
                    args.push(p.to_string());
                    args.push("dport".to_string());
                    args.push(port.clone());
                    args.push("accept".to_string());
                    if !comment.is_empty() {
                        args.push("comment".to_string());
                        args.push(comment.clone());
                    }
                    if !self.run_command("nft", &args) {
                        return;
                    }
                }
            }
            Backend::Iptables => {
                for p in protos {
                    let mut args = vec![
                        "-A".to_string(),
                        "INPUT".to_string(),
                    ];
                    if !src.is_empty() {
                        args.push("-s".to_string());
                        args.push(src.clone());
                    }
                    args.push("-p".to_string());
                    args.push(p.to_string());
                    args.push("--dport".to_string());
                    args.push(port.clone());
                    args.push("-j".to_string());
                    args.push("ACCEPT".to_string());
                    if !comment.is_empty() {
                        args.push("-m".to_string());
                        args.push("comment".to_string());
                        args.push("--comment".to_string());
                        args.push(comment.clone());
                    }
                    if !self.run_command("iptables", &args) {
                        return;
                    }
                }
            }
        }

        self.save_rules_snapshot();
        self.push_action_result(UiLabel::RuleAdded, None);
        self.refresh_rules(false);
    }

    fn action_remove_port(&mut self, prompt_values: &[String]) {
        let number = prompt_values.get(0).cloned().unwrap_or_default();

        match self.backend {
            Backend::Nftables => {
                if !self.nft_table_exists() {
                    self.output
                        .push(ui_label(self.language, UiLabel::TableMissing).to_string());
                    return;
                }
                if !self.run_command(
                    "nft",
                    &args_from(&[
                        "delete",
                        "rule",
                        NFT_FAMILY,
                        NFT_TABLE,
                        "input",
                        "handle",
                        number.as_str(),
                    ]),
                ) {
                    return;
                }
            }
            Backend::Iptables => {
                if !self.run_command(
                    "iptables",
                    &args_from(&["-D", "INPUT", number.as_str()]),
                ) {
                    return;
                }
            }
        }

        self.save_rules_snapshot();
        self.push_action_result(UiLabel::RuleRemoved, None);
        self.refresh_rules(false);
    }

    fn action_backup_auto(&mut self) {
        self.backup_auto_internal("manual_auto");
    }

    fn action_backup_manual(&mut self, prompt_values: &[String]) {
        let mut name = prompt_values.get(0).cloned().unwrap_or_default();
        if !name.ends_with(".tar.gz") {
            name.push_str(".tar.gz");
        }
        self.backup_named(&name);
    }

    fn action_restore(&mut self, prompt_values: &[String]) {
        let selection = prompt_values
            .get(0)
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let confirm = prompt_values
            .get(1)
            .map(|value| value == "si")
            .unwrap_or(false);

        if !confirm {
            self.output
                .push(ui_label(self.language, UiLabel::OperationCancelled).to_string());
            return;
        }

        if self.restore_candidates.is_empty() {
            self.restore_candidates = list_backups();
        }

        if selection == 0 || selection > self.restore_candidates.len() {
            self.output
                .push(ui_label(self.language, UiLabel::InvalidSelection).to_string());
            return;
        }

        let chosen = self.restore_candidates[selection - 1].clone();
        if self.extract_backup(&chosen) {
            self.restore_rules_snapshot();
            self.push_action_result(UiLabel::RestoreComplete, None);
            self.refresh_rules(false);
        } else {
            self.output
                .push(ui_label(self.language, UiLabel::RestoreFailed).to_string());
        }
    }

    fn delete_selected_rule(&mut self) {
        self.last_cmd = Some(ui_label(self.language, UiLabel::RuleDeleted).to_string());
        self.output_scroll = 0;
        self.output.clear();

        let Some(rule) = self.selected_rule() else {
            self.output
                .push(ui_label(self.language, UiLabel::NoRules).to_string());
            return;
        };
        let rule_id = rule.id.clone();
        let rule_summary = rule.summary.clone();

        self.output.push(format!(
            "{}: [{}] {}",
            ui_label(self.language, UiLabel::RuleDeleted),
            rule_id,
            rule_summary
        ));
        self.output.push(String::new());

        if !self.ensure_ready() {
            return;
        }

        match self.backend {
            Backend::Nftables => {
                if !self.run_command(
                    "nft",
                    &args_from(&[
                        "delete",
                        "rule",
                        NFT_FAMILY,
                        NFT_TABLE,
                        "input",
                        "handle",
                        rule_id.as_str(),
                    ]),
                ) {
                    return;
                }
            }
            Backend::Iptables => {
                if !self.run_command(
                    "iptables",
                    &args_from(&["-D", "INPUT", rule_id.as_str()]),
                ) {
                    return;
                }
            }
        }

        self.save_rules_snapshot();
        self.refresh_rules(false);
    }

    fn refresh_rules(&mut self, log_output: bool) {
        if log_output {
            self.output.clear();
            self.output_scroll = 0;
            self.last_cmd = Some(action_title(self.language, ActionId::ListPorts).to_string());
        }
        if !self.ensure_ready() {
            return;
        }

        let output = match self.backend {
            Backend::Nftables => {
                if !self.nft_table_exists() {
                    self.output
                        .push(ui_label(self.language, UiLabel::TableMissing).to_string());
                    self.rules.clear();
                    self.rules_state.select(None);
                    return;
                }
                let args = args_from(&["list", "chain", NFT_FAMILY, NFT_TABLE, "input", "-a"]);
                self.capture_command("nft", &args, log_output, true)
            }
            Backend::Iptables => {
                let args = args_from(&["-L", "INPUT", "-n", "--line-numbers"]);
                self.capture_command("iptables", &args, log_output, true)
            }
        };

        if let Some(output) = output {
            if !output.status.success() {
                self.rules.clear();
                self.rules_state.select(None);
                return;
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            self.rules = match self.backend {
                Backend::Nftables => parse_nft_rules(&stdout),
                Backend::Iptables => parse_iptables_rules(&stdout),
            };
        } else if log_output {
            self.output
                .push(ui_label(self.language, UiLabel::NoRules).to_string());
            self.rules.clear();
        }

        if self.rules.is_empty() {
            self.rules_state.select(None);
        } else {
            let idx = self.rules_state.selected().unwrap_or(0);
            let new_idx = idx.min(self.rules.len().saturating_sub(1));
            self.rules_state.select(Some(new_idx));
        }
    }

    fn backup_auto_internal(&mut self, suffix: &str) {
        let name = format!(
            "firewall_backup_{}_{}.tar.gz",
            suffix,
            timestamp()
        );
        self.backup_named(&name);
    }

    fn backup_named(&mut self, name: &str) {
        let backup_dir = Path::new(BACKUP_DIR);
        if !self.ensure_dir(backup_dir) {
            return;
        }

        let rules_file = self.rules_file();
        let backup_path = backup_dir.join(name);
        self.save_rules_snapshot();

        let backup_arg = backup_path.display().to_string();
        let args = vec![
            "czf".to_string(),
            backup_arg.clone(),
            "--ignore-failed-read".to_string(),
            rules_file.to_string(),
        ];
        if self.run_command("tar", &args) {
            self.push_action_result(UiLabel::BackupCreated, Some(backup_arg));
        } else {
            self.output
                .push(ui_label(self.language, UiLabel::BackupFailed).to_string());
        }
    }

    fn extract_backup(&mut self, path: &Path) -> bool {
        let path_arg = path.display().to_string();
        let args = vec![
            "xzf".to_string(),
            path_arg.clone(),
            "-C".to_string(),
            "/".to_string(),
        ];
        self.run_command("tar", &args)
    }

    fn restore_rules_snapshot(&mut self) {
        let rules_path = Path::new(self.rules_file());
        if !rules_path.exists() {
            self.output
                .push(ui_label(self.language, UiLabel::SnapshotFailed).to_string());
            return;
        }

        match self.backend {
            Backend::Nftables => {
                if self.nft_table_exists() {
                    self.run_command(
                        "nft",
                        &args_from(&["delete", "table", NFT_FAMILY, NFT_TABLE]),
                    );
                }
                let args = vec!["-f".to_string(), rules_path.display().to_string()];
                if !self.run_command("nft", &args) {
                    self.output
                        .push(ui_label(self.language, UiLabel::RestoreFailed).to_string());
                }
            }
            Backend::Iptables => {
                let cmd_line = format!("iptables-restore < {}", rules_path.display());
                if self.dry_run {
                    self.output.push(format!("DRY-RUN: $ {cmd_line}"));
                    return;
                }
                self.output.push(format!("$ {cmd_line}"));
                let file = match File::open(rules_path) {
                    Ok(file) => file,
                    Err(err) => {
                        self.output.push(format!(
                            "{}: {err}",
                            ui_label(self.language, UiLabel::RestoreFailed)
                        ));
                        return;
                    }
                };
                match Command::new("iptables-restore")
                    .stdin(Stdio::from(file))
                    .output()
                {
                    Ok(output) => {
                        if !output.status.success() {
                            self.output
                                .push(ui_label(self.language, UiLabel::RestoreFailed).to_string());
                            append_process_output(&mut self.output, &output);
                        }
                    }
                    Err(err) => {
                        self.output.push(format!(
                            "{}: {err}",
                            ui_label(self.language, UiLabel::RestoreFailed)
                        ));
                    }
                }
            }
        }
    }

    fn save_rules_snapshot(&mut self) -> bool {
        let rules_path = Path::new(self.rules_file());
        if let Some(parent) = rules_path.parent() {
            if !self.ensure_dir(parent) {
                return false;
            }
        }

        if self.dry_run {
            self.output.push(format!(
                "DRY-RUN: {}: {}",
                ui_label(self.language, UiLabel::SnapshotSaved),
                rules_path.display()
            ));
            return true;
        }

        let output = match self.backend {
            Backend::Nftables => {
                if !self.nft_table_exists() {
                    self.output
                        .push(ui_label(self.language, UiLabel::TableMissing).to_string());
                    return false;
                }
                Command::new("nft")
                    .args(&[
                        "list",
                        "table",
                        NFT_FAMILY,
                        NFT_TABLE,
                    ])
                    .output()
            }
            Backend::Iptables => Command::new("iptables-save").output(),
        };

        match output {
            Ok(output) => {
                if !output.status.success() {
                    self.output
                        .push(ui_label(self.language, UiLabel::SnapshotFailed).to_string());
                    append_process_output(&mut self.output, &output);
                    return false;
                }
                if let Err(err) = fs::write(rules_path, output.stdout) {
                    self.output.push(format!(
                        "{}: {err}",
                        ui_label(self.language, UiLabel::SnapshotFailed)
                    ));
                    return false;
                }
                self.push_action_result(
                    UiLabel::SnapshotSaved,
                    Some(rules_path.display().to_string()),
                );
                true
            }
            Err(err) => {
                self.output.push(format!(
                    "{}: {err}",
                    ui_label(self.language, UiLabel::SnapshotFailed)
                ));
                false
            }
        }
    }

    fn rules_file(&self) -> &'static str {
        match self.backend {
            Backend::Nftables => NFT_RULES_FILE,
            Backend::Iptables => IPTABLES_RULES_FILE,
        }
    }

    fn ensure_dir(&mut self, path: &Path) -> bool {
        if self.dry_run {
            self.output
                .push(format!("DRY-RUN: $ mkdir -p {}", path.display()));
            return true;
        }
        if let Err(err) = fs::create_dir_all(path) {
            self.output.push(format!(
                "{}: {err}",
                ui_label(self.language, UiLabel::ErrorCreateDir)
            ));
            return false;
        }
        true
    }

    fn run_command(&mut self, program: &str, args: &[String]) -> bool {
        let cmd_line = format!("$ {}", format_command(program, args));
        if self.dry_run {
            self.output.push(format!("DRY-RUN: {cmd_line}"));
            return true;
        }
        self.output.push(cmd_line);
        match Command::new(program).args(args).output() {
            Ok(output) => {
                append_process_output(&mut self.output, &output);
                output.status.success()
            }
            Err(err) => {
                self.output.push(format!(
                    "{}: {err}",
                    ui_label(self.language, UiLabel::ErrorExec)
                ));
                false
            }
        }
    }

    fn capture_command(
        &mut self,
        program: &str,
        args: &[String],
        log_output: bool,
        allow_in_dry_run: bool,
    ) -> Option<std::process::Output> {
        let cmd_line = format!("$ {}", format_command(program, args));
        if self.dry_run && !allow_in_dry_run {
            if log_output {
                self.output.push(format!("DRY-RUN: {cmd_line}"));
            }
            return None;
        }

        if log_output {
            self.output.push(cmd_line);
        }

        match Command::new(program).args(args).output() {
            Ok(output) => {
                if log_output {
                    append_process_output(&mut self.output, &output);
                }
                Some(output)
            }
            Err(err) => {
                self.output.push(format!(
                    "{}: {err}",
                    ui_label(self.language, UiLabel::ErrorExec)
                ));
                None
            }
        }
    }

    fn nft_table_exists(&self) -> bool {
        if self.dry_run {
            return true;
        }
        Command::new("nft")
            .args(&["list", "table", NFT_FAMILY, NFT_TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn push_action_result(&mut self, label: UiLabel, extra: Option<String>) {
        let base = ui_label(self.language, label);
        let message = if let Some(extra) = extra {
            format!("{base}: {extra}")
        } else {
            base.to_string()
        };
        if self.dry_run {
            self.output.push(format!("DRY-RUN: {message}"));
        } else {
            self.output.push(message);
        }
    }

    fn push_notice(&mut self, message: String) {
        self.output.clear();
        self.output_scroll = 0;
        self.output.push(message);
    }
}

fn build_actions() -> Vec<Action> {
    vec![
        Action {
            id: ActionId::Status,
            prompts: vec![],
        },
        Action {
            id: ActionId::Init,
            prompts: vec![
                PromptSpec {
                    id: PromptId::PreInitBackup,
                    default: Some("si"),
                    validation: Validation::YesNo,
                },
                PromptSpec {
                    id: PromptId::ConfirmInit,
                    default: Some("no"),
                    validation: Validation::YesNo,
                },
            ],
        },
        Action {
            id: ActionId::ListPorts,
            prompts: vec![],
        },
        Action {
            id: ActionId::AddPort,
            prompts: vec![
                PromptSpec {
                    id: PromptId::Port,
                    default: None,
                    validation: Validation::Port,
                },
                PromptSpec {
                    id: PromptId::Protocol,
                    default: Some("tcp"),
                    validation: Validation::Proto,
                },
                PromptSpec {
                    id: PromptId::SourceOptional,
                    default: None,
                    validation: Validation::CidrOptional,
                },
                PromptSpec {
                    id: PromptId::CommentOptional,
                    default: None,
                    validation: Validation::Any,
                },
            ],
        },
        Action {
            id: ActionId::RemovePort,
            prompts: vec![PromptSpec {
                id: PromptId::RuleNumber,
                default: None,
                validation: Validation::Number,
            }],
        },
        Action {
            id: ActionId::BackupAuto,
            prompts: vec![],
        },
        Action {
            id: ActionId::BackupManual,
            prompts: vec![PromptSpec {
                id: PromptId::BackupName,
                default: None,
                validation: Validation::NonEmpty,
            }],
        },
        Action {
            id: ActionId::Restore,
            prompts: vec![
                PromptSpec {
                    id: PromptId::RestoreNumber,
                    default: None,
                    validation: Validation::Number,
                },
                PromptSpec {
                    id: PromptId::ConfirmRestore,
                    default: Some("no"),
                    validation: Validation::YesNo,
                },
            ],
        },
    ]
}

fn action_prompts(action: &Action) -> &[PromptSpec] {
    &action.prompts
}

fn action_title(language: Language, id: ActionId) -> &'static str {
    match language {
        Language::Es => match id {
            ActionId::Status => "Estado / reglas",
            ActionId::Init => "Inicializar firewall",
            ActionId::ListPorts => "Listar reglas de entrada",
            ActionId::AddPort => "Anadir puerto permitido",
            ActionId::RemovePort => "Eliminar regla",
            ActionId::BackupAuto => "Backup automatico",
            ActionId::BackupManual => "Backup manual",
            ActionId::Restore => "Restaurar backup",
        },
        Language::En => match id {
            ActionId::Status => "Status / rules",
            ActionId::Init => "Initialize firewall",
            ActionId::ListPorts => "List inbound rules",
            ActionId::AddPort => "Add allowed port",
            ActionId::RemovePort => "Remove rule",
            ActionId::BackupAuto => "Automatic backup",
            ActionId::BackupManual => "Manual backup",
            ActionId::Restore => "Restore backup",
        },
        Language::ZhCn => match id {
            ActionId::Status => "状态 / 规则",
            ActionId::Init => "初始化防火墙",
            ActionId::ListPorts => "列出入站规则",
            ActionId::AddPort => "添加允许端口",
            ActionId::RemovePort => "删除规则",
            ActionId::BackupAuto => "自动备份",
            ActionId::BackupManual => "手动备份",
            ActionId::Restore => "恢复备份",
        },
    }
}

fn action_desc(language: Language, id: ActionId) -> &'static str {
    match language {
        Language::Es => match id {
            ActionId::Status => "Muestra el estado actual del firewall",
            ActionId::Init => "Reinicia la configuracion con politica segura",
            ActionId::ListPorts => "Lista reglas de entrada en INPUT",
            ActionId::AddPort => "Permite un puerto (tcp/udp/both)",
            ActionId::RemovePort => "Elimina regla por numero/handle",
            ActionId::BackupAuto => "Crea backup rapido",
            ActionId::BackupManual => "Crea backup con nombre personalizado",
            ActionId::Restore => "Restaura un backup disponible",
        },
        Language::En => match id {
            ActionId::Status => "Show current firewall status",
            ActionId::Init => "Reset firewall with safe policy",
            ActionId::ListPorts => "List INPUT chain rules",
            ActionId::AddPort => "Allow a port (tcp/udp/both)",
            ActionId::RemovePort => "Remove rule by number/handle",
            ActionId::BackupAuto => "Create quick backup",
            ActionId::BackupManual => "Create named backup",
            ActionId::Restore => "Restore an available backup",
        },
        Language::ZhCn => match id {
            ActionId::Status => "显示当前防火墙状态",
            ActionId::Init => "以安全策略重置防火墙",
            ActionId::ListPorts => "列出 INPUT 规则",
            ActionId::AddPort => "允许端口 (tcp/udp/both)",
            ActionId::RemovePort => "按编号/handle 删除规则",
            ActionId::BackupAuto => "创建快速备份",
            ActionId::BackupManual => "创建命名备份",
            ActionId::Restore => "恢复可用备份",
        },
    }
}

fn init_info_lines(language: Language) -> [&'static str; 3] {
    match language {
        Language::Es => [
            "Esto aplicara politicas seguras.",
            "INPUT y FORWARD en DROP, OUTPUT en ACCEPT.",
            "Se permiten conexiones establecidas/relacionadas y loopback.",
        ],
        Language::En => [
            "This will apply safe policies.",
            "INPUT and FORWARD set to DROP, OUTPUT set to ACCEPT.",
            "Established/related connections and loopback are allowed.",
        ],
        Language::ZhCn => [
            "将应用安全策略。",
            "INPUT 和 FORWARD 设为 DROP，OUTPUT 设为 ACCEPT。",
            "允许已建立/关联连接与回环。",
        ],
    }
}

fn prompt_label(language: Language, id: PromptId) -> &'static str {
    match language {
        Language::Es => match id {
            PromptId::PreInitBackup => "Crear backup antes de inicializar? (si/no)",
            PromptId::ConfirmInit => "Confirmar reinicio del firewall? (si/no)",
            PromptId::Port => "Puerto (1-65535)",
            PromptId::Protocol => "Protocolo (tcp/udp/both)",
            PromptId::SourceOptional => "Origen (IP/CIDR) opcional",
            PromptId::CommentOptional => "Comentario (opcional)",
            PromptId::RuleNumber => "Numero de regla/handle",
            PromptId::BackupName => "Nombre del backup (sin espacios)",
            PromptId::RestoreNumber => "Numero del backup",
            PromptId::ConfirmRestore => "Confirmar restauracion? (si/no)",
        },
        Language::En => match id {
            PromptId::PreInitBackup => "Create backup before init? (yes/no)",
            PromptId::ConfirmInit => "Confirm firewall reset? (yes/no)",
            PromptId::Port => "Port (1-65535)",
            PromptId::Protocol => "Protocol (tcp/udp/both)",
            PromptId::SourceOptional => "Source (IP/CIDR) optional",
            PromptId::CommentOptional => "Comment (optional)",
            PromptId::RuleNumber => "Rule/handle number",
            PromptId::BackupName => "Backup name (no spaces)",
            PromptId::RestoreNumber => "Backup number",
            PromptId::ConfirmRestore => "Confirm restore? (yes/no)",
        },
        Language::ZhCn => match id {
            PromptId::PreInitBackup => "初始化前创建备份？(是/否)",
            PromptId::ConfirmInit => "确认重置防火墙？(是/否)",
            PromptId::Port => "端口 (1-65535)",
            PromptId::Protocol => "协议 (tcp/udp/both)",
            PromptId::SourceOptional => "来源 (IP/CIDR，可选)",
            PromptId::CommentOptional => "备注 (可选)",
            PromptId::RuleNumber => "规则/handle 编号",
            PromptId::BackupName => "备份名称 (无空格)",
            PromptId::RestoreNumber => "备份编号",
            PromptId::ConfirmRestore => "确认恢复？(是/否)",
        },
    }
}

fn ui_label(language: Language, label: UiLabel) -> &'static str {
    match language {
        Language::Es => match label {
            UiLabel::Actions => "Acciones",
            UiLabel::Rules => "Reglas",
            UiLabel::Output => "Salida",
            UiLabel::ValueLabel => "Valor: ",
            UiLabel::DefaultLabel => "Por defecto: ",
            UiLabel::PromptHelp => "Enter: confirmar | Esc: cancelar",
            UiLabel::SelectAction => "Selecciona una accion y pulsa ENTER.",
            UiLabel::BackendSelected => "Backend seleccionado",
            UiLabel::DryRunMode => "Modo DRY-RUN",
            UiLabel::LanguageChanged => "Idioma",
            UiLabel::Backend => "Backend",
            UiLabel::DryRun => "Dry-run",
            UiLabel::Language => "Idioma",
            UiLabel::Keys => "Teclas",
            UiLabel::Focus => "Foco",
            UiLabel::FocusActions => "Acciones",
            UiLabel::FocusRules => "Reglas",
            UiLabel::Root => "root",
            UiLabel::NotRoot => "no-root",
            UiLabel::NoAction => "Sin accion",
            UiLabel::InputTitle => "Entrada",
            UiLabel::ErrorExec => "Error al ejecutar",
            UiLabel::ErrorCreateDir => "No se pudo crear el directorio",
            UiLabel::InvalidEmpty => "El valor no puede estar vacio.",
            UiLabel::InvalidPort => "Puerto invalido.",
            UiLabel::InvalidNumber => "Numero invalido.",
            UiLabel::InvalidYesNo => "Responde si/no.",
            UiLabel::InvalidCidr => "CIDR invalido.",
            UiLabel::InvalidProto => "Protocolo invalido (tcp/udp/both).",
            UiLabel::NeedRoot => "Este programa debe ejecutarse como root.",
            UiLabel::BackendUnavailable => "Backend no disponible",
            UiLabel::TableMissing => "La tabla no existe. Inicializa el firewall primero.",
            UiLabel::BackupsAvailable => "Backups disponibles en",
            UiLabel::NoBackups => "No se encontraron backups.",
            UiLabel::InvalidSelection => "Seleccion no valida.",
            UiLabel::OperationCancelled => "Operacion cancelada.",
            UiLabel::SnapshotSaved => "Snapshot guardado",
            UiLabel::SnapshotFailed => "No se pudo guardar el snapshot.",
            UiLabel::BackupCreated => "Backup creado",
            UiLabel::BackupFailed => "Error al crear el backup.",
            UiLabel::RestoreComplete => "Restauracion completada.",
            UiLabel::RestoreFailed => "Error al restaurar el backup.",
            UiLabel::RuleAdded => "Regla agregada.",
            UiLabel::RuleRemoved => "Regla eliminada.",
            UiLabel::NoRules => "No hay reglas para mostrar.",
            UiLabel::RuleDeleted => "Regla eliminada",
        },
        Language::En => match label {
            UiLabel::Actions => "Actions",
            UiLabel::Rules => "Rules",
            UiLabel::Output => "Output",
            UiLabel::ValueLabel => "Value: ",
            UiLabel::DefaultLabel => "Default: ",
            UiLabel::PromptHelp => "Enter: confirm | Esc: cancel",
            UiLabel::SelectAction => "Select an action and press ENTER.",
            UiLabel::BackendSelected => "Backend selected",
            UiLabel::DryRunMode => "DRY-RUN mode",
            UiLabel::LanguageChanged => "Language",
            UiLabel::Backend => "Backend",
            UiLabel::DryRun => "Dry-run",
            UiLabel::Language => "Lang",
            UiLabel::Keys => "Keys",
            UiLabel::Focus => "Focus",
            UiLabel::FocusActions => "Actions",
            UiLabel::FocusRules => "Rules",
            UiLabel::Root => "root",
            UiLabel::NotRoot => "not-root",
            UiLabel::NoAction => "No action",
            UiLabel::InputTitle => "Input",
            UiLabel::ErrorExec => "Failed to run",
            UiLabel::ErrorCreateDir => "Failed to create directory",
            UiLabel::InvalidEmpty => "Value cannot be empty.",
            UiLabel::InvalidPort => "Invalid port.",
            UiLabel::InvalidNumber => "Invalid number.",
            UiLabel::InvalidYesNo => "Answer yes/no.",
            UiLabel::InvalidCidr => "Invalid CIDR.",
            UiLabel::InvalidProto => "Invalid protocol (tcp/udp/both).",
            UiLabel::NeedRoot => "This program must run as root.",
            UiLabel::BackendUnavailable => "Backend not available",
            UiLabel::TableMissing => "Table does not exist. Initialize the firewall first.",
            UiLabel::BackupsAvailable => "Backups available in",
            UiLabel::NoBackups => "No backups found.",
            UiLabel::InvalidSelection => "Invalid selection.",
            UiLabel::OperationCancelled => "Operation cancelled.",
            UiLabel::SnapshotSaved => "Snapshot saved",
            UiLabel::SnapshotFailed => "Failed to save snapshot.",
            UiLabel::BackupCreated => "Backup created",
            UiLabel::BackupFailed => "Failed to create backup.",
            UiLabel::RestoreComplete => "Restore completed.",
            UiLabel::RestoreFailed => "Failed to restore backup.",
            UiLabel::RuleAdded => "Rule added.",
            UiLabel::RuleRemoved => "Rule removed.",
            UiLabel::NoRules => "No rules to display.",
            UiLabel::RuleDeleted => "Rule deleted",
        },
        Language::ZhCn => match label {
            UiLabel::Actions => "操作",
            UiLabel::Rules => "规则",
            UiLabel::Output => "输出",
            UiLabel::ValueLabel => "值: ",
            UiLabel::DefaultLabel => "默认: ",
            UiLabel::PromptHelp => "Enter: 确认 | Esc: 取消",
            UiLabel::SelectAction => "选择一个操作并按 ENTER。",
            UiLabel::BackendSelected => "已选择后端",
            UiLabel::DryRunMode => "DRY-RUN 模式",
            UiLabel::LanguageChanged => "语言",
            UiLabel::Backend => "后端",
            UiLabel::DryRun => "Dry-run",
            UiLabel::Language => "语言",
            UiLabel::Keys => "按键",
            UiLabel::Focus => "焦点",
            UiLabel::FocusActions => "操作",
            UiLabel::FocusRules => "规则",
            UiLabel::Root => "root",
            UiLabel::NotRoot => "非root",
            UiLabel::NoAction => "无操作",
            UiLabel::InputTitle => "输入",
            UiLabel::ErrorExec => "执行失败",
            UiLabel::ErrorCreateDir => "无法创建目录",
            UiLabel::InvalidEmpty => "值不能为空。",
            UiLabel::InvalidPort => "端口无效。",
            UiLabel::InvalidNumber => "编号无效。",
            UiLabel::InvalidYesNo => "请回答是/否。",
            UiLabel::InvalidCidr => "CIDR 无效。",
            UiLabel::InvalidProto => "协议无效 (tcp/udp/both)。",
            UiLabel::NeedRoot => "此程序需要以 root 运行。",
            UiLabel::BackendUnavailable => "后端不可用",
            UiLabel::TableMissing => "表不存在，请先初始化防火墙。",
            UiLabel::BackupsAvailable => "可用备份位于",
            UiLabel::NoBackups => "未找到备份。",
            UiLabel::InvalidSelection => "选择无效。",
            UiLabel::OperationCancelled => "操作已取消。",
            UiLabel::SnapshotSaved => "快照已保存",
            UiLabel::SnapshotFailed => "无法保存快照。",
            UiLabel::BackupCreated => "备份已创建",
            UiLabel::BackupFailed => "创建备份失败。",
            UiLabel::RestoreComplete => "恢复完成。",
            UiLabel::RestoreFailed => "恢复备份失败。",
            UiLabel::RuleAdded => "规则已添加。",
            UiLabel::RuleRemoved => "规则已删除。",
            UiLabel::NoRules => "没有可显示的规则。",
            UiLabel::RuleDeleted => "规则已删除",
        },
    }
}

fn language_name(language: Language) -> &'static str {
    match language {
        Language::Es => "ES",
        Language::En => "EN",
        Language::ZhCn => "中文",
    }
}

fn dry_run_state(language: Language, enabled: bool) -> &'static str {
    match (language, enabled) {
        (Language::Es, true) => "activado",
        (Language::Es, false) => "desactivado",
        (Language::En, true) => "on",
        (Language::En, false) => "off",
        (Language::ZhCn, true) => "开",
        (Language::ZhCn, false) => "关",
    }
}

fn display_default(language: Language, validation: Validation, default: &str) -> String {
    if default.is_empty() {
        return String::new();
    }

    if validation == Validation::YesNo {
        let normalized = default.to_lowercase();
        if normalized == "si" {
            return match language {
                Language::Es => "si".to_string(),
                Language::En => "yes".to_string(),
                Language::ZhCn => "是".to_string(),
            };
        }
        if normalized == "no" {
            return match language {
                Language::Es => "no".to_string(),
                Language::En => "no".to_string(),
                Language::ZhCn => "否".to_string(),
            };
        }
    }

    default.to_string()
}

fn initial_input(language: Language, spec: &PromptSpec) -> String {
    let Some(default) = spec.default else {
        return String::new();
    };
    if spec.validation == Validation::YesNo && language != Language::Es {
        return String::new();
    }
    default.to_string()
}

fn parse_language(value: &str) -> Option<Language> {
    let trimmed = value.trim().to_lowercase();
    if trimmed.starts_with("es") {
        Some(Language::Es)
    } else if trimmed.starts_with("en") {
        Some(Language::En)
    } else if trimmed.starts_with("zh") {
        Some(Language::ZhCn)
    } else {
        None
    }
}

fn detect_language() -> Language {
    for key in ["FIREWALL_UI_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(value) = env::var(key) {
            if let Some(lang) = parse_language(&value) {
                return lang;
            }
        }
    }
    Language::Es
}

fn backend_available(backend: Backend) -> bool {
    match backend {
        Backend::Nftables => Command::new("nft").arg("--version").output().is_ok(),
        Backend::Iptables => Command::new("iptables").arg("-V").output().is_ok(),
    }
}

fn detect_backend() -> Backend {
    if backend_available(Backend::Nftables) {
        Backend::Nftables
    } else {
        Backend::Iptables
    }
}

fn args_from(args: &[&str]) -> Vec<String> {
    args.iter().map(|value| value.to_string()).collect()
}

fn format_command(program: &str, args: &[String]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(program.to_string());
    for arg in args {
        if arg.contains(' ') {
            parts.push(format!("\"{arg}\""));
        } else {
            parts.push(arg.clone());
        }
    }
    parts.join(" ")
}

fn append_process_output(lines: &mut Vec<String>, output: &std::process::Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.trim().is_empty() {
        lines.extend(stdout.lines().map(|line| line.to_string()));
    }
    if !stderr.trim().is_empty() {
        lines.push("[stderr]".to_string());
        lines.extend(stderr.lines().map(|line| line.to_string()));
    }
    if !output.status.success() {
        lines.push(format!("exit: {}", output.status));
    }
}

fn parse_nft_rules(output: &str) -> Vec<RuleEntry> {
    let mut rules = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.contains("handle") {
            continue;
        }
        let handle = trimmed
            .split("handle")
            .last()
            .map(|value| value.trim().split_whitespace().next().unwrap_or(""))
            .unwrap_or("");
        if handle.is_empty() || !handle.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }

        let summary = if let Some(idx) = trimmed.rfind("handle") {
            trimmed[..idx].trim().trim_end_matches('#').trim()
        } else {
            trimmed
        };

        rules.push(RuleEntry {
            id: handle.to_string(),
            summary: summary.to_string(),
        });
    }
    rules
}

fn parse_iptables_rules(output: &str) -> Vec<RuleEntry> {
    let mut rules = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim_start();
        let mut parts = trimmed.split_whitespace();
        let Some(id) = parts.next() else {
            continue;
        };
        if !id.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let summary = parts.collect::<Vec<&str>>().join(" ");
        rules.push(RuleEntry {
            id: id.to_string(),
            summary,
        });
    }
    rules
}

fn list_backups() -> Vec<PathBuf> {
    let mut backups = Vec::new();
    let dir = Path::new(BACKUP_DIR);
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return backups,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext == "gz")
            .unwrap_or(false)
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| name.ends_with(".tar.gz"))
                .unwrap_or(false)
        {
            backups.push(path);
        }
    }

    backups.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    backups
}

fn timestamp() -> String {
    if let Ok(output) = Command::new("date").arg("+%F_%H-%M-%S").output() {
        let ts = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !ts.is_empty() {
            return ts;
        }
    }
    let fallback = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("ts_{fallback}")
}

fn validate_input(
    language: Language,
    input: &str,
    default: Option<&str>,
    validation: Validation,
) -> Result<String, String> {
    let raw = if input.trim().is_empty() {
        default.unwrap_or("").to_string()
    } else {
        input.trim().to_string()
    };

    match validation {
        Validation::Any => Ok(raw),
        Validation::NonEmpty => {
            if raw.is_empty() {
                Err(ui_label(language, UiLabel::InvalidEmpty).to_string())
            } else {
                Ok(raw)
            }
        }
        Validation::Port => {
            let port: u16 = raw
                .parse()
                .map_err(|_| ui_label(language, UiLabel::InvalidPort).to_string())?;
            if port == 0 {
                Err(ui_label(language, UiLabel::InvalidPort).to_string())
            } else {
                Ok(port.to_string())
            }
        }
        Validation::Number => {
            let num: u32 = raw
                .parse()
                .map_err(|_| ui_label(language, UiLabel::InvalidNumber).to_string())?;
            if num == 0 {
                Err(ui_label(language, UiLabel::InvalidNumber).to_string())
            } else {
                Ok(num.to_string())
            }
        }
        Validation::YesNo => {
            let lowered = raw.to_lowercase();
            if matches!(lowered.as_str(), "si" | "s" | "y" | "yes") {
                Ok("si".to_string())
            } else if matches!(lowered.as_str(), "no" | "n") {
                Ok("no".to_string())
            } else if raw == "是" {
                Ok("si".to_string())
            } else if raw == "否" {
                Ok("no".to_string())
            } else {
                Err(ui_label(language, UiLabel::InvalidYesNo).to_string())
            }
        }
        Validation::CidrOptional => {
            if raw.is_empty() {
                Ok(String::new())
            } else if is_valid_cidr(&raw) {
                Ok(raw)
            } else {
                Err(ui_label(language, UiLabel::InvalidCidr).to_string())
            }
        }
        Validation::Proto => {
            let lowered = raw.to_lowercase();
            if matches!(lowered.as_str(), "tcp" | "udp" | "both") {
                Ok(lowered)
            } else {
                Err(ui_label(language, UiLabel::InvalidProto).to_string())
            }
        }
    }
}

fn is_valid_cidr(input: &str) -> bool {
    if input == "0.0.0.0/0" {
        return true;
    }
    let mut parts = input.split('/');
    let ip = match parts.next() {
        Some(ip) => ip,
        None => return false,
    };
    let mask = parts.next();
    if parts.next().is_some() {
        return false;
    }
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    for octet in octets {
        if octet.parse::<u8>().is_err() {
            return false;
        }
    }
    if let Some(mask) = mask {
        let mask_val: u8 = match mask.parse() {
            Ok(v) => v,
            Err(_) => return false,
        };
        if mask_val > 32 {
            return false;
        }
    }
    true
}

fn ui(frame: &mut ratatui::Frame, app: &mut App) {
    let size = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(8),
            Constraint::Length(3),
        ])
        .split(size);

    render_menu(frame, app, chunks[0]);
    render_rules(frame, app, chunks[1]);
    render_panel(frame, app, chunks[2]);
    if app.mode == Mode::Prompting {
        render_prompt_modal(frame, app, size);
    }
    render_status(frame, app, chunks[3]);
}

fn render_menu(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(ui_label(app.language, UiLabel::Actions));
    if app.focus == Focus::Actions {
        block = block.border_style(Style::default().fg(Color::Yellow));
    }

    let selected = app.list_state.selected().unwrap_or(0);
    let mut spans = Vec::new();
    for (idx, action) in app.actions.iter().enumerate() {
        let title = action_title(app.language, action.id);
        let style = if idx == selected {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        spans.push(Span::styled(title, style));
        if idx + 1 < app.actions.len() {
            spans.push(Span::raw("  |  "));
        }
    }

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line).block(block).wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn render_rules(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = if app.rules.is_empty() {
        vec![ListItem::new(ui_label(app.language, UiLabel::NoRules))]
    } else {
        app.rules
            .iter()
            .map(|rule| {
                let line = format!("[{}] {}", rule.id, rule.summary);
                ListItem::new(line)
            })
            .collect()
    };

    let mut block = Block::default()
        .borders(Borders::ALL)
        .title(ui_label(app.language, UiLabel::Rules));
    if app.focus == Focus::Rules {
        block = block.border_style(Style::default().fg(Color::Yellow));
    }

    let list = List::new(items)
        .block(block)
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .highlight_symbol("> ");
    frame.render_stateful_widget(list, area, &mut app.rules_state);
}
fn render_panel(frame: &mut ratatui::Frame, app: &mut App, area: Rect) {
    let output_label = ui_label(app.language, UiLabel::Output);
    let title = if let Some(cmd) = &app.last_cmd {
        format!("{output_label}: {cmd}")
    } else {
        output_label.to_string()
    };
    app.output_view_height = area.height.saturating_sub(2);
    let max_scroll = app.max_output_scroll();
    if app.output_scroll > max_scroll {
        app.output_scroll = max_scroll;
    }
    let text = Text::from(app.output.join("\n"));
    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((app.output_scroll, 0));
    frame.render_widget(paragraph, area);
}

fn render_prompt_modal(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let state = app.prompt_state.as_ref();
    let (label, default, validation, error, input) = if let Some(state) = state {
        let action = &app.actions[state.action_index];
        let prompts = action_prompts(action);
        let spec = &prompts[state.step_index];
        (
            prompt_label(app.language, spec.id),
            spec.default.unwrap_or(""),
            spec.validation,
            state.error.clone(),
            state.input.clone(),
        )
    } else {
        (
            ui_label(app.language, UiLabel::InputTitle),
            "",
            Validation::Any,
            None,
            String::new(),
        )
    };

    let popup_area = centered_rect(60, 45, area);
    frame.render_widget(Clear, popup_area);

    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::raw(ui_label(app.language, UiLabel::ValueLabel)),
        Span::styled(input, Style::default().fg(Color::Cyan)),
    ]));
    let display_default = display_default(app.language, validation, default);
    if !display_default.is_empty() {
        lines.push(Line::from(vec![
            Span::raw(ui_label(app.language, UiLabel::DefaultLabel)),
            Span::styled(display_default, Style::default().fg(Color::DarkGray)),
        ]));
    }
    if let Some(err) = error {
        lines.push(Line::from(Span::styled(
            err,
            Style::default().fg(Color::Red),
        )));
    }
    lines.push(Line::from(Span::styled(
        ui_label(app.language, UiLabel::PromptHelp),
        Style::default().fg(Color::Gray),
    )));

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(label))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, popup_area);
}

fn render_status(frame: &mut ratatui::Frame, app: &App, area: Rect) {
    let backend = app.backend.label();
    let dry = dry_run_state(app.language, app.dry_run);
    let root = if app.is_root {
        ui_label(app.language, UiLabel::Root)
    } else {
        ui_label(app.language, UiLabel::NotRoot)
    };
    let action_info = app
        .selected_action()
        .map(|action| {
            if area.width >= 90 {
                action_desc(app.language, action.id)
            } else {
                action_title(app.language, action.id)
            }
        })
        .unwrap_or(ui_label(app.language, UiLabel::NoAction));
    let focus_label = match app.focus {
        Focus::Actions => ui_label(app.language, UiLabel::FocusActions),
        Focus::Rules => ui_label(app.language, UiLabel::FocusRules),
    };
    let mut components = vec![
        format!("{}: {backend}", ui_label(app.language, UiLabel::Backend)),
        format!("{}: {dry}", ui_label(app.language, UiLabel::DryRun)),
        format!(
            "{}: {}",
            ui_label(app.language, UiLabel::Language),
            language_name(app.language)
        ),
        format!("{}: {focus_label}", ui_label(app.language, UiLabel::Focus)),
        root.to_string(),
        action_info.to_string(),
    ];
    let available = area.width.saturating_sub(2) as usize;
    let mut base = join_components(&components);
    while text_width(&base) > available && components.len() > 2 {
        components.pop();
        base = join_components(&components);
    }

    let keys_full = keys_hint(app.language, KeyHint::Full);
    let keys_short = keys_hint(app.language, KeyHint::Short);
    let keys_min = keys_hint(app.language, KeyHint::Minimal);
    let keys_label = ui_label(app.language, UiLabel::Keys);
    let mut keys = format!("{keys_label}: {keys_full}");
    if text_width(&format!("{base} | {keys}")) > available {
        keys = format!("{keys_label}: {keys_short}");
    }
    if text_width(&format!("{base} | {keys}")) > available {
        keys = format!("{keys_label}: {keys_min}");
    }

    let mut lines = Vec::new();
    if text_width(&format!("{base} | {keys}")) <= available {
        lines.push(Line::from(format!("{base} | {keys}")));
    } else {
        lines.push(Line::from(base));
        lines.push(Line::from(keys));
    }

    let paragraph = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Gray))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[derive(Clone, Copy)]
enum KeyHint {
    Full,
    Short,
    Minimal,
}

fn keys_hint(language: Language, hint: KeyHint) -> &'static str {
    match language {
        Language::Es => match hint {
            KeyHint::Full => "Flechas Enter b d l t r x PgUp/PgDn q",
            KeyHint::Short => "Flechas Enter b d l t r x q",
            KeyHint::Minimal => "Flechas Enter q",
        },
        Language::En => match hint {
            KeyHint::Full => "Arrows Enter b d l t r x PgUp/PgDn q",
            KeyHint::Short => "Arrows Enter b d l t r x q",
            KeyHint::Minimal => "Arrows Enter q",
        },
        Language::ZhCn => match hint {
            KeyHint::Full => "方向键 Enter b d l t r x PgUp/PgDn q",
            KeyHint::Short => "方向键 Enter b d l t r x q",
            KeyHint::Minimal => "方向键 Enter q",
        },
    }
}

fn join_components(components: &[String]) -> String {
    components.join(" | ")
}

fn text_width(text: &str) -> usize {
    text.chars().count()
}
