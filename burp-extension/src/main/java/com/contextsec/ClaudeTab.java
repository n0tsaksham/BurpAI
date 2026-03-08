package com.contextsec;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.AuditConfiguration;

import burp.api.montoya.core.HighlightColor;

import com.google.gson.*;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.*;
import java.util.stream.Collectors;

/**
 * ClaudeTab - Claude AI chat panel inside Burp Suite
 *
 * A native Burp extension that embeds a full Claude conversation
 * panel inside Burp Suite. Right-click any request -> "Analyze with
 * Claude", or use the chat tab directly to ask anything about your
 * traffic, findings, and test ideas.
 */
public class ClaudeTab implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private Logging    logging;
    private ChatPanel  chatPanel;

    // Session role labels: normalized host|path → role ("Admin" / "User" / "Unauth")
    final Map<String, String> sessionLabels = new java.util.concurrent.ConcurrentHashMap<>();

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
        .connectTimeout(java.time.Duration.ofSeconds(10))
        .build();

    @Override
    public void initialize(MontoyaApi api) {
        this.api     = api;
        this.logging = api.logging();
        api.extension().setName("ClaudeTab");
        api.userInterface().registerContextMenuItemsProvider(this);

        SwingUtilities.invokeLater(() -> {
            chatPanel = new ChatPanel();
            api.userInterface().registerSuiteTab("Claude", chatPanel);
        });

        logging.logToOutput("[ClaudeTab] Loaded. Set your Anthropic API key in the Claude tab.");
    }

    // ----------------------------------------------------------------
    // Context menu: right-click in Proxy / Repeater / Scanner
    // ----------------------------------------------------------------

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        // "Analyze with Claude" — works on selected request/response
        JMenuItem analyze = new JMenuItem("Analyze with Claude");
        analyze.addActionListener(e -> {
            String context = buildContextFromEvent(event);
            if (context != null && chatPanel != null) {
                chatPanel.sendWithContext("Analyze this for security vulnerabilities:\n\n" + context);
                api.userInterface().swingUtils().suiteFrame().toFront();
            }
        });
        items.add(analyze);

        // "Find IDOR" shortcut
        JMenuItem idor = new JMenuItem("Claude: Find IDOR/BAC");
        idor.addActionListener(e -> {
            String context = buildContextFromEvent(event);
            if (context != null && chatPanel != null) {
                chatPanel.sendWithContext(
                    "Look at this request and identify IDOR, Broken Access Control, " +
                    "and privilege escalation vulnerabilities. " +
                    "Give specific test payloads.\n\n" + context);
                api.userInterface().swingUtils().suiteFrame().toFront();
            }
        });
        items.add(idor);

        // "Explain response" shortcut
        JMenuItem explain = new JMenuItem("Claude: Explain Response");
        explain.addActionListener(e -> {
            String context = buildContextFromEvent(event);
            if (context != null && chatPanel != null) {
                chatPanel.sendWithContext(
                    "Explain what this response reveals about the application " +
                    "and identify any security concerns:\n\n" + context);
                api.userInterface().swingUtils().suiteFrame().toFront();
            }
        });
        items.add(explain);

        // Intruder payload generation
        JMenuItem intruder = new JMenuItem("Claude: Generate Intruder Payloads");
        intruder.addActionListener(e -> {
            try {
                List<HttpRequestResponse> sel = event.selectedRequestResponses();
                HttpRequest req = null;
                if (!sel.isEmpty()) req = sel.get(0).request();
                else if (event.messageEditorRequestResponse().isPresent())
                    req = event.messageEditorRequestResponse().get().requestResponse().request();
                if (req == null) return;
                final HttpRequest finalReq = req;
                if (chatPanel == null) return;
                chatPanel.generateIntruderPayloads(finalReq);
                api.userInterface().swingUtils().suiteFrame().toFront();
            } catch (Exception ex) {
                logging.logToError("[ClaudeTab] Intruder error: " + ex.getMessage());
            }
        });
        items.add(intruder);

        // Session role labeling submenu
        JMenu labelMenu = new JMenu("ClaudeTab: Label Session Role");
        for (String role : new String[]{"Admin", "Regular User", "Unauthenticated"}) {
            JMenuItem roleItem = new JMenuItem("Mark as " + role);
            roleItem.addActionListener(e -> {
                try {
                    List<HttpRequestResponse> sel = event.selectedRequestResponses();
                    if (sel.isEmpty()) return;
                    HttpRequest req = sel.get(0).request();
                    String host = req.httpService() != null ? req.httpService().host() : "";
                    String path = req.url().split("\\?")[0];
                    String key = host + "|" + path;
                    sessionLabels.put(key, role);
                    // Also mark in proxy history with a note
                    for (ProxyHttpRequestResponse rr : api.proxy().history()) {
                        String rHost = rr.request().httpService() != null ? rr.request().httpService().host() : "";
                        String rPath = rr.request().url().split("\\?")[0];
                        if ((rHost + "|" + rPath).equals(key)) {
                            rr.annotations().setNotes("[" + role + "] " +
                                (rr.annotations().notes() != null ? rr.annotations().notes() : ""));
                        }
                    }
                    logging.logToOutput("[ClaudeTab] Labeled " + key + " as: " + role);
                } catch (Exception ex) {
                    logging.logToError("[ClaudeTab] Label error: " + ex.getMessage());
                }
            });
            labelMenu.add(roleItem);
        }
        JMenuItem clearLabels = new JMenuItem("Clear All Labels");
        clearLabels.addActionListener(e -> { sessionLabels.clear(); logging.logToOutput("[ClaudeTab] Session labels cleared."); });
        labelMenu.addSeparator();
        labelMenu.add(clearLabels);
        items.add(labelMenu);

        return items;
    }

    private String buildContextFromEvent(ContextMenuEvent event) {
        try {
            // From Proxy / HTTP history
            List<HttpRequestResponse> proxyItems = event.selectedRequestResponses();
            if (!proxyItems.isEmpty()) {
                HttpRequestResponse rr = proxyItems.get(0);
                return formatRequestResponse(rr.request(), rr.response());
            }
            // From Repeater / message editor
            Optional<MessageEditorHttpRequestResponse> editor = event.messageEditorRequestResponse();
            if (editor.isPresent()) {
                MessageEditorHttpRequestResponse me = editor.get();
                return formatRequestResponse(me.requestResponse().request(),
                                             me.requestResponse().response());
            }
        } catch (Exception ex) {
            logging.logToError("[ClaudeTab] Context menu error: " + ex.getMessage());
        }
        return null;
    }

    private String formatRequestResponse(HttpRequest req, HttpResponse resp) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== REQUEST ===\n");
        sb.append(req.toString(), 0, Math.min(req.toString().length(), 2000));
        if (resp != null) {
            sb.append("\n\n=== RESPONSE ===\n");
            String respStr = resp.toString();
            sb.append(respStr, 0, Math.min(respStr.length(), 2000));
        }
        return sb.toString();
    }

    // ----------------------------------------------------------------
    // Chat Panel
    // ----------------------------------------------------------------

    class ChatPanel extends JPanel {

        private final JTextPane   chatArea;
        private final JTextField  inputField;
        private final JButton     sendBtn;
        private final JButton     clearBtn;
        private JButton           stopBtn;
        private volatile boolean  stopRequested = false;

        private final JTextField  apiKeyField;
        private final JLabel      statusLabel;
        private final JTextArea   targetContextArea; // CLAUDE.md / engagement brief

        // Conversation history sent to Claude on each request
        private final List<Map<String, String>> conversationHistory = new ArrayList<>();

        // Streaming state
        private volatile Style  streamBodyStyle  = null;
        private volatile int    streamStartOffset = 0;
        private volatile StringBuilder streamBuffer = new StringBuilder();

        // Extra context prepended (current request, history summary, etc.)
        private String pendingContext = null;

        ChatPanel() {
            super(new BorderLayout(0, 0));
            setBackground(Color.decode("#1e1e1e"));

            // ---- Header bar ----------------------------------------
            JPanel header = new JPanel(new BorderLayout());
            header.setBackground(Color.decode("#141414"));
            header.setBorder(new EmptyBorder(8, 12, 8, 12));

            JLabel title = new JLabel("  Claude AI  —  ClaudeTab");
            title.setForeground(Color.decode("#00d2a0"));
            title.setFont(new Font("Monospaced", Font.BOLD, 14));
            header.add(title, BorderLayout.WEST);

            JPanel apiPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            apiPanel.setBackground(Color.decode("#141414"));
            JLabel apiLabel = new JLabel("API Key:");
            apiLabel.setForeground(Color.decode("#888888"));
            apiLabel.setFont(new Font("Monospaced", Font.PLAIN, 12));
            apiPanel.add(apiLabel);
            apiKeyField = new JTextField(32);
            apiKeyField.setFont(new Font("Monospaced", Font.PLAIN, 12));
            apiKeyField.setBackground(Color.decode("#2a2a2a"));
            apiKeyField.setForeground(Color.decode("#cccccc"));
            apiKeyField.setCaretColor(Color.WHITE);
            apiKeyField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.decode("#444444")),
                new EmptyBorder(4, 6, 4, 6)));
            apiKeyField.setToolTipText("sk-ant-... (saved automatically)");

            // Load saved API key from Burp preferences
            String savedKey = api.persistence().preferences().getString("claudetab.apikey");
            if (savedKey != null && !savedKey.isBlank()) apiKeyField.setText(savedKey);

            // Save whenever the field changes
            apiKeyField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                private void save() {
                    String k = apiKeyField.getText().trim();
                    if (k.startsWith("sk-ant-"))
                        api.persistence().preferences().setString("claudetab.apikey", k);
                }
                public void insertUpdate(javax.swing.event.DocumentEvent e)  { save(); }
                public void removeUpdate(javax.swing.event.DocumentEvent e)  { save(); }
                public void changedUpdate(javax.swing.event.DocumentEvent e) { save(); }
            });

            apiPanel.add(apiKeyField);
            header.add(apiPanel, BorderLayout.EAST);

            // ---- Target context panel (CLAUDE.md / engagement brief) ----
            JPanel ctxPanel = new JPanel(new BorderLayout(6, 0));
            ctxPanel.setBackground(Color.decode("#1a1a1a"));
            ctxPanel.setBorder(new EmptyBorder(0, 10, 6, 10));

            targetContextArea = new JTextArea(2, 40);
            targetContextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
            targetContextArea.setBackground(Color.decode("#242424"));
            targetContextArea.setForeground(Color.decode("#888888"));
            targetContextArea.setCaretColor(Color.WHITE);
            targetContextArea.setLineWrap(true);
            targetContextArea.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.decode("#333333")),
                new EmptyBorder(4, 8, 4, 8)));
            targetContextArea.setText("Engagement brief: target, scope, focus areas, credentials... or load CLAUDE.md");
            targetContextArea.addFocusListener(new java.awt.event.FocusAdapter() {
                public void focusGained(java.awt.event.FocusEvent e) {
                    if (targetContextArea.getText().startsWith("Engagement brief:"))
                        targetContextArea.setText("");
                    targetContextArea.setForeground(Color.decode("#cccccc"));
                }
            });

            JPanel ctxBtns = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
            ctxBtns.setBackground(Color.decode("#1a1a1a"));

            JButton loadMdBtn = styledButton("📁 CLAUDE.md", "#2a3a4a");
            loadMdBtn.setToolTipText("Load engagement brief from a CLAUDE.md file");
            loadMdBtn.setFont(new Font("Dialog", Font.PLAIN, 11));
            loadMdBtn.addActionListener(e -> loadClaudeMd());
            ctxBtns.add(loadMdBtn);

            JButton saveSessionBtn = styledButton("💾 Save", "#2a4a2a");
            saveSessionBtn.setToolTipText("Save chat session to JSON");
            saveSessionBtn.setFont(new Font("Dialog", Font.PLAIN, 11));
            saveSessionBtn.addActionListener(e -> saveSession());
            ctxBtns.add(saveSessionBtn);

            JButton loadSessionBtn = styledButton("📂 Load", "#4a3a1a");
            loadSessionBtn.setToolTipText("Load a previously saved chat session");
            loadSessionBtn.setFont(new Font("Dialog", Font.PLAIN, 11));
            loadSessionBtn.addActionListener(e -> loadSession());
            ctxBtns.add(loadSessionBtn);

            ctxPanel.add(ctxBtns, BorderLayout.WEST);
            ctxPanel.add(new JScrollPane(targetContextArea), BorderLayout.CENTER);

            JPanel topArea = new JPanel(new BorderLayout());
            topArea.add(header,   BorderLayout.NORTH);
            topArea.add(ctxPanel, BorderLayout.SOUTH);
            add(topArea, BorderLayout.NORTH);

            // ---- Chat area -----------------------------------------
            chatArea = new JTextPane();
            chatArea.setEditable(false);
            chatArea.setBackground(Color.decode("#1e1e1e"));
            chatArea.setFont(new Font("Monospaced", Font.PLAIN, 11));

            // Right-click: Send to Repeater
            JPopupMenu chatCtxMenu = new JPopupMenu();
            JMenuItem sendToRepeaterItem = new JMenuItem("Send selection to Repeater");
            sendToRepeaterItem.addActionListener(e -> {
                String sel = chatArea.getSelectedText();
                if (sel != null && !sel.isBlank()) tryParseAndSendToRepeater(sel.trim());
                else appendMessage("system", "Select a raw HTTP request block first, then right-click.");
            });
            JMenuItem copyItem = new JMenuItem("Copy");
            copyItem.addActionListener(e -> chatArea.copy());
            chatCtxMenu.add(sendToRepeaterItem);
            chatCtxMenu.addSeparator();
            chatCtxMenu.add(copyItem);
            chatArea.addMouseListener(new MouseAdapter() {
                public void mousePressed(MouseEvent e)  { if (e.isPopupTrigger()) chatCtxMenu.show(chatArea, e.getX(), e.getY()); }
                public void mouseReleased(MouseEvent e) { if (e.isPopupTrigger()) chatCtxMenu.show(chatArea, e.getX(), e.getY()); }
            });

            JScrollPane scroll = new JScrollPane(chatArea);
            scroll.setBackground(Color.decode("#1e1e1e"));
            scroll.setBorder(null);
            scroll.getVerticalScrollBar().setBackground(Color.decode("#2a2a2a"));

            // ---- Single toolbar: Scan dropdown + Export + Clear ----
            JPanel toolbar = new JPanel(new BorderLayout());
            toolbar.setBackground(Color.decode("#252525"));
            toolbar.setBorder(new EmptyBorder(2, 8, 2, 8));
            JPanel toolbarLeft  = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
            JPanel toolbarRight = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 4));
            toolbarLeft.setBackground(Color.decode("#252525"));
            toolbarRight.setBackground(Color.decode("#252525"));

            // Scan dropdown button
            JButton scanDropBtn = styledButton("Scan  \u25BE", "#2a6a3a");
            scanDropBtn.setToolTipText("Run a Claude-powered scan");
            JPopupMenu scanMenu = new JPopupMenu();

            JMenuItem fullScan = new JMenuItem("Full Vulnerability Scan");
            fullScan.addActionListener(e -> sendWithContext(
                "Run a comprehensive vulnerability scan on all the proxy history above. " +
                "Analyze every endpoint for: IDOR, Broken Access Control, SSRF, CORS misconfigs, " +
                "injection points, auth flaws, privilege escalation, sensitive data exposure, " +
                "and missing security headers. " +
                "Format as a professional pentest report: CRITICAL / HIGH / MEDIUM / LOW sections, " +
                "each finding with endpoint, evidence from the actual traffic, attack payload. " +
                "End with a ranked test priority list."));
            scanMenu.add(fullScan);
            scanMenu.addSeparator();

            JMenuItem passiveItem = new JMenuItem("Passive Scan  \u2192 adds to Burp Scanner");
            passiveItem.addActionListener(e -> runInThread(this::runPassiveScan));
            scanMenu.add(passiveItem);

            JMenuItem activeItem = new JMenuItem("Active Scan  \u2192 sends test requests");
            activeItem.addActionListener(e -> runInThread(this::runActiveScan));
            scanMenu.add(activeItem);

            JMenuItem verifyItem = new JMenuItem("Verify Burp Findings  \u2192 mark false positives");
            verifyItem.addActionListener(e -> runInThread(this::verifyScannerFindings));
            scanMenu.add(verifyItem);

            scanMenu.addSeparator();
            JMenuItem agentItem = new JMenuItem("⏺ Agent Scan  \u2192 Claude sends & chains requests");
            agentItem.setFont(agentItem.getFont().deriveFont(Font.BOLD));
            agentItem.addActionListener(e -> runInThread(this::runAgentScan));
            scanMenu.add(agentItem);

            scanMenu.addSeparator();
            JMenuItem stackItem = new JMenuItem("Detect Tech Stack");
            stackItem.addActionListener(e -> sendWithContext("Detect the tech stack from the proxy history. Show evidence for each detection."));
            scanMenu.add(stackItem);

            scanMenu.addSeparator();
            JMenuItem authItem = new JMenuItem("🔑 Authenticate + Capture Token");
            authItem.addActionListener(e -> {
                String[] fields = {"Login URL (e.g. https://app.example.com/api/auth/login)",
                                   "Username / Email", "Password"};
                JTextField[] inputs = new JTextField[3];
                JPanel authPanel = new JPanel(new java.awt.GridLayout(fields.length * 2, 1, 4, 4));
                authPanel.setBorder(new EmptyBorder(8, 8, 8, 8));
                for (int i = 0; i < fields.length; i++) {
                    authPanel.add(new JLabel(fields[i]));
                    inputs[i] = new JTextField(40);
                    authPanel.add(inputs[i]);
                }
                int res = javax.swing.JOptionPane.showConfirmDialog(null, authPanel,
                    "ClaudeTab — Authenticate", javax.swing.JOptionPane.OK_CANCEL_OPTION,
                    javax.swing.JOptionPane.PLAIN_MESSAGE);
                if (res != javax.swing.JOptionPane.OK_OPTION) return;
                String loginUrl  = inputs[0].getText().trim();
                String username  = inputs[1].getText().trim();
                String password  = inputs[2].getText().trim();
                if (loginUrl.isEmpty() || username.isEmpty() || password.isEmpty()) {
                    appendMessage("error", "All fields required.");
                    return;
                }
                // Parse host/port/https from URL
                boolean isHttps = loginUrl.startsWith("https://");
                String withoutScheme = loginUrl.replaceFirst("https?://", "");
                String host = withoutScheme.contains("/") ? withoutScheme.substring(0, withoutScheme.indexOf('/')) : withoutScheme;
                String path = withoutScheme.contains("/") ? withoutScheme.substring(withoutScheme.indexOf('/')) : "/";
                int port = isHttps ? 443 : 80;
                if (host.contains(":")) {
                    try { port = Integer.parseInt(host.split(":")[1]); } catch (Exception ignored) {}
                    host = host.split(":")[0];
                }
                final String finalHost = host;
                final int finalPort = port;
                final String finalPath = path;

                String authPrompt = String.format(
                    "Your task: authenticate to this application and capture the session token.\n\n" +
                    "Login URL: %s\nHost: %s\nPort: %d\nHTTPS: %b\nPath: %s\n" +
                    "Username: %s\nPassword: %s\n\n" +
                    "Steps:\n" +
                    "1. Send a POST to the login endpoint with the credentials. Try JSON body first: {\"email\":\"...\",\"password\":\"...\"} and also {\"username\":\"...\",\"password\":\"...\"}. Check Content-Type in proxy history.\n" +
                    "2. Read the response. Extract any JWT or session token from the response body or Set-Cookie header.\n" +
                    "3. If the response includes an MFA or 2FA screen, look for a 'skip', 'setup later', 'remind me later' or similar option — send a request to that endpoint to bypass it.\n" +
                    "4. Make one authenticated request to a profile or dashboard endpoint to confirm the token works.\n" +
                    "5. Print the captured token clearly labeled as: CAPTURED TOKEN: <value>\n" +
                    "6. Print the Authorization header format: Authorization: Bearer <token>\n\n" +
                    "Do NOT stop until you have a working token or have exhausted all login endpoint variations visible in proxy history.",
                    loginUrl, finalHost, finalPort, isHttps, finalPath, username, password);

                runInThread(() -> runAgentAuth(apiKeyField.getText().trim(), authPrompt));
            });
            scanMenu.add(authItem);

            scanDropBtn.addActionListener(e ->
                scanMenu.show(scanDropBtn, 0, scanDropBtn.getHeight()));
            toolbarLeft.add(scanDropBtn);

            JButton exportBtn = styledButton("Export Report", "#6a3a1a");
            exportBtn.addActionListener(e -> exportReport());
            toolbarLeft.add(exportBtn);

            clearBtn = styledButton("Clear", "#3a3a3a");
            clearBtn.addActionListener(e -> clearChat());
            toolbarLeft.add(clearBtn);

            statusLabel = new JLabel("Ready");
            statusLabel.setForeground(Color.decode("#555555"));
            statusLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
            toolbarLeft.add(statusLabel);

            stopBtn = styledButton("⏹ Stop", "#2a2a2a");
            stopBtn.setForeground(Color.decode("#555555"));
            stopBtn.setEnabled(false);
            stopBtn.setPreferredSize(new Dimension(90, 28));
            stopBtn.addActionListener(e -> {
                stopRequested = true;
                stopBtn.setEnabled(false);
                setStatus("Stopping...");
            });
            toolbarRight.add(stopBtn);

            toolbar.add(toolbarLeft,  BorderLayout.CENTER);
            toolbar.add(toolbarRight, BorderLayout.EAST);

            // ---- Input row -----------------------------------------
            JPanel inputRow = new JPanel(new BorderLayout(6, 0));
            inputRow.setBackground(Color.decode("#1a1a1a"));
            inputRow.setBorder(new EmptyBorder(8, 10, 10, 10));

            inputField = new JTextField();
            inputField.setFont(new Font("Monospaced", Font.PLAIN, 12));
            inputField.setBackground(Color.decode("#2a2a2a"));
            inputField.setForeground(Color.decode("#e0e0e0"));
            inputField.setCaretColor(Color.WHITE);
            inputField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.decode("#444444")),
                new EmptyBorder(8, 10, 8, 10)));
            inputField.setToolTipText("Ask Claude anything about your traffic...");
            inputField.addActionListener(e -> sendMessage());

            // ESC key stops agent — bind on the panel with WHEN_IN_FOCUSED_WINDOW
            javax.swing.KeyStroke escKey = javax.swing.KeyStroke.getKeyStroke(
                java.awt.event.KeyEvent.VK_ESCAPE, 0);
            getInputMap(javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW).put(escKey, "stopAgent");
            getActionMap().put("stopAgent", new javax.swing.AbstractAction() {
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    if (stopBtn.isVisible() && !stopRequested) {
                        stopRequested = true;
                        stopBtn.setEnabled(false);
                        setStatus("Stopping after current turn... (ESC)");
                    }
                }
            });

            sendBtn = styledButton("Send", "#00d2a0");
            sendBtn.setForeground(Color.decode("#111111"));
            sendBtn.setFont(new Font("Monospaced", Font.BOLD, 12));
            sendBtn.setPreferredSize(new Dimension(70, 38));
            sendBtn.addActionListener(e -> sendMessage());

            inputRow.add(inputField, BorderLayout.CENTER);
            inputRow.add(sendBtn,    BorderLayout.EAST);

            // ---- Bottom panel --------------------------------------
            JPanel bottom = new JPanel(new BorderLayout());
            bottom.setBackground(Color.decode("#1a1a1a"));
            bottom.add(toolbar,  BorderLayout.NORTH);
            bottom.add(inputRow, BorderLayout.SOUTH);

            add(scroll, BorderLayout.CENTER);
            add(bottom, BorderLayout.SOUTH);

            // Welcome message
            appendMessage("system",
                "ClaudeTab ready.\n\n" +
                "Claude automatically sees your live proxy traffic and scanner findings on every message.\n" +
                "No need to load anything manually — just browse the app and start asking.\n\n" +
                "Enter your Anthropic API key above, then try:\n\n" +
                "  > find IDOR and broken access control vulnerabilities\n" +
                "  > which parameters look injectable?\n" +
                "  > what does this application do?\n" +
                "  > detect the tech stack\n" +
                "  > which scanner findings are false positives?\n" +
                "  > write a payload for the /api/users endpoint\n\n" +
                "Or right-click any request -> Analyze with Claude / Find IDOR/BAC / Explain Response\n"
            );
        }

        // ---- Send a message ----------------------------------------

        void sendMessage() {
            String text = inputField.getText().trim();
            if (text.isEmpty()) return;
            inputField.setText("");
            sendWithContext(text);
        }

        void sendWithContext(String userMessage) {
            String apiKey = apiKeyField.getText().trim();
            if (apiKey.isEmpty()) {
                appendMessage("error", "No API key set. Enter your Anthropic API key above.");
                return;
            }

            String fullMessage = userMessage;
            if (pendingContext != null) {
                fullMessage = pendingContext + "\n\n" + userMessage;
                pendingContext = null;
            }

            appendMessage("user", userMessage);
            int histCount = api.proxy().history().size();
            int issueCount = api.siteMap().issues().size();
            setStatus("Streaming... (context: " + histCount + " requests, " + issueCount + " issues)");
            sendBtn.setEnabled(false);
            showStopButton(true);

            final String messageToSend = fullMessage;
            ExecutorService exec = Executors.newSingleThreadExecutor();
            exec.submit(() -> {
                try {
                    streamClaude(apiKey, messageToSend);
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        appendMessage("error", "Error: " + ex.getMessage());
                        setStatus("Error");
                        sendBtn.setEnabled(true);
                    });
                }
                showStopButton(false);
                exec.shutdown();
            });
        }

        // ---- Streaming Claude call ---------------------------------

        /** Returns true if the message is a conversational/simple query that doesn't need proxy context */
        private boolean isConversational(String msg) {
            String lower = msg.toLowerCase().trim();
            // Short messages or simple questions — no need to inject 300+ requests
            if (lower.length() < 30) return true;
            String[] securityKeywords = {"scan","vuln","idor","sqli","xss","ssrf","cors","inject","payload",
                "endpoint","exploit","bypass","auth","token","jwt","pentest","test","find","analyze",
                "attack","sensitive","disclosure","parameter","request","response","history","scope"};
            for (String kw : securityKeywords) { if (lower.contains(kw)) return false; }
            return true;
        }

        private void streamClaude(String apiKey, String userMessage) throws Exception {
            String liveCtx = isConversational(userMessage) ? null : buildLiveContext();
            StringBuilder fullMessage = new StringBuilder();
            if (liveCtx != null) fullMessage.append(liveCtx).append("\n");
            fullMessage.append(userMessage);

            Map<String, String> userMsg = new LinkedHashMap<>();
            userMsg.put("role", "user");
            userMsg.put("content", fullMessage.toString());
            conversationHistory.add(userMsg);

            List<Map<String, String>> history = conversationHistory;
            if (history.size() > 20) history = history.subList(history.size() - 20, history.size());

            Gson gson = new Gson();
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("model", "claude-opus-4-5");
            payload.put("max_tokens", 4096);
            payload.put("stream", true);
            payload.put("system",
                "You are an expert penetration tester embedded inside Burp Suite Pro. " +
                "You have LIVE access to the user's proxy history and scanner findings — they are automatically " +
                "included at the top of every message. Use them as your primary context. " +
                "Never say you don't have access to proxy history or Burp data. " +
                "Your job: identify vulnerabilities (IDOR, BAC, SSRF, injection, auth flaws) and give " +
                "actionable attack guidance with real payloads specific to the endpoints shown. " +
                "Format findings with severity: CRITICAL / HIGH / MEDIUM / LOW.");
            payload.put("messages", history);

            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create("https://api.anthropic.com/v1/messages"))
                .header("x-api-key", apiKey)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(gson.toJson(payload)))
                .timeout(java.time.Duration.ofSeconds(120))
                .build();

            // Start the streaming bubble in UI
            SwingUtilities.invokeAndWait(this::startStreamingBubble);
            streamBuffer.setLength(0);

            java.net.http.HttpResponse<InputStream> response = HTTP_CLIENT.send(
                request, java.net.http.HttpResponse.BodyHandlers.ofInputStream());

            if (response.statusCode() != 200) {
                byte[] body = response.body().readAllBytes();
                throw new Exception("API error " + response.statusCode() + ": " + new String(body));
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(response.body(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (stopRequested) {
                        SwingUtilities.invokeLater(() -> appendStreamChunk("\n\n*[Stopped]*"));
                        break;
                    }
                    if (!line.startsWith("data: ")) continue;
                    String data = line.substring(6).trim();
                    if (data.equals("[DONE]")) break;
                    try {
                        JsonObject event = JsonParser.parseString(data).getAsJsonObject();
                        if (!"content_block_delta".equals(getStr(event, "type", ""))) continue;
                        JsonObject delta = event.getAsJsonObject("delta");
                        if (delta == null || !"text_delta".equals(getStr(delta, "type", ""))) continue;
                        String chunk = delta.get("text").getAsString();
                        streamBuffer.append(chunk);
                        final String c = chunk;
                        SwingUtilities.invokeLater(() -> appendStreamChunk(c));
                    } catch (Exception ignored) {}
                }
            }

            // Finalise: store in history, mark HTTP history, re-enable UI
            final String fullReply = streamBuffer.toString();
            Map<String, String> assistantMsg = new LinkedHashMap<>();
            assistantMsg.put("role", "assistant");
            assistantMsg.put("content", fullReply);
            conversationHistory.add(assistantMsg);

            SwingUtilities.invokeLater(() -> {
                finalizeStreamingBubble(fullReply);
                markVulnerableInHistory(fullReply);
                setStatus("Ready");
                sendBtn.setEnabled(true);
                scrollToBottom();
            });
        }

        private void startStreamingBubble() {
            StyledDocument doc = chatArea.getStyledDocument();
            streamStartOffset = doc.getLength(); // snapshot so we can replace on finalize

            Style label = chatArea.addStyle("slabel", null);
            StyleConstants.setFontFamily(label, "Monospaced");
            StyleConstants.setFontSize(label, 11);
            StyleConstants.setForeground(label, Color.decode("#ffb800"));
            StyleConstants.setBold(label, true);

            streamBodyStyle = chatArea.addStyle("sbody", null);
            StyleConstants.setFontFamily(streamBodyStyle, "Monospaced");
            StyleConstants.setFontSize(streamBodyStyle, 11);
            StyleConstants.setForeground(streamBodyStyle, Color.decode("#d0d0d0"));

            try {
                doc.insertString(doc.getLength(), "\nClaude\n", label);
            } catch (BadLocationException ignored) {}
            scrollToBottom();
        }

        private void appendStreamChunk(String chunk) {
            if (streamBodyStyle == null) return;
            try {
                StyledDocument doc = chatArea.getStyledDocument();
                doc.insertString(doc.getLength(), chunk, streamBodyStyle);
                scrollToBottom();
            } catch (BadLocationException ignored) {}
        }

        /** Remove raw streamed text and re-render with markdown formatting */
        private void finalizeStreamingBubble(String fullText) {
            streamBodyStyle = null;
            StyledDocument doc = chatArea.getStyledDocument();
            try {
                int len = doc.getLength() - streamStartOffset;
                if (len > 0) doc.remove(streamStartOffset, len);
            } catch (BadLocationException ignored) {}
            // Re-insert with full markdown rendering
            appendClaudeFormatted(fullText);
        }

        // ---- Markdown-aware message renderer -----------------------

        private void appendClaudeFormatted(String text) {
            StyledDocument doc = chatArea.getStyledDocument();

            // Label style
            Style labelSt = chatArea.addStyle("cLabel", null);
            StyleConstants.setFontFamily(labelSt, "Monospaced");
            StyleConstants.setFontSize(labelSt, 11);
            StyleConstants.setForeground(labelSt, Color.decode("#ffb800"));
            StyleConstants.setBold(labelSt, true);

            // Body styles
            Style normalSt = chatArea.addStyle("cNormal", null);
            StyleConstants.setFontFamily(normalSt, "Monospaced");
            StyleConstants.setFontSize(normalSt, 11);
            StyleConstants.setForeground(normalSt, Color.decode("#d0d0d0"));

            Style headingSt = chatArea.addStyle("cHeading", null);
            StyleConstants.setFontFamily(headingSt, "Monospaced");
            StyleConstants.setFontSize(headingSt, 12);
            StyleConstants.setForeground(headingSt, Color.decode("#00d2a0"));
            StyleConstants.setBold(headingSt, true);

            Style codeSt = chatArea.addStyle("cCode", null);
            StyleConstants.setFontFamily(codeSt, "Monospaced");
            StyleConstants.setFontSize(codeSt, 12);
            StyleConstants.setForeground(codeSt, Color.decode("#ce9178"));
            StyleConstants.setBackground(codeSt, Color.decode("#2d2d2d"));

            Style boldSt = chatArea.addStyle("cBold", null);
            StyleConstants.setFontFamily(boldSt, "Monospaced");
            StyleConstants.setFontSize(boldSt, 11);
            StyleConstants.setForeground(boldSt, Color.decode("#d0d0d0"));
            StyleConstants.setBold(boldSt, true);

            Style tableSt = chatArea.addStyle("cTable", null);
            StyleConstants.setFontFamily(tableSt, "Monospaced");
            StyleConstants.setFontSize(tableSt, 11);
            StyleConstants.setForeground(tableSt, Color.decode("#b0c0b0"));

            try {
                doc.insertString(doc.getLength(), "\nClaude\n", labelSt);
            } catch (BadLocationException ignored) {}

            String[] lines = text.split("\n", -1);
            int i = 0;
            while (i < lines.length) {
                String line = lines[i];

                // Fenced code block
                if (line.trim().startsWith("```")) {
                    StringBuilder code = new StringBuilder();
                    i++;
                    while (i < lines.length && !lines[i].trim().startsWith("```")) {
                        code.append(lines[i]).append("\n");
                        i++;
                    }
                    i++; // consume closing ```
                    try { doc.insertString(doc.getLength(), code.toString(), codeSt); }
                    catch (BadLocationException ignored) {}
                    continue;
                }

                // Table block: collect consecutive pipe lines
                if (line.trim().startsWith("|")) {
                    List<String> tableLines = new ArrayList<>();
                    while (i < lines.length && lines[i].trim().startsWith("|")) {
                        tableLines.add(lines[i]);
                        i++;
                    }
                    String rendered = renderTable(tableLines);
                    try { doc.insertString(doc.getLength(), rendered, tableSt); }
                    catch (BadLocationException ignored) {}
                    continue;
                }

                // Heading
                if (line.startsWith("#")) {
                    String heading = line.replaceFirst("^#{1,6}\\s*", "").trim();
                    try { doc.insertString(doc.getLength(), heading + "\n", headingSt); }
                    catch (BadLocationException ignored) {}
                    i++;
                    continue;
                }

                // Normal line — handle inline **bold** and `code`
                appendInlineLine(doc, line + "\n", normalSt, boldSt, codeSt);
                i++;
            }

            try { doc.insertString(doc.getLength(), "\n", normalSt); }
            catch (BadLocationException ignored) {}
            scrollToBottom();
        }

        private void appendInlineLine(StyledDocument doc, String line,
                                      Style normal, Style bold, Style code) {
            // Tokenize **bold** and `inline code`
            Pattern p = Pattern.compile("(`[^`]+`|\\*\\*[^*]+\\*\\*)");
            Matcher m = p.matcher(line);
            int last = 0;
            while (m.find()) {
                // Normal text before match
                if (m.start() > last) {
                    try { doc.insertString(doc.getLength(), line.substring(last, m.start()), normal); }
                    catch (BadLocationException ignored) {}
                }
                String token = m.group();
                Style style;
                String content;
                if (token.startsWith("`")) {
                    content = token.substring(1, token.length() - 1);
                    style = code;
                } else {
                    content = token.substring(2, token.length() - 2);
                    style = bold;
                }
                try { doc.insertString(doc.getLength(), content, style); }
                catch (BadLocationException ignored) {}
                last = m.end();
            }
            if (last < line.length()) {
                try { doc.insertString(doc.getLength(), line.substring(last), normal); }
                catch (BadLocationException ignored) {}
            }
        }

        private String renderTable(List<String> lines) {
            // Parse rows, skip separator lines (|---|)
            List<List<String>> rows = new ArrayList<>();
            for (String line : lines) {
                String stripped = line.trim();
                if (stripped.replaceAll("[|:\\- ]", "").isEmpty()) continue; // separator
                String[] parts = stripped.split("\\|", -1);
                List<String> cells = new ArrayList<>();
                for (String part : parts) {
                    String cell = part.trim();
                    // strip inline code backticks
                    cell = cell.replaceAll("`([^`]*)`", "$1");
                    // strip bold
                    cell = cell.replaceAll("\\*\\*([^*]*)\\*\\*", "$1");
                    cells.add(cell);
                }
                // Remove leading/trailing empty cells from outer pipes
                if (!cells.isEmpty() && cells.get(0).isEmpty()) cells.remove(0);
                if (!cells.isEmpty() && cells.get(cells.size() - 1).isEmpty()) cells.remove(cells.size() - 1);
                if (!cells.isEmpty()) rows.add(cells);
            }
            if (rows.isEmpty()) return String.join("\n", lines) + "\n";

            int cols = rows.stream().mapToInt(List::size).max().orElse(0);
            int[] w = new int[cols];
            for (List<String> row : rows)
                for (int i = 0; i < row.size(); i++)
                    w[i] = Math.max(w[i], row.get(i).length());

            StringBuilder sb = new StringBuilder("\n");
            String hr = buildHr(w, "├", "┼", "┤", "─");
            // Top border
            sb.append(buildHr(w, "┌", "┬", "┐", "─")).append("\n");
            for (int r = 0; r < rows.size(); r++) {
                sb.append("│");
                List<String> row = rows.get(r);
                for (int c = 0; c < cols; c++) {
                    String cell = c < row.size() ? row.get(c) : "";
                    sb.append(" ").append(cell);
                    sb.append(" ".repeat(w[c] - cell.length()));
                    sb.append(" │");
                }
                sb.append("\n");
                if (r == 0 && rows.size() > 1) sb.append(hr).append("\n");
            }
            sb.append(buildHr(w, "└", "┴", "┘", "─")).append("\n");
            return sb.toString();
        }

        private String buildHr(int[] w, String l, String m, String r, String fill) {
            StringBuilder sb = new StringBuilder(l);
            for (int i = 0; i < w.length; i++) {
                sb.append(fill.repeat(w[i] + 2));
                sb.append(i < w.length - 1 ? m : r);
            }
            return sb.toString();
        }

        // ---- Mark vulnerable requests in HTTP History --------------

        private void markVulnerableInHistory(String claudeResponse) {
            if (claudeResponse == null || claudeResponse.isBlank()) return;
            try {
                // Extract (path → vuln context window) pairs so we can colour by type
                Pattern p = Pattern.compile(
                    "(?:^|\\s)(GET|POST|PUT|DELETE|PATCH|HEAD)\\s+(/[\\w/{}\\-_.?=&%]+)",
                    Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);
                Matcher m = p.matcher(claudeResponse);

                // path → colour (first match wins)
                Map<String, HighlightColor> pathColors = new LinkedHashMap<>();
                Map<String, String>         pathNotes  = new LinkedHashMap<>();

                while (m.find()) {
                    String path = m.group(2).toLowerCase().split("\\?")[0];
                    path = path.replaceAll(
                        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}");
                    if (pathColors.containsKey(path)) continue;

                    // Grab ±400 chars around the match as context for classification
                    int start = Math.max(0, m.start() - 400);
                    int end   = Math.min(claudeResponse.length(), m.end() + 400);
                    String ctx = claudeResponse.substring(start, end);

                    HighlightColor color = classifyVulnColor(ctx);
                    String note         = classifyVulnNote(ctx);
                    pathColors.put(path, color);
                    pathNotes.put(path, note);
                }

                if (pathColors.isEmpty()) return;

                // Counters per type
                Map<HighlightColor, Integer> counts = new LinkedHashMap<>();

                for (ProxyHttpRequestResponse rr : api.proxy().history()) {
                    String reqPath = rr.request().url().toLowerCase().split("\\?")[0];
                    reqPath = reqPath.replaceAll(
                        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}");

                    for (Map.Entry<String, HighlightColor> entry : pathColors.entrySet()) {
                        String normVp = entry.getKey();
                        if (reqPath.contains(normVp) || reqPath.endsWith(normVp)) {
                            HighlightColor c = entry.getValue();
                            rr.annotations().setHighlightColor(c);
                            rr.annotations().setNotes("⚠ ClaudeTab: " + pathNotes.get(normVp));
                            counts.merge(c, 1, Integer::sum);
                            break;
                        }
                    }
                }

                if (!counts.isEmpty()) {
                    StringBuilder summary = new StringBuilder("HTTP History marked:\n");
                    counts.forEach((c, n) -> summary.append("  ")
                        .append(colorEmoji(c)).append(" ").append(n)
                        .append("x ").append(colorLabel(c)).append("\n"));
                    summary.append("\nLegend: ")
                        .append("🔴 Injection  🔵 IDOR/BAC  🟠 SSRF  🟣 Auth/Session  ")
                        .append("🟡 Info Disclosure  🩵 CORS/Headers  ⬛ Other");
                    final String msg = summary.toString();
                    SwingUtilities.invokeLater(() -> appendMessage("system", msg));
                }
            } catch (Exception ex) {
                logging.logToError("[ClaudeTab] markVulnerableInHistory error: " + ex.getMessage());
            }
        }

        private HighlightColor classifyVulnColor(String ctx) {
            String s = ctx.toLowerCase();
            if (s.matches("(?s).*(sql.?inject|sqli|xss|cross.site.script|ssti|template.inject|command.inject|rce|remote.code|os.command|path.travers|lfi|rfi|log.inject|header.inject).*"))
                return HighlightColor.RED;
            if (s.matches("(?s).*(\\bidor\\b|broken.access|bac|unauthorized|access.control|privilege.escal|object.ref|insecure.direct).*"))
                return HighlightColor.BLUE;
            if (s.matches("(?s).*(ssrf|server.side.request|open.redirect|internal.network|metadata.endpoint).*"))
                return HighlightColor.ORANGE;
            if (s.matches("(?s).*(auth|session|token|jwt|password|credential|login.bypass|broken.auth|2fa|mfa).*"))
                return HighlightColor.MAGENTA;
            if (s.matches("(?s).*(information.disclosure|sensitive.data|leak|exposure|secret|api.key|stack.trace|debug|verbose).*"))
                return HighlightColor.YELLOW;
            if (s.matches("(?s).*(cors|content.security|csp|x-frame|clickjack|security.header|hsts|missing.header).*"))
                return HighlightColor.CYAN;
            return HighlightColor.GRAY;
        }

        private String classifyVulnNote(String ctx) {
            String s = ctx.toLowerCase();
            if (s.matches("(?s).*(sql.?inject|sqli).*"))        return "SQL Injection";
            if (s.matches("(?s).*(xss|cross.site.script).*"))  return "XSS";
            if (s.matches("(?s).*(ssti|template.inject).*"))    return "SSTI";
            if (s.matches("(?s).*(command.inject|rce|os.command).*")) return "Command Injection";
            if (s.matches("(?s).*(path.travers|lfi|rfi).*"))   return "Path Traversal";
            if (s.matches("(?s).*(\\bidor\\b|object.ref).*"))  return "IDOR";
            if (s.matches("(?s).*(broken.access|bac|access.control|privilege).*")) return "Broken Access Control";
            if (s.matches("(?s).*(ssrf).*"))                    return "SSRF";
            if (s.matches("(?s).*(open.redirect).*"))           return "Open Redirect";
            if (s.matches("(?s).*(auth|session|token|jwt).*")) return "Auth/Session Issue";
            if (s.matches("(?s).*(cors).*"))                    return "CORS Misconfiguration";
            if (s.matches("(?s).*(clickjack|x-frame).*"))      return "Clickjacking";
            if (s.matches("(?s).*(secret|api.key|leak).*"))    return "Sensitive Data Exposure";
            return "Potential Vulnerability";
        }

        private String colorEmoji(HighlightColor c) {
            switch (c) {
                case RED:     return "🔴";
                case BLUE:    return "🔵";
                case ORANGE:  return "🟠";
                case MAGENTA: return "🟣";
                case YELLOW:  return "🟡";
                case CYAN:    return "🩵";
                default:      return "⬛";
            }
        }

        private String colorLabel(HighlightColor c) {
            switch (c) {
                case RED:     return "Injection";
                case BLUE:    return "IDOR/BAC";
                case ORANGE:  return "SSRF/Redirect";
                case MAGENTA: return "Auth/Session";
                case YELLOW:  return "Info Disclosure";
                case CYAN:    return "CORS/Headers";
                default:      return "Other";
            }
        }

        // ---- Send selection to Repeater ----------------------------

        private void tryParseAndSendToRepeater(String text) {
            String[] lines = text.replace("\r\n", "\n").split("\n");
            if (lines.length < 2) {
                appendMessage("system", "Select a raw HTTP request block (at least request line + Host header).");
                return;
            }
            Matcher firstLine = Pattern.compile(
                "^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+(\\S+)\\s+HTTP/[\\d.]+",
                Pattern.CASE_INSENSITIVE).matcher(lines[0].trim());
            if (!firstLine.find()) {
                appendMessage("system", "Selection doesn't look like an HTTP request. Start from the request line: GET /path HTTP/1.1");
                return;
            }
            String method = firstLine.group(1).toUpperCase();
            String path   = firstLine.group(2);

            String host = null;
            boolean secure = false;
            for (String l : lines) {
                if (l.toLowerCase().startsWith("host:")) {
                    host = l.substring(5).trim();
                }
                if (l.toLowerCase().contains("https://")) secure = true;
            }
            if (host == null) {
                appendMessage("system", "No Host header found in selection.");
                return;
            }

            // Split host:port if present in Host header (e.g. localhost:8888)
            String hostname = host;
            int parsedPort = -1;
            if (host.contains(":")) {
                String[] parts = host.split(":", 2);
                hostname = parts[0];
                try { parsedPort = Integer.parseInt(parts[1].trim()); } catch (Exception ignored) {}
            }

            // Infer https from existing proxy history context
            final String hostFinal = hostname;
            boolean inferSecure = secure || api.proxy().history().stream().anyMatch(rr -> {
                try { return rr.request().httpService().host().equalsIgnoreCase(hostFinal)
                           && rr.request().httpService().secure(); }
                catch (Exception e) { return false; }
            });

            int port = parsedPort > 0 ? parsedPort : (inferSecure ? 443 : 80);
            try {
                burp.api.montoya.http.HttpService svc =
                    burp.api.montoya.http.HttpService.httpService(hostname, port, inferSecure);
                // Ensure CRLF line endings for HTTP
                String rawRequest = String.join("\r\n", lines);
                burp.api.montoya.core.ByteArray rawBytes =
                    burp.api.montoya.core.ByteArray.byteArray(rawRequest.getBytes(StandardCharsets.UTF_8));
                HttpRequest req = HttpRequest.httpRequest(svc, rawBytes);
                api.repeater().sendToRepeater(req, "Claude: " + method + " " + path);
                appendMessage("system", "Sent to Repeater → " + method + " " + path + " (" + host + ")");
            } catch (Exception ex) {
                appendMessage("error", "Repeater send failed: " + ex.getMessage());
            }
        }

        // ---- Load proxy history into context -----------------------

        private void loadProxyHistory() {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (history.isEmpty()) {
                appendMessage("system", "No proxy history captured yet. Browse a target first.");
                return;
            }

            // Scan ALL history — deduplicate by host + method + path
            Map<String, String> seen = new LinkedHashMap<>();
            StringBuilder sb = new StringBuilder();
            for (ProxyHttpRequestResponse rr : history) {
                HttpRequest req  = rr.request();
                String host = req.httpService() != null ? req.httpService().host() : "";
                String path = req.url().split("\\?")[0];
                path = path.replaceAll("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}");
                String key = host + "|" + req.method() + "|" + path;
                if (seen.containsKey(key)) continue;

                List<String> params = new ArrayList<>();
                for (var p : req.parameters()) { if (!params.contains(p.name())) params.add(p.name()); }
                int status = rr.response() != null ? rr.response().statusCode() : 0;
                String line = String.format("%-6s %-70s [%d]", req.method(), host + path, status)
                    + (params.isEmpty() ? "" : "  params:[" + String.join(",", params) + "]") + "\n";
                seen.put(key, line);
                sb.append(line);
            }

            pendingContext = "[FULL PROXY HISTORY — " + seen.size() + " unique endpoints]\n\n" + sb;
            appendMessage("system", "Loaded " + seen.size() + " unique endpoints into context. Now ask Claude anything.");
            setStatus("History loaded (" + seen.size() + " endpoints)");
        }

        // ---- Load scanner issues into context ----------------------

        private void loadScannerIssues() {
            List<AuditIssue> issues = api.siteMap().issues();
            if (issues.isEmpty()) {
                appendMessage("system", "No scanner issues found yet. Run a scan first.");
                return;
            }

            StringBuilder sb = new StringBuilder();
            sb.append("[BURP SCANNER ISSUES - ").append(issues.size()).append(" total]\n\n");
            for (AuditIssue issue : issues) {
                sb.append(String.format("[%s] %s\n  URL: %s\n  Confidence: %s\n  Detail: %s\n\n",
                    issue.severity(), issue.name(), issue.baseUrl(),
                    issue.confidence(),
                    issue.detail() != null ? issue.detail().substring(0, Math.min(200, issue.detail().length())) : ""));
            }

            pendingContext = sb.toString();
            appendMessage("system",
                "Loaded " + issues.size() + " scanner issues into context. Ask Claude to validate or prioritize them.");
            setStatus("Issues loaded (" + issues.size() + ")");
        }

        // ---- Claude API call ---------------------------------------

        private String buildLiveContext() {
            StringBuilder ctx = new StringBuilder();

            // Inject engagement brief / CLAUDE.md content
            String brief = targetContextArea.getText().trim();
            if (!brief.isEmpty() && !brief.startsWith("Engagement brief:")) {
                ctx.append("[ENGAGEMENT BRIEF]\n").append(brief).append("\n\n");
            }

            // Inject session role labels summary
            if (!sessionLabels.isEmpty()) {
                ctx.append("[SESSION ROLE LABELS]\n");
                sessionLabels.forEach((k, v) -> ctx.append("  ").append(v).append(": ").append(k).append("\n"));
                ctx.append("\n");
            }

            // ---------------------------------------------------------------
            // Build unified endpoint map from BOTH proxy history + site map
            // Deduplicates by normalised path pattern (IDs → {id}, UUIDs → {uuid})
            // ---------------------------------------------------------------
            List<ProxyHttpRequestResponse> history;
            try {
                history = api.proxy().history();
                logging.logToOutput("[ClaudeTab] proxy history size: " + history.size());
            } catch (Exception e) {
                logging.logToError("[ClaudeTab] Failed to read proxy history: " + e.getMessage());
                history = new ArrayList<>();
            }

            // Collect site map request/responses (returns all nodes Burp has seen)
            List<burp.api.montoya.http.message.HttpRequestResponse> siteMapItems = new ArrayList<>();
            try {
                siteMapItems = api.siteMap().requestResponses();
                logging.logToOutput("[ClaudeTab] site map size: " + siteMapItems.size());
            } catch (Exception e) {
                logging.logToOutput("[ClaudeTab] Site map not readable via requestResponses(), using proxy history only");
            }

            // Check if scope is configured
            boolean scopeActive = false;
            for (ProxyHttpRequestResponse rr : history) {
                try { if (api.scope().isInScope(rr.request().url())) { scopeActive = true; break; } }
                catch (Exception ignored) {}
            }

            // Normalise path: replace numeric IDs and UUIDs with placeholders
            java.util.function.Function<String, String> normPath = (raw) -> {
                String p = raw.split("\\?")[0];
                p = p.replaceAll("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "{uuid}");
                p = p.replaceAll("(?<=/)[0-9]{1,10}(?=/|$)", "{id}");
                return p;
            };

            // Helper: build context entry from a request/response pair
            java.util.function.BiFunction<HttpRequest, HttpResponse, StringBuilder> buildEntry = (req, resp) -> {
                String host = req.httpService() != null ? req.httpService().host() : "";
                String normalisedPath = normPath.apply(req.url());
                List<String> params = new ArrayList<>();
                for (var p : req.parameters()) { if (!params.contains(p.name())) params.add(p.name()); }
                int status = resp != null ? resp.statusCode() : 0;
                String roleLabel = sessionLabels.get(host + "|" + normalisedPath);

                StringBuilder entry = new StringBuilder();
                entry.append(String.format("%-6s %s%s [%d]", req.method(), host, normalisedPath, status));
                if (roleLabel != null) entry.append("  [role:").append(roleLabel).append("]");
                if (!params.isEmpty()) entry.append("  params:[").append(String.join(",", params)).append("]");

                if (resp != null) {
                    List<String> secHdrs = new ArrayList<>();
                    for (var h : resp.headers()) {
                        String hn = h.name().toLowerCase();
                        if (hn.equals("access-control-allow-origin") || hn.equals("access-control-allow-credentials")
                         || hn.equals("set-cookie") || hn.equals("content-security-policy")
                         || hn.equals("server") || hn.equals("x-powered-by")
                         || hn.equals("location") || hn.equals("www-authenticate")) {
                            secHdrs.add(h.name() + ": " + h.value());
                        }
                    }
                    if (!secHdrs.isEmpty()) entry.append("\n    resp_headers:[").append(String.join(" | ", secHdrs)).append("]");
                    String reqBody = req.bodyToString();
                    if (reqBody != null && !reqBody.isBlank()) {
                        String s = reqBody.length() > 200 ? reqBody.substring(0, 200) + "..." : reqBody;
                        entry.append("\n    req_body:").append(s.replace("\n", " "));
                    }
                    String respBody = resp.bodyToString();
                    if (respBody != null && !respBody.isBlank()) {
                        String s = respBody.length() > 300 ? respBody.substring(0, 300) + "..." : respBody;
                        entry.append("\n    resp_body:").append(s.replace("\n", " "));
                    }
                }
                entry.append("\n");
                return entry;
            };

            // Merged deduplication map: key = host|METHOD|normalisedPath
            Map<String, StringBuilder> seen = new LinkedHashMap<>();

            // 1. Process proxy history first (most complete — has full req+resp)
            for (ProxyHttpRequestResponse rr : history) {
                try {
                    HttpRequest req = rr.request(); HttpResponse resp = rr.response();
                    if (scopeActive && !api.scope().isInScope(req.url())) continue;
                    String key = req.httpService().host() + "|" + req.method() + "|" + normPath.apply(req.url());
                    if (!seen.containsKey(key)) seen.put(key, buildEntry.apply(req, resp));
                } catch (Exception ignored) {}
            }

            // 2. Add site map entries not already seen from proxy history
            for (burp.api.montoya.http.message.HttpRequestResponse rr : siteMapItems) {
                try {
                    HttpRequest req = rr.request(); HttpResponse resp = rr.response();
                    if (req == null) continue;
                    if (scopeActive && !api.scope().isInScope(req.url())) continue;
                    String key = req.httpService().host() + "|" + req.method() + "|" + normPath.apply(req.url());
                    if (!seen.containsKey(key)) seen.put(key, buildEntry.apply(req, resp));
                } catch (Exception ignored) {}
            }

            logging.logToOutput("[ClaudeTab] total unique endpoints (proxy+sitemap): " + seen.size());

            if (!seen.isEmpty()) {
                StringBuilder endpoints = new StringBuilder();
                seen.values().forEach(endpoints::append);
                ctx.append("[SITE MAP + PROXY — ").append(seen.size()).append(" unique endpoints]\n");
                ctx.append(endpoints);
            }

            // Auto-inject scanner issues if any exist
            List<AuditIssue> issues = api.siteMap().issues();
            if (!issues.isEmpty()) {
                ctx.append("\n[BURP SCANNER — ").append(issues.size()).append(" findings]\n");
                for (AuditIssue issue : issues) {
                    ctx.append(String.format("[%s] %s — %s\n",
                        issue.severity(), issue.name(), issue.baseUrl()));
                }
            }

            return ctx.length() > 0 ? ctx.toString() : null;
        }

        private String callClaude(String apiKey, String userMessage) throws Exception {
            // Build full message — live context + any extra context (from right-click) + user question
            String liveCtx  = buildLiveContext();
            StringBuilder fullMessage = new StringBuilder();
            if (liveCtx != null) {
                fullMessage.append(liveCtx).append("\n");
            }
            if (pendingContext != null) {
                fullMessage.append(pendingContext).append("\n");
                pendingContext = null;
            }
            fullMessage.append(userMessage);

            // Add to conversation history
            Map<String, String> userMsg = new LinkedHashMap<>();
            userMsg.put("role", "user");
            userMsg.put("content", fullMessage.toString());
            conversationHistory.add(userMsg);

            // Keep last 20 turns to avoid token overflow
            List<Map<String, String>> history = conversationHistory;
            if (history.size() > 20) {
                history = history.subList(history.size() - 20, history.size());
            }

            // Build JSON payload using Gson
            Gson gson = new Gson();
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("model", "claude-opus-4-5");
            payload.put("max_tokens", 4096);
            payload.put("system",
                "You are an expert penetration tester embedded inside Burp Suite Pro. " +
                "You have LIVE access to the user's proxy history and scanner findings — they are automatically " +
                "included at the top of every message. Use them as your primary context. " +
                "Never say you don't have access to proxy history or Burp data. " +
                "Your job: identify vulnerabilities (IDOR, BAC, SSRF, injection, auth flaws) and give " +
                "actionable attack guidance with real payloads specific to the endpoints shown. " +
                "Format findings with severity: CRITICAL / HIGH / MEDIUM / LOW."
            );
            payload.put("messages", history);

            String jsonBody = gson.toJson(payload);

            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create("https://api.anthropic.com/v1/messages"))
                .header("x-api-key", apiKey)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(jsonBody))
                .timeout(java.time.Duration.ofSeconds(90))
                .build();

            java.net.http.HttpResponse<String> response = HTTP_CLIENT.send(
                request, java.net.http.HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new Exception("API error " + response.statusCode() + ": " + response.body());
            }

            JsonObject json   = JsonParser.parseString(response.body()).getAsJsonObject();
            String     result = json.getAsJsonArray("content")
                                    .get(0).getAsJsonObject()
                                    .get("text").getAsString();

            // Store assistant reply in history
            Map<String, String> assistantMsg = new LinkedHashMap<>();
            assistantMsg.put("role", "assistant");
            assistantMsg.put("content", result);
            conversationHistory.add(assistantMsg);

            return result;
        }

        // ---- UI helpers --------------------------------------------

        private void appendMessage(String type, String text) {
            StyledDocument doc = chatArea.getStyledDocument();

            // Styles
            Style base = chatArea.addStyle("base", null);
            StyleConstants.setFontFamily(base, "Monospaced");
            StyleConstants.setFontSize(base, 11);

            Style labelStyle = chatArea.addStyle("label", base);
            Style bodyStyle  = chatArea.addStyle("body",  base);

            switch (type) {
                case "user":
                    StyleConstants.setForeground(labelStyle, Color.decode("#00d2a0"));
                    StyleConstants.setForeground(bodyStyle,  Color.decode("#e0e0e0"));
                    StyleConstants.setBold(labelStyle, true);
                    appendStyled(doc, "\nYou\n", labelStyle);
                    appendStyled(doc, text + "\n", bodyStyle);
                    break;
                case "claude":
                    // Delegate to full markdown renderer
                    appendClaudeFormatted(text);
                    return; // appendClaudeFormatted handles scrolling
                case "error":
                    StyleConstants.setForeground(bodyStyle, Color.decode("#ff4444"));
                    appendStyled(doc, "\n" + text + "\n", bodyStyle);
                    break;
                default: // system
                    StyleConstants.setForeground(bodyStyle, Color.decode("#666666"));
                    StyleConstants.setItalic(bodyStyle, true);
                    appendStyled(doc, "\n" + text + "\n", bodyStyle);
                    break;
            }
            scrollToBottom();
        }

        private void appendStyled(StyledDocument doc, String text, Style style) {
            try { doc.insertString(doc.getLength(), text, style); }
            catch (BadLocationException ignored) {}
        }

        // ---- Claude Passive Scan -----------------------------------

        private void runPassiveScan() {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (history.isEmpty()) {
                appendMessage("system", "No proxy history. Browse the target first.");
                return;
            }
            setStatus("Running Claude Passive Scan...");
            appendMessage("system", "Running passive scan on " + history.size() + " requests...");

            String liveCtx = buildLiveContext();
            String prompt =
                (liveCtx != null ? liveCtx + "\n\n" : "") +
                "Perform a passive security scan on all the proxy history above. " +
                "Do NOT suggest sending requests — only analyze what is already captured. " +
                "Find vulnerabilities from: headers, URL patterns, parameters, response bodies, cookies. " +
                "Return ONLY a JSON array:\n" +
                "[{\"title\":\"CORS Misconfiguration\",\"severity\":\"HIGH\",\"confidence\":\"CERTAIN\"," +
                "\"url\":\"https://app.example.com/api\",\"detail\":\"Full technical description\"," +
                "\"remediation\":\"How to fix it\",\"evidence\":\"Exact header/value that proves it\"}]\n" +
                "severity: HIGH|MEDIUM|LOW|INFORMATION\n" +
                "confidence: CERTAIN|FIRM|TENTATIVE\n" +
                "Only include real findings with evidence from the captured traffic. Return ONLY JSON.";

            try {
                String result = callClaudeRaw(apiKeyField.getText().trim(), prompt);
                int s = result.indexOf("["), e = result.lastIndexOf("]") + 1;
                if (s < 0 || e <= s) { appendMessage("error", "No findings returned."); setStatus("Passive scan done."); return; }
                JsonArray findings = JsonParser.parseString(result.substring(s, e)).getAsJsonArray();
                int added = 0;
                for (JsonElement fe : findings) {
                    JsonObject f = fe.getAsJsonObject();
                    try {
                        AuditIssue issue = AuditIssue.auditIssue(
                            "[Claude] " + getStr(f, "title", "Finding"),
                            getStr(f, "detail", "") + "<br><br><b>Evidence:</b> " + getStr(f, "evidence", ""),
                            getStr(f, "remediation", ""),
                            getStr(f, "url", ""),
                            toSeverity(getStr(f, "severity", "MEDIUM")),
                            toConfidence(getStr(f, "confidence", "FIRM")),
                            "Identified by Claude AI passive scan via ClaudeTab",
                            "Verify manually and apply appropriate fix.",
                            toSeverity(getStr(f, "severity", "MEDIUM"))
                        );
                        api.siteMap().add(issue);
                        added++;
                    } catch (Exception ex) {
                        logging.logToError("[ClaudeTab] Failed to add issue: " + ex.getMessage());
                    }
                }
                final int count = added;
                SwingUtilities.invokeLater(() -> {
                    appendMessage("system",
                        "Passive scan complete. Added " + count + " findings to Burp Scanner tab.\n" +
                        "Check Scanner -> Issue activity to see them.");
                    setStatus("Passive scan done — " + count + " issues added to Scanner.");
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> { appendMessage("error", "Passive scan error: " + ex.getMessage()); setStatus("Error."); });
            }
        }

        // ---- Claude Active Scan ------------------------------------

        private void runActiveScan() {
            List<ProxyHttpRequestResponse> history = api.proxy().history();
            if (history.isEmpty()) {
                appendMessage("system", "No proxy history. Browse the target first.");
                return;
            }
            setStatus("Running Claude Active Scan...");
            appendMessage("system", "Identifying test candidates...");

            String liveCtx = buildLiveContext();
            // Step 1: identify candidates
            String planPrompt =
                (liveCtx != null ? liveCtx + "\n\n" : "") +
                "Identify the top 10 endpoints from the proxy history most likely to be vulnerable. " +
                "For each, generate a specific test request to confirm the vulnerability. " +
                "Return ONLY JSON array:\n" +
                "[{\"vuln_type\":\"IDOR\",\"url\":\"https://app.example.com/api/users/44bda21d\",\n" +
                "  \"method\":\"GET\",\"host\":\"app.example.com\",\"port\":443,\"https\":true,\n" +
                "  \"request_b64\":\"base64-encoded raw HTTP request with test payload\",\n" +
                "  \"confirm_if\":\"response contains user data from a different account\"}]\n" +
                "Only include endpoints where active testing makes sense. Return ONLY JSON.";

            try {
                String planResult = callClaudeRaw(apiKeyField.getText().trim(), planPrompt);
                int s = planResult.indexOf("["), e = planResult.lastIndexOf("]") + 1;
                if (s < 0 || e <= s) { appendMessage("error", "No candidates identified."); setStatus("Done."); return; }
                JsonArray candidates = JsonParser.parseString(planResult.substring(s, e)).getAsJsonArray();
                appendMessage("system", "Testing " + candidates.size() + " candidates...");

                int added = 0;
                for (JsonElement ce : candidates) {
                    JsonObject c = ce.getAsJsonObject();
                    try {
                        // Send test request through Burp
                        String reqB64 = getStr(c, "request_b64", "");
                        if (reqB64.isEmpty()) continue;

                        burp.api.montoya.http.HttpService svc = burp.api.montoya.http.HttpService.httpService(
                            getStr(c, "host", ""), toIntVal(c, "port", 443),
                            c.has("https") && c.get("https").getAsBoolean());
                        burp.api.montoya.core.ByteArray reqBytes =
                            burp.api.montoya.core.ByteArray.byteArray(
                                java.util.Base64.getDecoder().decode(reqB64));
                        HttpRequest testReq = HttpRequest.httpRequest(svc, reqBytes);
                        var testResult = api.http().sendRequest(testReq);
                        HttpResponse testResp = testResult.response();

                        if (testResp == null) continue;

                        String respBody = testResp.bodyToString();
                        String confirmIf = getStr(c, "confirm_if", "");
                        String vulnType  = getStr(c, "vuln_type", "Vulnerability");
                        String url       = getStr(c, "url", "");

                        // Step 2: ask Claude to interpret the response
                        String verifyPrompt =
                            "Test request was sent for: " + vulnType + " on " + url + "\n" +
                            "Expected confirmation: " + confirmIf + "\n" +
                            "Response status: " + testResp.statusCode() + "\n" +
                            "Response body (first 800 chars):\n" +
                            (respBody.length() > 800 ? respBody.substring(0, 800) : respBody) +
                            "\n\nIs this vulnerability CONFIRMED, POSSIBLE, or NOT_VULNERABLE? " +
                            "Reply with one word: CONFIRMED, POSSIBLE, or NOT_VULNERABLE. " +
                            "Then on the next line, one sentence of evidence.";

                        String verdict = callClaudeRaw(apiKeyField.getText().trim(), verifyPrompt).trim();
                        boolean confirmed = verdict.toUpperCase().startsWith("CONFIRMED");
                        boolean possible  = verdict.toUpperCase().startsWith("POSSIBLE");

                        if (confirmed || possible) {
                            AuditIssueSeverity sev = confirmed ? AuditIssueSeverity.HIGH : AuditIssueSeverity.MEDIUM;
                            AuditIssueConfidence conf = confirmed ? AuditIssueConfidence.CERTAIN : AuditIssueConfidence.FIRM;
                            AuditIssue issue = AuditIssue.auditIssue(
                                "[Claude Active] " + vulnType,
                                "Claude active scan verified this finding.<br><br>" +
                                "<b>Test URL:</b> " + url + "<br>" +
                                "<b>Verdict:</b> " + verdict.split("\n")[0] + "<br>" +
                                "<b>Evidence:</b> " + (verdict.contains("\n") ? verdict.split("\n")[1] : ""),
                                "Verify manually and remediate as appropriate.",
                                url,
                                sev, conf,
                                "Identified and verified by Claude AI active scan via ClaudeTab",
                                "Apply proper authorization checks and input validation.",
                                sev,
                                testResult
                            );
                            api.siteMap().add(issue);
                            added++;
                        }
                    } catch (Exception ex) {
                        logging.logToError("[ClaudeTab] Active scan test error: " + ex.getMessage());
                    }
                }

                final int count = added;
                SwingUtilities.invokeLater(() -> {
                    appendMessage("system",
                        "Active scan complete. " + count + " verified findings added to Burp Scanner tab.\n" +
                        "These are Claude-confirmed — low false positive rate.");
                    setStatus("Active scan done — " + count + " confirmed issues.");
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> { appendMessage("error", "Active scan error: " + ex.getMessage()); setStatus("Error."); });
            }
        }

        // ---- Verify existing Scanner findings ----------------------

        private void verifyScannerFindings() {
            List<AuditIssue> issues = api.siteMap().issues();
            if (issues.isEmpty()) {
                appendMessage("system", "No Burp Scanner findings yet. Run a scan first.");
                return;
            }
            setStatus("Verifying " + issues.size() + " scanner findings...");
            appendMessage("system", "Reviewing " + issues.size() + " Burp Scanner findings for false positives...");

            StringBuilder findingsText = new StringBuilder();
            for (int i = 0; i < Math.min(30, issues.size()); i++) {
                AuditIssue iss = issues.get(i);
                findingsText.append(i).append(": name=").append(iss.name())
                    .append(" | sev=").append(iss.severity())
                    .append(" | conf=").append(iss.confidence())
                    .append(" | url=").append(iss.baseUrl())
                    .append(" | detail=").append(iss.detail() != null ? iss.detail().substring(0, Math.min(200, iss.detail().length())) : "")
                    .append("\n");
            }

            String prompt =
                "Review these Burp Scanner findings and classify each:\n\n" + findingsText +
                "\nFor each finding by index, respond with:\n" +
                "TRUE_POSITIVE — genuinely exploitable\n" +
                "FALSE_POSITIVE — not actually vulnerable (common Burp FPs: HTTP request smuggling on HTTP/2, " +
                "stored XSS without confirmed reflection, SQLi on integer params with same responses)\n" +
                "NEEDS_MANUAL — requires manual confirmation\n\n" +
                "Return ONLY JSON: [{\"index\":0,\"verdict\":\"TRUE_POSITIVE\",\"reason\":\"brief explanation\"}]";

            try {
                String result = callClaudeRaw(apiKeyField.getText().trim(), prompt);
                int s = result.indexOf("["), e = result.lastIndexOf("]") + 1;
                if (s < 0) { appendMessage("error", "Failed to parse response."); return; }
                JsonArray verdicts = JsonParser.parseString(result.substring(s, e)).getAsJsonArray();

                int tpCount = 0, fpCount = 0, manualCount = 0;
                StringBuilder summary = new StringBuilder("Scanner Verification Results:\n\n");

                for (JsonElement ve : verdicts) {
                    JsonObject v = ve.getAsJsonObject();
                    int idx = v.has("index") ? v.get("index").getAsInt() : -1;
                    String verdict = getStr(v, "verdict", "");
                    String reason  = getStr(v, "reason", "");

                    if (idx >= 0 && idx < issues.size()) {
                        AuditIssue iss = issues.get(idx);
                        String label;
                        if ("FALSE_POSITIVE".equals(verdict)) {
                            fpCount++;
                            label = "[FALSE POSITIVE]";
                            // Add back as FALSE_POSITIVE severity so it's visible in Burp
                            AuditIssue marked = AuditIssue.auditIssue(
                                "[FP] " + iss.name(),
                                "Claude verified as FALSE POSITIVE: " + reason,
                                "No remediation needed.",
                                iss.baseUrl(),
                                AuditIssueSeverity.FALSE_POSITIVE,
                                AuditIssueConfidence.CERTAIN,
                                "Verified false positive by ClaudeTab",
                                "No action required.", AuditIssueSeverity.FALSE_POSITIVE);
                            api.siteMap().add(marked);
                        } else if ("TRUE_POSITIVE".equals(verdict)) {
                            tpCount++;
                            label = "[CONFIRMED]";
                        } else {
                            manualCount++;
                            label = "[MANUAL]";
                        }
                        summary.append(label).append(" ").append(iss.name())
                               .append(" — ").append(iss.baseUrl()).append("\n")
                               .append("  Reason: ").append(reason).append("\n\n");
                    }
                }

                summary.append("Summary: ").append(tpCount).append(" confirmed, ")
                       .append(fpCount).append(" false positives, ")
                       .append(manualCount).append(" need manual review.");

                final String sumStr  = summary.toString();
                final int finalTp   = tpCount;
                final int finalFp   = fpCount;
                SwingUtilities.invokeLater(() -> {
                    appendMessage("claude", sumStr);
                    setStatus("Verification done — " + finalTp + " real, " + finalFp + " FP.");
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> { appendMessage("error", "Verify error: " + ex.getMessage()); setStatus("Error."); });
            }
        }

        private AuditIssueSeverity toSeverity(String s) {
            switch (s.toUpperCase()) {
                case "HIGH":    return AuditIssueSeverity.HIGH;
                case "MEDIUM":  return AuditIssueSeverity.MEDIUM;
                case "LOW":     return AuditIssueSeverity.LOW;
                default:        return AuditIssueSeverity.INFORMATION;
            }
        }

        private AuditIssueConfidence toConfidence(String s) {
            switch (s.toUpperCase()) {
                case "CERTAIN": return AuditIssueConfidence.CERTAIN;
                case "FIRM":    return AuditIssueConfidence.FIRM;
                default:        return AuditIssueConfidence.TENTATIVE;
            }
        }

        private int toIntVal(JsonObject o, String key, int def) {
            return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsInt() : def;
        }

        private void runInThread(Runnable fn) {
            showStopButton(true);
            ExecutorService ex = Executors.newSingleThreadExecutor();
            ex.submit(() -> {
                try { fn.run(); } catch (Exception e) { e.printStackTrace(); }
                showStopButton(false);
                ex.shutdown();
            });
        }

        private void exportReport() {
            if (conversationHistory.isEmpty()) {
                appendMessage("system", "No conversation to export. Run a scan first.");
                return;
            }
            setStatus("Generating report...");
            ExecutorService exec = Executors.newSingleThreadExecutor();
            exec.submit(() -> {
                try {
                    String apiKey = apiKeyField.getText().trim();
                    // Ask Claude to format findings as structured JSON for the report
                    String reportPrompt =
                        "Based on our entire conversation, generate a professional penetration test report. " +
                        "Return ONLY a valid JSON object with this exact structure:\n" +
                        "{\n" +
                        "  \"target\": \"target name/domain\",\n" +
                        "  \"date\": \"" + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")) + "\",\n" +
                        "  \"executive_summary\": \"2-3 sentence overview\",\n" +
                        "  \"findings\": [\n" +
                        "    {\n" +
                        "      \"id\": \"F1\",\n" +
                        "      \"title\": \"Finding title\",\n" +
                        "      \"severity\": \"CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL\",\n" +
                        "      \"cvss_score\": \"9.8\",\n" +
                        "      \"cvss_vector\": \"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H\",\n" +
                        "      \"owasp\": \"A01:2021 - Broken Access Control\",\n" +
                        "      \"mitre\": \"T1078 - Valid Accounts\",\n" +
                        "      \"affected_asset\": \"GET /api/users/{id} — app.example.com\",\n" +
                        "      \"status\": \"Open\",\n" +
                        "      \"summary\": \"Detailed description of the vulnerability\",\n" +
                        "      \"poc\": \"Step-by-step proof of concept with HTTP request\",\n" +
                        "      \"impact\": \"Business and technical impact description\",\n" +
                        "      \"recommendation\": \"Specific remediation steps\"\n" +
                        "    }\n" +
                        "  ]\n" +
                        "}\n" +
                        "Include ALL findings from our analysis. Calculate accurate CVSS 3.1 scores. " +
                        "Return ONLY the JSON, no markdown, no explanation.";

                    // Use Claude but bypass conversation history injection for clean output
                    String raw = callClaudeRaw(apiKey, reportPrompt);

                    // Extract JSON
                    int s = raw.indexOf("{");
                    int e2 = raw.lastIndexOf("}") + 1;
                    if (s < 0 || e2 <= s) throw new Exception("No JSON in response");
                    String jsonStr = raw.substring(s, e2);

                    JsonObject report = JsonParser.parseString(jsonStr).getAsJsonObject();
                    String html = buildHtmlReport(report);

                    // Save to file
                    JFileChooser fc = new JFileChooser();
                    fc.setDialogTitle("Save Pentest Report");
                    fc.setSelectedFile(new File("pentest-report-" +
                        LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")) + ".html"));
                    SwingUtilities.invokeAndWait(() -> {
                        int result = fc.showSaveDialog(ChatPanel.this);
                        if (result == JFileChooser.APPROVE_OPTION) {
                            try {
                                File file = fc.getSelectedFile();
                                Files.writeString(file.toPath(), html, StandardCharsets.UTF_8);
                                Desktop.getDesktop().browse(file.toURI());
                                appendMessage("system", "Report exported: " + file.getAbsolutePath());
                                setStatus("Report saved.");
                            } catch (Exception ex) {
                                appendMessage("error", "Failed to save: " + ex.getMessage());
                            }
                        }
                    });
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> {
                        appendMessage("error", "Export failed: " + ex.getMessage());
                        setStatus("Export failed.");
                    });
                }
                exec.shutdown();
            });
        }

        private String callClaudeRaw(String apiKey, String userMessage) throws Exception {
            Gson gson = new Gson();
            Map<String, Object> payload = new LinkedHashMap<>();
            // Use Haiku for report generation — 5-10x faster, same structured JSON output
            payload.put("model", "claude-haiku-4-5");
            payload.put("max_tokens", 8000);
            payload.put("system",
                "You are a professional penetration tester writing formal security reports. " +
                "When asked for JSON, return ONLY valid JSON with no markdown code blocks or extra text.");
            // Include full conversation as context
            List<Map<String, String>> msgs = new ArrayList<>(conversationHistory);
            Map<String, String> userMsg = new LinkedHashMap<>();
            userMsg.put("role", "user");
            userMsg.put("content", userMessage);
            msgs.add(userMsg);
            payload.put("messages", msgs);

            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create("https://api.anthropic.com/v1/messages"))
                .header("x-api-key", apiKey)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(gson.toJson(payload)))
                .timeout(java.time.Duration.ofSeconds(120))
                .build();

            java.net.http.HttpResponse<String> response = HTTP_CLIENT.send(
                request, java.net.http.HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200)
                throw new Exception("API error " + response.statusCode());
            JsonObject json = JsonParser.parseString(response.body()).getAsJsonObject();
            return json.getAsJsonArray("content").get(0).getAsJsonObject().get("text").getAsString();
        }

        private String buildHtmlReport(JsonObject report) {
            String target  = getStr(report, "target", "Target Application");
            String date    = getStr(report, "date", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd")));
            String summary = getStr(report, "executive_summary", "");
            JsonArray findings = report.has("findings") ? report.getAsJsonArray("findings") : new JsonArray();

            StringBuilder sb = new StringBuilder();
            sb.append("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
              .append("<title>Penetration Test Report — ").append(esc(target)).append("</title>")
              .append("<style>")
              .append("*{box-sizing:border-box;margin:0;padding:0}")
              .append("body{font-family:'Segoe UI',Arial,sans-serif;font-size:13px;color:#222;background:#f5f5f5}")
              .append(".page{max-width:1100px;margin:0 auto;background:#fff;padding:40px;box-shadow:0 0 20px rgba(0,0,0,.1)}")
              .append("h1{font-size:24px;color:#1a1a2e;margin-bottom:4px}")
              .append("h2{font-size:18px;color:#1a1a2e;margin:32px 0 12px;border-bottom:2px solid #e0e0e0;padding-bottom:6px}")
              .append("h3{font-size:15px;color:#1a1a2e;margin:24px 0 10px}")
              .append(".meta{color:#666;font-size:12px;margin-bottom:24px}")
              .append(".exec-summary{background:#f8f9fa;border-left:4px solid #1a73e8;padding:16px 20px;margin:20px 0;border-radius:0 6px 6px 0}")
              .append(".finding{background:#fff;border:1px solid #e0e0e0;border-radius:8px;margin:24px 0;overflow:hidden;page-break-inside:avoid}")
              .append(".finding-header{padding:14px 20px;display:flex;align-items:center;gap:12px}")
              .append(".finding-id{font-weight:700;font-size:13px;color:#fff;background:#555;padding:3px 10px;border-radius:4px}")
              .append(".finding-title{font-weight:600;font-size:15px;flex:1}")
              .append(".severity-badge{padding:4px 12px;border-radius:4px;font-weight:700;font-size:12px;color:#fff}")
              .append(".CRITICAL{background:#c0392b}.HIGH{background:#e67e22}.MEDIUM{background:#f39c12;color:#333}")
              .append(".LOW{background:#27ae60}.INFORMATIONAL{background:#3498db}")
              .append(".meta-table{width:100%;border-collapse:collapse;margin:0}")
              .append(".meta-table td{padding:8px 16px;border-bottom:1px solid #eee;font-size:12px}")
              .append(".meta-table td:first-child{font-weight:600;width:180px;background:#fafafa;color:#555}")
              .append(".finding-body{padding:20px}")
              .append(".finding-body h3{font-size:13px;font-weight:700;color:#333;margin:16px 0 8px;text-transform:uppercase;letter-spacing:.5px}")
              .append(".finding-body h3:first-child{margin-top:0}")
              .append(".finding-body p{line-height:1.7;color:#444;margin-bottom:10px}")
              .append("pre{background:#1e1e1e;color:#d4d4d4;padding:14px 16px;border-radius:6px;font-size:11px;overflow-x:auto;line-height:1.6;margin:10px 0}")
              .append("ul{padding-left:20px;line-height:1.9;color:#444}")
              .append(".cvss{font-family:monospace;font-size:11px;color:#666;margin-top:2px}")
              .append(".toc{background:#f8f9fa;border:1px solid #e0e0e0;border-radius:8px;padding:16px 24px;margin:20px 0}")
              .append(".toc ul{list-style:none;padding:0}.toc li{padding:4px 0;border-bottom:1px solid #eee}")
              .append(".toc li:last-child{border:0}.toc a{text-decoration:none;color:#1a73e8}")
              .append(".sev-CRITICAL{color:#c0392b;font-weight:700}.sev-HIGH{color:#e67e22;font-weight:700}")
              .append(".sev-MEDIUM{color:#f39c12;font-weight:700}.sev-LOW{color:#27ae60}.sev-INFORMATIONAL{color:#3498db}")
              .append("@media print{body{background:#fff}.page{box-shadow:none;padding:20px}}")
              .append("</style></head><body><div class='page'>")
              // Cover
              .append("<h1>Penetration Test Report</h1>")
              .append("<div class='meta'>Target: <strong>").append(esc(target)).append("</strong>")
              .append(" &nbsp;|&nbsp; Date: <strong>").append(esc(date)).append("</strong>")
              .append(" &nbsp;|&nbsp; Generated by: <strong>ClaudeTab</strong></div>")
              // Executive Summary
              .append("<h2>Executive Summary</h2>")
              .append("<div class='exec-summary'>").append(esc(summary)).append("</div>");

            // Stats bar
            int crit=0, high=0, med=0, low=0, info=0;
            for (JsonElement fe : findings) {
                switch (getStr(fe.getAsJsonObject(),"severity","").toUpperCase()) {
                    case "CRITICAL": crit++; break; case "HIGH": high++; break;
                    case "MEDIUM": med++; break; case "LOW": low++; break; default: info++;
                }
            }
            sb.append("<h2>Finding Summary</h2>")
              .append("<table style='width:100%;border-collapse:collapse;margin:12px 0'>")
              .append("<tr style='background:#1a1a2e;color:#fff'>")
              .append("<th style='padding:10px;text-align:center'>CRITICAL</th>")
              .append("<th style='padding:10px;text-align:center'>HIGH</th>")
              .append("<th style='padding:10px;text-align:center'>MEDIUM</th>")
              .append("<th style='padding:10px;text-align:center'>LOW</th>")
              .append("<th style='padding:10px;text-align:center'>INFO</th></tr>")
              .append("<tr>")
              .append("<td style='padding:14px;text-align:center;font-size:22px;font-weight:700;color:#c0392b'>").append(crit).append("</td>")
              .append("<td style='padding:14px;text-align:center;font-size:22px;font-weight:700;color:#e67e22'>").append(high).append("</td>")
              .append("<td style='padding:14px;text-align:center;font-size:22px;font-weight:700;color:#f39c12'>").append(med).append("</td>")
              .append("<td style='padding:14px;text-align:center;font-size:22px;font-weight:700;color:#27ae60'>").append(low).append("</td>")
              .append("<td style='padding:14px;text-align:center;font-size:22px;font-weight:700;color:#3498db'>").append(info).append("</td>")
              .append("</tr></table>");

            // ToC
            sb.append("<h2>Table of Contents</h2><div class='toc'><ul>");
            int idx = 1;
            for (JsonElement fe : findings) {
                JsonObject f = fe.getAsJsonObject();
                String sev = getStr(f,"severity","INFO").toUpperCase();
                String title = getStr(f,"title","Finding");
                String fid = getStr(f,"id","F" + idx);
                sb.append("<li><a href='#").append(fid).append("'>")
                  .append(fid).append(". ").append(esc(title))
                  .append(" <span class='sev-").append(sev).append("'>[").append(sev).append("]</span>")
                  .append("</a></li>");
                idx++;
            }
            sb.append("</ul></div>");

            // Findings
            sb.append("<h2>Findings</h2>");
            for (JsonElement fe : findings) {
                JsonObject f = fe.getAsJsonObject();
                String sev      = getStr(f,"severity","INFO").toUpperCase();
                String fid      = getStr(f,"id","F" + idx);
                String title    = getStr(f,"title","");
                String cvssScore = getStr(f,"cvss_score","N/A");
                String cvssVec   = getStr(f,"cvss_vector","");
                String owasp     = getStr(f,"owasp","");
                String mitre     = getStr(f,"mitre","");
                String asset     = getStr(f,"affected_asset","");
                String status    = getStr(f,"status","Open");
                String summary2  = getStr(f,"summary","");
                String poc       = getStr(f,"poc","");
                String impact    = getStr(f,"impact","");
                String rec       = getStr(f,"recommendation","");

                sb.append("<div class='finding' id='").append(fid).append("'>")
                  .append("<div class='finding-header' style='background:")
                  .append(sevColor(sev)).append("20;border-bottom:3px solid ").append(sevColor(sev)).append("'>")
                  .append("<span class='finding-id'>").append(esc(fid)).append("</span>")
                  .append("<span class='finding-title'>").append(esc(title)).append("</span>")
                  .append("<span class='severity-badge ").append(sev).append("'>").append(sev).append("</span>")
                  .append("</div>")
                  // Meta table
                  .append("<table class='meta-table'>")
                  .append("<tr><td>Affected Asset</td><td>").append(esc(asset)).append("</td></tr>")
                  .append("<tr><td>Severity</td><td><span class='severity-badge ").append(sev).append("'>").append(sev).append("</span></td></tr>")
                  .append("<tr><td>CVSS 3.1 Score</td><td><strong>").append(esc(cvssScore)).append("</strong>")
                  .append(cvssVec.isEmpty() ? "" : "<br><span class='cvss'>" + esc(cvssVec) + "</span>")
                  .append("</td></tr>");
                if (!owasp.isEmpty())  sb.append("<tr><td>OWASP Category</td><td>").append(esc(owasp)).append("</td></tr>");
                if (!mitre.isEmpty())  sb.append("<tr><td>MITRE ATT&CK</td><td>").append(esc(mitre)).append("</td></tr>");
                sb.append("<tr><td>Status</td><td><span style='background:").append("Open".equals(status)?"#e74c3c":"#27ae60")
                  .append(";color:#fff;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700'>")
                  .append(esc(status)).append("</span></td></tr>")
                  .append("</table>")
                  // Body
                  .append("<div class='finding-body'>")
                  .append("<h3>Summary</h3><p>").append(esc(summary2)).append("</p>");
                if (!poc.isEmpty())
                    sb.append("<h3>Proof of Concept</h3><pre>").append(esc(poc)).append("</pre>");
                if (!impact.isEmpty())
                    sb.append("<h3>Impact</h3><p>").append(esc(impact)).append("</p>");
                if (!rec.isEmpty())
                    sb.append("<h3>Recommendation</h3><p>").append(esc(rec)).append("</p>");
                sb.append("</div></div>");
            }

            sb.append("<p style='text-align:center;color:#aaa;font-size:11px;margin-top:40px'>")
              .append("Generated by ClaudeTab &mdash; ").append(date).append("</p>")
              .append("</div></body></html>");
            return sb.toString();
        }

        private String sevColor(String sev) {
            switch (sev) {
                case "CRITICAL": return "#c0392b";
                case "HIGH":     return "#e67e22";
                case "MEDIUM":   return "#f39c12";
                case "LOW":      return "#27ae60";
                default:         return "#3498db";
            }
        }

        private String getStr(JsonObject o, String key, String def) {
            return o.has(key) && !o.get(key).isJsonNull() ? o.get(key).getAsString() : def;
        }

        private String esc(String s) {
            if (s == null) return "";
            return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
                    .replace("\"","&quot;").replace("\n","<br>");
        }

        // ====== AGENTIC SCAN ENGINE =================================

        private void showStopButton(boolean show) {
            SwingUtilities.invokeLater(() -> {
                if (show) stopRequested = false;
                stopBtn.setEnabled(show);
                stopBtn.setForeground(show ? Color.WHITE : Color.decode("#555555"));
                stopBtn.setBackground(show ? Color.decode("#8b0000") : Color.decode("#2a2a2a"));
            });
        }

        /** Scan site map + proxy history for auth-related requests and return them as context */
        private String buildAuthContext(String targetHost) {
            List<String> AUTH_KEYWORDS = java.util.Arrays.asList(
                "login", "signin", "sign-in", "auth", "token", "oauth",
                "session", "password", "credential", "mfa", "otp", "2fa", "verify"
            );
            StringBuilder sb = new StringBuilder();
            sb.append("=== AUTH-RELATED REQUESTS FROM BURP SITE MAP ===\n\n");
            int found = 0;
            try {
                List<ProxyHttpRequestResponse> history = api.proxy().history();
                for (ProxyHttpRequestResponse item : history) {
                    try {
                        HttpRequest req = item.request();
                        String url = req.url().toLowerCase();
                        String path = req.path().toLowerCase();
                        boolean isAuth = AUTH_KEYWORDS.stream().anyMatch(k -> path.contains(k) || url.contains(k));
                        if (!isAuth) continue;
                        if (targetHost != null && !targetHost.isEmpty() &&
                            !req.httpService().host().contains(targetHost) &&
                            !targetHost.contains(req.httpService().host())) continue;

                        sb.append("--- REQUEST ").append(++found).append(" ---\n");
                        sb.append("Host: ").append(req.httpService().host())
                          .append(":").append(req.httpService().port()).append("\n");
                        sb.append("HTTPS: ").append(req.httpService().secure()).append("\n");
                        sb.append(req.method()).append(" ").append(req.path()).append("\n");
                        req.headers().forEach(h -> sb.append(h.name()).append(": ").append(h.value()).append("\n"));
                        if (req.body() != null && req.body().length() > 0)
                            sb.append("\nBody:\n").append(req.bodyToString()).append("\n");

                        if (item.response() != null) {
                            HttpResponse resp = item.response();
                            sb.append("\nResponse: HTTP ").append(resp.statusCode()).append("\n");
                            resp.headers().forEach(h -> sb.append(h.name()).append(": ").append(h.value()).append("\n"));
                            String body = resp.bodyToString();
                            if (body != null && !body.isEmpty())
                                sb.append("\nResponse Body:\n").append(body, 0, Math.min(body.length(), 2000)).append("\n");
                        }
                        sb.append("\n");
                        if (found >= 20) break;
                    } catch (Exception ignored) {}
                }
            } catch (Exception ignored) {}

            if (found == 0) return null;
            return sb.toString();
        }

        private void runAgentAuth(String apiKey, String authPrompt) {
            if (apiKey == null || apiKey.isBlank()) { SwingUtilities.invokeLater(() -> appendMessage("error", "No API key set.")); return; }

            // Extract host hint from prompt for site map filtering
            String hostHint = "";
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("Host: ([\\w.\\-]+)").matcher(authPrompt);
            if (m.find()) hostHint = m.group(1);

            String authCtx = buildAuthContext(hostHint);
            int ctxCount = authCtx != null ? authCtx.split("--- REQUEST").length - 1 : 0;

            if (authCtx != null) {
                final int count = ctxCount;
                SwingUtilities.invokeLater(() ->
                    appendMessage("system", "🔑 Auth agent started — found " + count +
                        " auth-related request(s) in Site Map. Claude will replicate the login flow."));
            } else {
                SwingUtilities.invokeLater(() ->
                    appendMessage("system", "🔑 Auth agent started — no prior auth requests in Site Map. " +
                        "Browse to the login page through Burp first for better results. Attempting blind login..."));
            }

            SwingUtilities.invokeLater(() -> { sendBtn.setEnabled(false); setStatus("Authenticating..."); });

            String fullPrompt = (authCtx != null ? authCtx + "\n\n" : "") + authPrompt;

            List<Map<String, Object>> messages = new ArrayList<>();
            Map<String, Object> userMsg = new LinkedHashMap<>();
            userMsg.put("role", "user");
            userMsg.put("content", fullPrompt);
            messages.add(userMsg);

            try {
                agentLoop(apiKey, messages, 0);
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> appendMessage("error", "Auth agent error: " + e.getMessage()));
            } finally {
                SwingUtilities.invokeLater(() -> { sendBtn.setEnabled(true); setStatus("Auth complete."); });
                showStopButton(false);
            }
        }

        private void runAgentScan() {
            String apiKey = apiKeyField.getText().trim();
            if (apiKey.isBlank()) { SwingUtilities.invokeLater(() -> appendMessage("error", "No API key set.")); return; }

            String liveCtx = buildLiveContext();
            SwingUtilities.invokeLater(() -> {
                appendMessage("system", "⏺ Agent mode started — Claude will send and chain requests autonomously.");
                sendBtn.setEnabled(false);
                setStatus("Agent running...");
            });
            showStopButton(true);

            String userMsg = (liveCtx != null ? liveCtx + "\n\n" : "") +
                "You are an autonomous penetration tester embedded inside Burp Suite with full access to send HTTP requests.\n" +
                "Your goal is to find REAL, CONFIRMED vulnerabilities — not guesses. Zero tolerance for false positives.\n\n" +

                "PHASE 0 — UNDERSTAND THE APPLICATION (do this before any testing)\n" +
                "The site map and proxy history above contain every endpoint Burp has seen.\n" +
                "Before firing a single payload:\n" +
                "  a. Read ALL endpoints from the site map context above\n" +
                "  b. Identify the tech stack, auth mechanism, API structure, and data models\n" +
                "  c. Map which endpoints handle user-owned resources (IDOR candidates)\n" +
                "  d. Identify the auth flow: login endpoint, token type (JWT/cookie/API key), refresh pattern\n" +
                "  e. Note any admin, internal, or privileged endpoints\n" +
                "Print a summary: 'Application Map: [summary]' before proceeding\n\n" +

                "PHASE 1 — AUTHENTICATE (if credentials are provided)\n" +
                "Check the engagement brief and user prompt for credentials (username/email + password).\n" +
                "If credentials are present:\n" +
                "  a. Find the login endpoint from the site map (look for /login, /auth, /signin, /token, /api/auth)\n" +
                "  b. Send a POST with the credentials — try JSON {\"email\":\"...\",\"password\":\"...\"} first\n" +
                "  c. Extract the JWT or session token from the response body or Set-Cookie header\n" +
                "  d. If MFA/2FA prompt appears, look for a skip/setup-later endpoint and bypass it\n" +
                "  e. Confirm auth works by hitting a profile/dashboard endpoint\n" +
                "  f. Use this token in the Authorization header for ALL subsequent requests\n" +
                "Print: 'AUTH: [token type] captured. Testing as authenticated user.'\n" +
                "If no credentials provided, test as unauthenticated and note which endpoints are still accessible.\n\n" +

                "PHASE 2 — SCAN based on the engagement brief and user instructions\n" +
                "Follow the scope, focus areas, and goals from CLAUDE.md / the brief above.\n" +
                "For each high-priority endpoint (ranked by true-positive likelihood):\n" +
                "  a. Baseline — understand normal response with valid auth\n" +
                "  b. Tamper — change IDs/UUIDs, remove/swap auth headers, inject payloads\n" +
                "  c. Confirm — 2-3 follow-up requests to prove it's real\n" +
                "  d. Only report CONFIRMED findings with proof from the actual response\n\n" +

                "ATTACK VECTORS (apply to every relevant endpoint):\n" +
                "  - IDOR: swap resource IDs/UUIDs between accounts\n" +
                "  - Auth bypass: remove Authorization header, try null/expired token\n" +
                "  - SQLi: ' OR 1=1-- , ' AND SLEEP(5)-- \n" +
                "  - NoSQL: {\"$ne\":null}, {\"$gt\":\"\"}\n" +
                "  - CORS: Origin: https://attacker.com (note: this is a test string, not a real target)\n" +
                "  - SSRF: callback URLs pointing to internal IPs (169.254.169.254, internal hostnames)\n" +
                "  - Mass assignment: add role=admin, isAdmin=true, balance=99999\n" +
                "  - Broken function-level auth: access admin endpoints as regular user\n\n" +

                "WHEN YOU CONFIRM A FINDING:\n" +
                "  - State: CONFIRMED [SEVERITY]: [vuln type]\n" +
                "  - Show the exact request and response that proves it\n" +
                "  - Continue — don't stop at first find\n\n" +

                "Begin with Phase 0. Narrate each phase clearly.";

            // Bootstrap conversation for agentic loop
            List<Map<String, Object>> messages = new ArrayList<>();
            Map<String, Object> userMessage = new LinkedHashMap<>();
            userMessage.put("role", "user");
            userMessage.put("content", userMsg);
            messages.add(userMessage);

            try {
                agentLoop(apiKey, messages, 0);
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    appendMessage("error", "Agent error: " + ex.getMessage());
                    sendBtn.setEnabled(true);
                    setStatus("Error.");
                });
            }
        }

        private static final int AGENT_CHECKPOINT = 50;

        private void agentLoop(String apiKey, List<Map<String, Object>> messages, int turn) throws Exception {
            // Check stop request before each turn
            if (stopRequested) {
                SwingUtilities.invokeLater(() -> {
                    appendMessage("system", "⏹ Agent stopped by user after " + turn + " turn(s).");
                    sendBtn.setEnabled(true);
                    setStatus("Stopped.");
                });
                showStopButton(false);
                return;
            }

            // At every 50-turn checkpoint, ask user whether to continue
            if (turn > 0 && turn % AGENT_CHECKPOINT == 0) {
                final int[] choice = {-1};
                try {
                    SwingUtilities.invokeAndWait(() -> {
                        choice[0] = javax.swing.JOptionPane.showConfirmDialog(
                            null,
                            "Agent has completed " + turn + " turns.\n\nContinue testing for another " + AGENT_CHECKPOINT + " turns?",
                            "ClaudeTab — Agent Checkpoint",
                            javax.swing.JOptionPane.YES_NO_OPTION,
                            javax.swing.JOptionPane.QUESTION_MESSAGE
                        );
                    });
                } catch (Exception ignored) {}

                if (choice[0] != javax.swing.JOptionPane.YES_OPTION) {
                    SwingUtilities.invokeLater(() -> {
                        appendMessage("system", "⏺ Agent paused at " + turn + " turns. Extracting findings...");
                        setStatus("Extracting findings...");
                    });
                    extractFindingsToScanner(apiKey, messages, "Paused at turn " + turn, turn);
                    return;
                }
                SwingUtilities.invokeLater(() ->
                    appendMessage("system", "⏺ Continuing — turn " + turn + ". Running next " + AGENT_CHECKPOINT + " turns..."));
            }

            // Show live turn counter
            final int t = turn + 1;
            SwingUtilities.invokeLater(() -> setStatus("Agent running — turn " + t + "..."));

            Gson gson = new Gson();

            // Tool definition
            Map<String, Object> toolDef = new LinkedHashMap<>();
            toolDef.put("name", "send_request");
            toolDef.put("description",
                "Send an HTTP request through Burp Suite and return the response. " +
                "Use this to test endpoints, send payloads, verify findings. " +
                "You can use existing auth headers from the proxy history.");
            Map<String, Object> schema = new LinkedHashMap<>();
            schema.put("type", "object");
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("host",    Map.of("type","string", "description","Target hostname e.g. app.example.com"));
            props.put("https",   Map.of("type","boolean","description","true for HTTPS"));
            props.put("port",    Map.of("type","integer","description","Port, default 443/80"));
            props.put("method",  Map.of("type","string", "description","HTTP method: GET POST PUT DELETE PATCH"));
            props.put("path",    Map.of("type","string", "description","URL path + query string e.g. /api/users?id=1"));
            props.put("headers", Map.of("type","object", "description","HTTP headers as key-value pairs"));
            props.put("body",    Map.of("type","string", "description","Request body (for POST/PUT)"));
            schema.put("properties", props);
            schema.put("required", List.of("host", "method", "path"));
            toolDef.put("input_schema", schema);

            // Build payload
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("model", "claude-opus-4-5");
            payload.put("max_tokens", 4096);
            payload.put("tools", List.of(toolDef));
            payload.put("system",
                "You are an expert penetration tester running inside Burp Suite. " +
                "Use the send_request tool to actively test endpoints. " +
                "Narrate your thinking before each tool call. Be systematic and thorough.");
            payload.put("messages", messages);

            java.net.http.HttpRequest req = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create("https://api.anthropic.com/v1/messages"))
                .header("x-api-key", apiKey)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(gson.toJson(payload)))
                .timeout(java.time.Duration.ofSeconds(120))
                .build();

            java.net.http.HttpResponse<String> resp = HTTP_CLIENT.send(req,
                java.net.http.HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200)
                throw new Exception("API error " + resp.statusCode() + ": " + resp.body());

            JsonObject responseJson = JsonParser.parseString(resp.body()).getAsJsonObject();
            String stopReason = responseJson.has("stop_reason") ? responseJson.get("stop_reason").getAsString() : "";
            JsonArray content  = responseJson.getAsJsonArray("content");

            // Collect text and tool_use blocks
            StringBuilder textSb = new StringBuilder();
            List<Map<String, Object>> toolCalls = new ArrayList<>();

            for (JsonElement el : content) {
                JsonObject block = el.getAsJsonObject();
                String type = block.get("type").getAsString();
                if ("text".equals(type)) {
                    textSb.append(block.get("text").getAsString());
                } else if ("tool_use".equals(type)) {
                    Map<String, Object> tc = new LinkedHashMap<>();
                    tc.put("id",    block.get("id").getAsString());
                    tc.put("name",  block.get("name").getAsString());
                    tc.put("input", block.getAsJsonObject("input"));
                    toolCalls.add(tc);
                }
            }

            // Show Claude's narration text
            if (textSb.length() > 0) {
                final String txt = textSb.toString();
                SwingUtilities.invokeLater(() -> appendClaudeFormatted(txt));
            }

            // If no tool calls → Claude is done
            if (toolCalls.isEmpty()) {
                final String finalText = textSb.toString();

                // Store in conversation history
                Map<String, String> assistantMsg = new LinkedHashMap<>();
                assistantMsg.put("role", "assistant");
                assistantMsg.put("content", finalText);
                conversationHistory.add(assistantMsg);

                SwingUtilities.invokeLater(() -> {
                    appendMessage("system", "⏺ Agent finished testing. Extracting confirmed findings into Burp Scanner...");
                    setStatus("Extracting findings...");
                });

                // Ask Claude to output structured JSON of confirmed findings
                extractFindingsToScanner(apiKey, messages, finalText, turn);
                return;
            }

            // Add assistant message (full content array) to messages
            Map<String, Object> assistantTurn = new LinkedHashMap<>();
            assistantTurn.put("role", "assistant");
            List<Map<String, Object>> assistantContent = new ArrayList<>();
            if (textSb.length() > 0) {
                Map<String, Object> textBlock = new LinkedHashMap<>();
                textBlock.put("type", "text");
                textBlock.put("text", textSb.toString());
                assistantContent.add(textBlock);
            }
            for (Map<String, Object> tc : toolCalls) {
                Map<String, Object> toolBlock = new LinkedHashMap<>();
                toolBlock.put("type",  "tool_use");
                toolBlock.put("id",    tc.get("id"));
                toolBlock.put("name",  tc.get("name"));
                toolBlock.put("input", tc.get("input"));
                assistantContent.add(toolBlock);
            }
            assistantTurn.put("content", assistantContent);
            messages.add(assistantTurn);

            // Execute each tool call and collect results
            List<Map<String, Object>> toolResults = new ArrayList<>();
            for (Map<String, Object> tc : toolCalls) {
                String toolName  = (String) tc.get("name");
                String toolId    = (String) tc.get("id");
                JsonObject input = (JsonObject) tc.get("input");

                String result = executeAgentTool(toolName, input);
                Map<String, Object> resultBlock = new LinkedHashMap<>();
                resultBlock.put("type",        "tool_result");
                resultBlock.put("tool_use_id", toolId);
                resultBlock.put("content",     result);
                toolResults.add(resultBlock);
            }

            // Add tool results as a user message
            Map<String, Object> toolResultMsg = new LinkedHashMap<>();
            toolResultMsg.put("role", "user");
            toolResultMsg.put("content", toolResults);
            messages.add(toolResultMsg);

            // Continue the loop
            agentLoop(apiKey, messages, turn + 1);
        }

        private String executeAgentTool(String name, JsonObject input) {
            if (!"send_request".equals(name)) return "Unknown tool: " + name;

            try {
                String host   = getStr(input, "host",   "");
                String method = getStr(input, "method", "GET").toUpperCase();
                String path   = getStr(input, "path",   "/");
                boolean https = !input.has("https") || input.get("https").getAsBoolean();
                int port      = input.has("port") ? input.get("port").getAsInt() : (https ? 443 : 80);
                String body   = getStr(input, "body",   "");

                // Show agent step in UI
                final String stepText = method + " " + path;
                SwingUtilities.invokeLater(() -> appendAgentStep("Sending: " + stepText));

                // Build raw request
                StringBuilder rawReq = new StringBuilder();
                rawReq.append(method).append(" ").append(path).append(" HTTP/1.1\r\n");
                rawReq.append("Host: ").append(host).append("\r\n");
                rawReq.append("User-Agent: ClaudeTab-Agent/1.0\r\n");
                rawReq.append("Accept: */*\r\n");

                // Add provided headers
                if (input.has("headers") && input.get("headers").isJsonObject()) {
                    JsonObject hdrs = input.getAsJsonObject("headers");
                    for (Map.Entry<String, JsonElement> h : hdrs.entrySet()) {
                        rawReq.append(h.getKey()).append(": ").append(h.getValue().getAsString()).append("\r\n");
                    }
                }
                if (!body.isEmpty()) {
                    rawReq.append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
                }
                rawReq.append("\r\n");
                if (!body.isEmpty()) rawReq.append(body);

                burp.api.montoya.http.HttpService svc =
                    burp.api.montoya.http.HttpService.httpService(host, port, https);
                burp.api.montoya.core.ByteArray reqBytes =
                    burp.api.montoya.core.ByteArray.byteArray(rawReq.toString().getBytes(StandardCharsets.UTF_8));
                HttpRequest httpReq = HttpRequest.httpRequest(svc, reqBytes);
                var result = api.http().sendRequest(httpReq);
                HttpResponse httpResp = result.response();

                if (httpResp == null) return "No response received.";

                int status = httpResp.statusCode();
                String respBody = httpResp.bodyToString();
                int bodyLen = respBody != null ? respBody.length() : 0;
                String preview = respBody != null && respBody.length() > 1000
                    ? respBody.substring(0, 1000) + "\n... [truncated, " + bodyLen + " total chars]"
                    : respBody;

                // Collect response headers
                StringBuilder hdrs = new StringBuilder();
                for (var h : httpResp.headers()) {
                    hdrs.append(h.name()).append(": ").append(h.value()).append("\n");
                }

                final String statusLine = "⎿ " + status + " — " + bodyLen + " bytes";
                SwingUtilities.invokeLater(() -> appendAgentResult(statusLine));

                return "HTTP " + status + "\n" +
                       "Headers:\n" + hdrs +
                       "\nBody:\n" + (preview != null ? preview : "(empty)");

            } catch (Exception ex) {
                final String err = "⎿ Error: " + ex.getMessage();
                SwingUtilities.invokeLater(() -> appendAgentResult(err));
                return "Request failed: " + ex.getMessage();
            }
        }

        /** Ask Claude to output structured JSON of all confirmed findings, then add to Burp Scanner */
        private void extractFindingsToScanner(String apiKey,
                List<Map<String, Object>> messages, String finalText, int turns) {
            ExecutorService ex = Executors.newSingleThreadExecutor();
            ex.submit(() -> {
                try {
                    // Add the extraction request to conversation
                    List<Map<String, Object>> extractMsgs = new ArrayList<>(messages);
                    Map<String, Object> extractReq = new LinkedHashMap<>();
                    extractReq.put("role", "user");
                    extractReq.put("content",
                        "Based on everything you tested, list ONLY the confirmed vulnerabilities as JSON. " +
                        "Return ONLY a valid JSON array, no markdown:\n" +
                        "[{\"title\":\"NoSQL Injection\",\"severity\":\"CRITICAL\"," +
                        "\"url\":\"http://localhost:8888/community/api/v2/coupon/validate-coupon\"," +
                        "\"evidence\":\"$ne operator returned valid coupon code\"," +
                        "\"remediation\":\"Sanitize input, use parameterized queries\"}]\n" +
                        "severity must be: CRITICAL, HIGH, MEDIUM, or LOW.\n" +
                        "Only include findings you actually confirmed with a real HTTP response. Return ONLY JSON.");
                    extractMsgs.add(extractReq);

                    String raw = callClaudeRaw(apiKey,
                        "Based on everything tested in this session, list ONLY confirmed vulnerabilities as a JSON array: " +
                        "[{\"title\", \"severity\": CRITICAL/HIGH/MEDIUM/LOW, \"url\", \"evidence\", \"remediation\"}]. " +
                        "Return ONLY valid JSON, no markdown.");

                    // Parse JSON
                    int s = raw.indexOf("["), e = raw.lastIndexOf("]") + 1;
                    if (s < 0 || e <= s) throw new Exception("No JSON array in response");
                    JsonArray findings = JsonParser.parseString(raw.substring(s, e)).getAsJsonArray();

                    int added = 0;
                    for (JsonElement fe : findings) {
                        JsonObject f = fe.getAsJsonObject();
                        String title      = getStr(f, "title", "Finding");
                        String sevStr     = getStr(f, "severity", "MEDIUM").toUpperCase();
                        String rawUrl     = getStr(f, "url", "/");
                        // Ensure full URL — Claude sometimes returns just a path
                        String url;
                        if (rawUrl.startsWith("http://") || rawUrl.startsWith("https://")) {
                            url = rawUrl;
                        } else {
                            // Strip leading method (e.g. "GET /path") if present
                            rawUrl = rawUrl.replaceAll("^(GET|POST|PUT|DELETE|PATCH)\\s+", "").trim();
                            // Derive base from proxy history
                            String base = "http://localhost:8888";
                            try {
                                List<ProxyHttpRequestResponse> h = api.proxy().history();
                                if (!h.isEmpty()) {
                                    var svc = h.get(0).request().httpService();
                                    if (svc != null) {
                                        base = (svc.secure() ? "https" : "http") + "://" + svc.host() +
                                               (svc.port() == 80 || svc.port() == 443 ? "" : ":" + svc.port());
                                    }
                                }
                            } catch (Exception ignored) {}
                            url = base + (rawUrl.startsWith("/") ? rawUrl : "/" + rawUrl);
                        }
                        String evidence   = getStr(f, "evidence", "");
                        String remediation = getStr(f, "remediation", "Verify and remediate.");
                        AuditIssueSeverity sev = toSeverity(sevStr);

                        AuditIssue issue = AuditIssue.auditIssue(
                            "[Claude Agent] " + title,
                            "<b>Evidence:</b> " + evidence,
                            remediation,
                            url, sev, AuditIssueConfidence.CERTAIN,
                            "Confirmed by ClaudeTab autonomous agent scan (" + turns + " turns).",
                            remediation, sev);
                        api.siteMap().add(issue);
                        added++;
                    }

                    final int count = added;
                    final String fullText = finalText;
                    SwingUtilities.invokeLater(() -> {
                        appendMessage("system",
                            "⏺ Agent complete — " + turns + " turns.\n" +
                            count + " confirmed finding(s) added to Burp Scanner tab → Issue activity.");
                        markVulnerableInHistory(fullText);
                        sendBtn.setEnabled(true);
                        setStatus("Agent done — " + count + " issues in Scanner.");
                    });
                    showStopButton(false);

                } catch (Exception exc) {
                    final String fullText = finalText;
                    SwingUtilities.invokeLater(() -> {
                        appendMessage("system", "⏺ Agent complete — " + turns + " turns. " +
                            "(Could not auto-add to Scanner: " + exc.getMessage() + ")");
                        markVulnerableInHistory(fullText);
                        sendBtn.setEnabled(true);
                        setStatus("Agent done.");
                    });
                    showStopButton(false);
                }
                ex.shutdown();
            });
        }

        private void appendAgentStep(String text) {
            StyledDocument doc = chatArea.getStyledDocument();
            Style st = chatArea.addStyle("agentStep", null);
            StyleConstants.setFontFamily(st, "Monospaced");
            StyleConstants.setFontSize(st, 12);
            StyleConstants.setForeground(st, Color.decode("#00d2a0"));
            StyleConstants.setBold(st, true);
            try { doc.insertString(doc.getLength(), "\n⏺ " + text + "\n", st); }
            catch (BadLocationException ignored) {}
            scrollToBottom();
        }

        private void appendAgentResult(String text) {
            StyledDocument doc = chatArea.getStyledDocument();
            Style st = chatArea.addStyle("agentResult", null);
            StyleConstants.setFontFamily(st, "Monospaced");
            StyleConstants.setFontSize(st, 11);
            StyleConstants.setForeground(st, Color.decode("#666666"));
            try { doc.insertString(doc.getLength(), "  " + text + "\n", st); }
            catch (BadLocationException ignored) {}
            scrollToBottom();
        }

        // ====== END AGENTIC ENGINE ==================================

        // ---- CLAUDE.md loader -------------------------------------

        private void loadClaudeMd() {
            JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
            fc.setDialogTitle("Load CLAUDE.md or engagement brief");
            fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Markdown / Text files", "md", "txt"));
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    String content = Files.readString(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8);
                    targetContextArea.setForeground(Color.decode("#cccccc"));
                    targetContextArea.setText(content);
                    appendMessage("system", "Loaded: " + fc.getSelectedFile().getName() +
                        " (" + content.lines().count() + " lines). This brief will be injected into every Claude call.");
                } catch (Exception ex) {
                    appendMessage("error", "Failed to load file: " + ex.getMessage());
                }
            }
        }

        // ---- Save / Load session ----------------------------------

        private void saveSession() {
            if (conversationHistory.isEmpty()) {
                appendMessage("system", "Nothing to save yet.");
                return;
            }
            JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
            fc.setDialogTitle("Save ClaudeTab Session");
            fc.setSelectedFile(new File("burpai-session-" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd_HHmm")) + ".json"));
            if (fc.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    Gson gson = new GsonBuilder().setPrettyPrinting().create();
                    Map<String, Object> session = new LinkedHashMap<>();
                    session.put("saved_at", LocalDateTime.now().toString());
                    session.put("engagement_brief", targetContextArea.getText());
                    session.put("conversation", conversationHistory);
                    Files.writeString(fc.getSelectedFile().toPath(), gson.toJson(session), StandardCharsets.UTF_8);
                    appendMessage("system", "Session saved → " + fc.getSelectedFile().getName());
                } catch (Exception ex) {
                    appendMessage("error", "Save failed: " + ex.getMessage());
                }
            }
        }

        private void loadSession() {
            JFileChooser fc = new JFileChooser(System.getProperty("user.home"));
            fc.setDialogTitle("Load ClaudeTab Session");
            fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("JSON sessions", "json"));
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                try {
                    String raw = Files.readString(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8);
                    JsonObject session = JsonParser.parseString(raw).getAsJsonObject();

                    // Restore conversation history
                    conversationHistory.clear();
                    if (session.has("conversation")) {
                        for (JsonElement el : session.getAsJsonArray("conversation")) {
                            JsonObject msg = el.getAsJsonObject();
                            Map<String, String> m = new LinkedHashMap<>();
                            m.put("role", msg.get("role").getAsString());
                            m.put("content", msg.get("content").getAsString());
                            conversationHistory.add(m);
                        }
                    }
                    // Restore brief
                    if (session.has("engagement_brief")) {
                        String brief = session.get("engagement_brief").getAsString();
                        if (!brief.isBlank()) {
                            targetContextArea.setForeground(Color.decode("#cccccc"));
                            targetContextArea.setText(brief);
                        }
                    }
                    // Replay visible conversation
                    clearChatArea();
                    for (Map<String, String> msg : conversationHistory) {
                        if ("user".equals(msg.get("role")))
                            appendMessage("user", msg.get("content").length() > 300
                                ? msg.get("content").substring(0, 300) + "..." : msg.get("content"));
                        else if ("assistant".equals(msg.get("role")))
                            appendClaudeFormatted(msg.get("content"));
                    }
                    appendMessage("system", "Session loaded: " + conversationHistory.size() / 2 + " turns restored.");
                } catch (Exception ex) {
                    appendMessage("error", "Load failed: " + ex.getMessage());
                }
            }
        }

        // ---- Intruder payload generation --------------------------

        void generateIntruderPayloads(HttpRequest req) {
            String apiKey = apiKeyField.getText().trim();
            if (apiKey.isBlank()) { appendMessage("error", "No API key set."); return; }

            setStatus("Generating Intruder payloads...");
            String reqStr = req.toString().length() > 3000
                ? req.toString().substring(0, 3000) : req.toString();

            String prompt =
                "Analyze this HTTP request and generate targeted Intruder payloads:\n\n" + reqStr +
                "\n\nReturn ONLY JSON:\n" +
                "{\"endpoint\":\"POST /api/login\",\"attack_type\":\"SQLi/XSS/IDOR/etc\"," +
                "\"param\":\"username\",\"payloads\":[\"' OR 1=1--\",\"admin'--\",...],\"notes\":\"why these payloads\"}";

            runInThread(() -> {
                try {
                    String result = callClaudeRaw(apiKey, prompt);
                    int s = result.indexOf("{"), e = result.lastIndexOf("}") + 1;
                    if (s < 0) throw new Exception("No JSON returned");
                    JsonObject j = JsonParser.parseString(result.substring(s, e)).getAsJsonObject();

                    String endpoint   = getStr(j, "endpoint", req.url());
                    String attackType = getStr(j, "attack_type", "Fuzzing");
                    String param      = getStr(j, "param", "");
                    String notes      = getStr(j, "notes", "");
                    JsonArray payloads = j.has("payloads") ? j.getAsJsonArray("payloads") : new JsonArray();

                    // Build payload list as a chat summary
                    StringBuilder sb = new StringBuilder();
                    sb.append("Intruder payloads for ").append(endpoint).append("\n");
                    sb.append("Attack: ").append(attackType).append(" | Param: ").append(param).append("\n");
                    sb.append("Notes: ").append(notes).append("\n\nPayloads:\n");
                    for (JsonElement p : payloads) sb.append("  ").append(p.getAsString()).append("\n");
                    sb.append("\nSending to Intruder...");

                    SwingUtilities.invokeLater(() -> appendMessage("system", sb.toString()));

                    // Send original request to Intruder
                    api.intruder().sendToIntruder(req, "Claude: " + attackType + " — " + endpoint);

                    SwingUtilities.invokeLater(() -> {
                        appendMessage("system",
                            "Sent to Intruder tab. Go to Intruder → Payloads and paste the payload list above.\n" +
                            "Tip: mark the parameter with § markers in the Positions tab.");
                        setStatus("Ready");
                    });
                } catch (Exception ex) {
                    SwingUtilities.invokeLater(() -> { appendMessage("error", "Intruder error: " + ex.getMessage()); setStatus("Error."); });
                }
            });
        }

        private void clearChatArea() {
            try {
                StyledDocument doc = chatArea.getStyledDocument();
                doc.remove(0, doc.getLength());
            } catch (BadLocationException ignored) {}
        }

        private void clearChat() {
            chatArea.setText("");
            conversationHistory.clear();
            pendingContext = null;
            appendMessage("system", "Chat cleared. Start a new conversation.");
        }

        private void scrollToBottom() {
            SwingUtilities.invokeLater(() ->
                chatArea.setCaretPosition(chatArea.getDocument().getLength()));
        }

        private void setStatus(String msg) {
            SwingUtilities.invokeLater(() -> statusLabel.setText("  " + msg));
        }

        private JButton styledButton(String text, String hexColor) {
            JButton btn = new JButton(text);
            btn.setBackground(Color.decode(hexColor));
            btn.setForeground(Color.decode("#dddddd"));
            btn.setFont(new Font("Monospaced", Font.BOLD, 11));
            btn.setFocusPainted(false);
            btn.setBorder(new EmptyBorder(5, 10, 5, 10));
            btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            return btn;
        }
    }
}
