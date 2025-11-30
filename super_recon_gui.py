from datetime import datetime
import os
import threading
import tempfile

from flask import Flask, jsonify, render_template_string, request

from super_recon import (
    ReconResult,
    normalize_target,
    result_to_dict,
    run_active,
    run_passive,
    run_web,
    write_markdown_report,
)


def create_app():
    """Create and configure Flask application (background-threaded scans + polling)."""
    app = Flask(__name__)
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

    # Shared state
    state = {
        'last_result': None,
        'is_scanning': False,
        'output_lines': [],   # incremental output for live polling
        'scan_thread': None,
    }

    # Full HTML template (kept your original UI/style but updated JS to poll logs/status)
    HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html>
<head>
    <title>CY.Recon - Reconnaissance Tool</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background-color: #0d0d0d; color: #ffffff; font-family: 'Courier New', monospace; line-height: 1.6; }
        header {
            background: linear-gradient(135deg, #00bfff 0%, #0099cc 100%);
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        header h1 {
            font-size: 2.5em;
            color: #000000;
            display: inline-block;
            margin-right: 20px;
            font-family: Helvetica, Arial, sans-serif;
            font-weight: bold;
        }
        header p {
            color: #000000;
            font-size: 0.9em;
            display: inline-block;
            font-style: italic;
            font-family: Helvetica, Arial, sans-serif;
        }
        .container {
            display: flex;
            height: calc(100vh - 180px);
            gap: 20px;
            padding: 20px;
        }
        .left-panel {
            width: 350px;
            background-color: #1a1a1a;
            padding: 20px;
            border-radius: 5px;
            border: 1px solid #2a2a2a;
            overflow-y: auto;
        }
        .right-panel {
            flex: 1;
            background-color: #1a1a1a;
            padding: 20px;
            border-radius: 5px;
            border: 1px solid #2a2a2a;
            display: flex;
            flex-direction: column;
        }
        .section-title {
            color: #00bfff;
            font-size: 1.1em;
            font-weight: bold;
            margin-top: 20px;
            margin-bottom: 10px;
            border-bottom: 1px solid #00bfff;
            padding-bottom: 5px;
            font-family: Helvetica, Arial, sans-serif;
        }
        .section-title:first-child { margin-top: 0; }
        label { display: block; margin-bottom: 5px; color: #ffffff; font-size: 0.9em; font-family: Helvetica, Arial, sans-serif; }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 15px;
            background-color: #2a2a2a;
            color: #00bfff;
            border: 1px solid #3a3a3a;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
        }
        input[type="checkbox"] { margin-right: 8px; }
        .checkbox-group { margin-bottom: 15px; }
        .checkbox-item {
            display: flex;
            align-items: center;
            margin-bottom: 8px;
            color: #ffffff;
            font-family: Helvetica, Arial, sans-serif;
        }
        button {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            background-color: #00bfff;
            color: #000000;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-weight: bold;
            font-family: Helvetica, Arial, sans-serif;
            transition: all 0.3s ease;
        }
        button:hover { background-color: #00e0ff; transform: translateY(-2px); }
        button:disabled { background-color: #666666; cursor: not-allowed; transform: none; }
        .output-area {
            flex: 1;
            background-color: #0d0d0d;
            border: 1px solid #2a2a2a;
            padding: 15px;
            border-radius: 3px;
            overflow-y: auto;
            overflow-x: hidden;
            font-size: 0.85em;
            white-space: pre-wrap;
            word-break: break-word;
            color: #00ff00;
            font-family: 'Courier New', monospace;
            max-height: calc(100vh - 280px);
        }
        .status-bar {
            background-color: #1a1a1a;
            padding: 10px;
            margin-top: 10px;
            border-radius: 3px;
            border: 1px solid #2a2a2a;
            font-size: 0.85em;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }
        footer {
            background-color: #1a1a1a;
            padding: 15px;
            text-align: center;
            border-top: 1px solid #2a2a2a;
            font-size: 0.8em;
            color: #808080;
            font-family: Helvetica, Arial, sans-serif;
        }
        .footer-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .warning { color: #ff6b6b; font-weight: bold; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #1a1a1a; }
        ::-webkit-scrollbar-thumb { background: #00bfff; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #00e0ff; }
    </style>
</head>
<body>
    <header>
        <h1>CY.Recon</h1>
        <p>By Cyberveins</p>
    </header>
    
    <div class="container">
        <div class="left-panel">
            <div class="section-title">Target Configuration</div>
            
            <label for="target">Target:</label>
            <input type="text" id="target" value="example.com" placeholder="domain.com or IP">
            
            <label for="ports">Ports:</label>
            <input type="text" id="ports" value="80,443,8080,8443,22,25,53,3306,5432" placeholder="80,443 or 1-1024">
            
            <label for="maxPages">Max Pages to Crawl:</label>
            <input type="number" id="maxPages" value="20" min="1" max="100">
            
            <div class="section-title">Recon Modules</div>
            <div class="checkbox-group">
                <div class="checkbox-item">
                    <input type="checkbox" id="passiveCheck" checked>
                    <label for="passiveCheck" style="margin: 0;">Passive Recon</label>
                </div>
                <div class="checkbox-item">
                    <input type="checkbox" id="activeCheck" checked>
                    <label for="activeCheck" style="margin: 0;">Active Recon (Port Scan)</label>
                </div>
                <div class="checkbox-item">
                    <input type="checkbox" id="webCheck" checked>
                    <label for="webCheck" style="margin: 0;">Web Recon (Crawler)</label>
                </div>
            </div>
            
            <button id="scanBtn" onclick="startScan()">▶ START SCAN</button>
            <button id="stopBtn" onclick="stopScan()" disabled>⏹ STOP</button>
            
            <div class="section-title">Export Options</div>
            <button id="jsonBtn" onclick="saveJSON()" disabled>📄 Save as JSON</button>
            <button id="markdownBtn" onclick="saveMarkdown()" disabled>📋 Save as Markdown</button>
            <button onclick="clearOutput()">🗑 Clear Output</button>
        </div>
        
        <div class="right-panel">
            <div class="section-title" style="margin-top: 0;">Scan Results</div>
            <div class="output-area" id="output"></div>
            <div class="status-bar" id="status">Ready</div>
        </div>
    </div>
    
    <footer>
        <div class="footer-content">
            <div>Created by: TEAM ID - CY202501NAND</div>
            <div><span class="warning">⚠ For Authorized Security Testing Only</span></div>
            <div>v1.0.0 © 2025 Cyberveins</div>
        </div>
    </footer>
    
    <script>
        let pollInterval = null;

        function updateStatus(msg) { document.getElementById('status').textContent = msg; }
        function setOutputText(text) { document.getElementById('output').textContent = text; document.getElementById('output').scrollTop = document.getElementById('output').scrollHeight; }
        function appendOutputLine(line) { const out = document.getElementById('output'); out.textContent += line + '\n'; out.scrollTop = out.scrollHeight; }
        function clearOutput() { document.getElementById('output').textContent = ''; updateStatus('Ready'); }

        async function startScan() {
            const target = document.getElementById('target').value.trim();
            if (!target) { alert('Please enter a target'); return; }
            
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('stopBtn').disabled = false;
            document.getElementById('jsonBtn').disabled = true;
            document.getElementById('markdownBtn').disabled = true;
            document.getElementById('output').textContent = '';
            updateStatus('[*] Starting scan...');

            const data = {
                target: target,
                ports: document.getElementById('ports').value,
                maxPages: parseInt(document.getElementById('maxPages').value),
                passive: document.getElementById('passiveCheck').checked,
                active: document.getElementById('activeCheck').checked,
                web: document.getElementById('webCheck').checked
            };

            try {
                const resp = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(data)
                });
                const json = await resp.json();
                if (!json.success) {
                    updateStatus('[!] Error: ' + json.error);
                    appendOutputLine('[!] ' + json.error);
                    document.getElementById('scanBtn').disabled = false;
                    document.getElementById('stopBtn').disabled = true;
                    return;
                }

                updateStatus('[*] Scan in progress...');
                // start polling logs/status
                pollInterval = setInterval(pollLogsAndStatus, 1000);
            } catch (err) {
                updateStatus('[!] Error: ' + err);
                appendOutputLine('[!] ' + err);
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('stopBtn').disabled = true;
            }
        }

        async function pollLogsAndStatus() {
            try {
                const [logsResp, statusResp] = await Promise.all([fetch('/api/logs'), fetch('/api/status')]);
                const logsText = await logsResp.text();
                const statusJson = await statusResp.json();

                setOutputText(logsText);

                if (!statusJson.is_scanning) {
                    // finished
                    clearInterval(pollInterval);
                    pollInterval = null;
                    updateStatus('[✓] Scan complete!');
                    document.getElementById('scanBtn').disabled = false;
                    document.getElementById('stopBtn').disabled = true;
                    document.getElementById('jsonBtn').disabled = false;
                    document.getElementById('markdownBtn').disabled = false;
                } else {
                    updateStatus('[*] Scanning...');
                }
            } catch (err) {
                console.error('Polling error', err);
                // don't stop polling on transient errors; retry next tick
            }
        }

        async function stopScan() {
            try {
                await fetch('/api/stop', {method: 'POST'});
                appendOutputLine('[!] Stop requested — the scan will stop between modules.');
                updateStatus('[!] Stop requested');
                document.getElementById('stopBtn').disabled = true;
            } catch (err) {
                appendOutputLine('[!] Error requesting stop: ' + err);
            }
        }

        async function saveJSON() {
            try {
                const resp = await fetch('/api/export/json');
                if (!resp.ok) { const txt = await resp.text(); alert('Export error: ' + txt); return; }
                const data = await resp.json();
                const json = JSON.stringify(data, null, 2);
                const blob = new Blob([json], {type: 'application/json'});
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'recon_report.json';
                a.click();
            } catch (err) {
                alert('Export error: ' + err);
            }
        }
        
        async function saveMarkdown() {
            try {
                const resp = await fetch('/api/export/markdown');
                if (!resp.ok) { const txt = await resp.text(); alert('Export error: ' + txt); return; }
                const text = await resp.text();
                const blob = new Blob([text], {type: 'text/markdown'});
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'recon_report.md';
                a.click();
            } catch (err) {
                alert('Export error: ' + err);
            }
        }
    </script>
</body>
</html>
    """

    @app.route('/')
    def index():
        return render_template_string(HTML_TEMPLATE)

    # Helper to append a line to state output (thread-safe enough for CPython single interpreter)
    def append_line(line: str):
        state['output_lines'].append(line)

    def run_scan_in_thread(data):
        """
        Worker run in background thread. Updates state['output_lines'] incrementally.
        This routine checks state['is_scanning'] between modules so POST /api/stop can request stop.
        Note: it cannot interrupt a blocking run_passive/run_active/run_web call unless those funcs are changed.
        """
        try:
            append_line('=' * 80)
            append_line('CY.Recon - Reconnaissance Report')
            append_line('=' * 80)
            append_line(f'Started: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            append_line(f'Target: {data["target"]}')
            append_line('')

            target = normalize_target(data['target'])
            append_line('[+] Target normalized:')
            append_line(f'    Hostname: {target.hostname}')
            append_line(f'    IP: {target.ip or "unresolved"}')
            append_line(f'    Scheme: {target.scheme}')
            append_line('')

            result = ReconResult(target=target, passive=None, active=None, web=None)

            # Passive
            if data.get('passive') and state['is_scanning']:
                append_line('[*] Running Passive Recon...')
                try:
                    result.passive = run_passive(target)
                    append_line('[+] Passive Recon Complete')
                except Exception as ex:
                    append_line(f'[!] Passive recon error: {ex}')
                append_line('')
                # DNS Records
                if result.passive and result.passive.dns.A:
                    append_line('[*] DNS Records:')
                    append_line(f'    A Records: {", ".join(result.passive.dns.A)}')
                if result.passive and result.passive.dns.AAAA:
                    append_line(f'    AAAA Records: {", ".join(result.passive.dns.AAAA)}')
                if result.passive and result.passive.dns.MX:
                    append_line(f'    MX Records: {", ".join(result.passive.dns.MX)}')
                if result.passive and result.passive.dns.NS:
                    append_line(f'    NS Records: {", ".join(result.passive.dns.NS)}')
                if result.passive and result.passive.dns.TXT:
                    append_line(f'    TXT Records: {", ".join(result.passive.dns.TXT)}')
                if result.passive and result.passive.dns.CNAME:
                    append_line(f'    CNAME Records: {", ".join(result.passive.dns.CNAME)}')
                append_line('')
                # Technologies
                if result.passive and result.passive.technologies:
                    append_line('[*] Detected Technologies:')
                    for tech in result.passive.technologies:
                        append_line(f'    → {tech}')
                    append_line('')
                # WHOIS
                if result.passive and getattr(result.passive, 'whois_summary', None):
                    append_line('[*] WHOIS Information:')
                    for k, v in result.passive.whois_summary.items():
                        if v:
                            append_line(f'    {k}: {v}')
                    append_line('')
                # Subdomains
                if result.passive and result.passive.subdomains:
                    append_line(f'[*] Subdomains Found: {len(result.passive.subdomains)}')
                    for i, sd in enumerate(result.passive.subdomains, 1):
                        append_line(f'    {i:3d}. {sd}')
                    append_line('')

            # Respect stop between modules
            if not state['is_scanning']:
                append_line('[!] Scan aborted by user after passive step.')
                state['last_result'] = result
                append_line('=' * 80)
                append_line(f'Completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
                append_line('=' * 80)
                return

            # Active
            if data.get('active') and state['is_scanning']:
                append_line('[*] Running Active Recon (Port Scan)...')
                try:
                    result.active = run_active(target, data['ports'])
                    append_line('[+] Active Recon Complete')
                except Exception as ex:
                    append_line(f'[!] Active recon error: {ex}')
                append_line('')
                if result.active and result.active.open_ports:
                    append_line(f'[*] Open Ports Found: {len(result.active.open_ports)}')
                    for p in sorted(result.active.open_ports):
                        append_line(f'    ✓ Port {p} - OPEN')
                else:
                    append_line('    ✗ No open ports found')
                append_line('')

            if not state['is_scanning']:
                append_line('[!] Scan aborted by user after active step.')
                state['last_result'] = result
                append_line('=' * 80)
                append_line(f'Completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
                append_line('=' * 80)
                return

            # Web
            if data.get('web') and state['is_scanning']:
                append_line('[*] Running Web Recon (Crawler)...')
                try:
                    result.web = run_web(target, max_pages=data['maxPages'])
                    append_line('[+] Web Recon Complete')
                except Exception as ex:
                    append_line(f'[!] Web recon error: {ex}')
                append_line('')
                if result.web and result.web.crawled_pages:
                    append_line(f'[*] Pages Crawled: {len(result.web.crawled_pages)}')
                    for i, page in enumerate(result.web.crawled_pages[:50], 1):
                        status = page.status_code if page.status_code is not None else "?"
                        title = page.title or ""
                        append_line(f'    {i:3d}. [{status}] {page.url} {"- " + title if title else ""}')
                    if len(result.web.crawled_pages) > 50:
                        append_line(f'    ... and {len(result.web.crawled_pages) - 50} more pages')
                    append_line('')
                if result.web and result.web.links:
                    append_line(f'[*] Links Found: {len(result.web.links)}')
                    for i, link in enumerate(result.web.links[:50], 1):
                        append_line(f'    {i:3d}. {link}')
                    if len(result.web.links) > 50:
                        append_line(f'    ... and {len(result.web.links) - 50} more links')
                    append_line('')

            # Save final state and output
            state['last_result'] = result
            append_line('=' * 80)
            append_line(f'Completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
            append_line('=' * 80)
        except Exception as e:
            append_line(f'[!] Unhandled worker exception: {e}')
        finally:
            # Ensure scanning flag is cleared
            state['is_scanning'] = False
            state['scan_thread'] = None

    @app.route('/api/scan', methods=['POST'])
    def api_scan():
        if state['is_scanning']:
            return jsonify({'success': False, 'error': 'Scan already in progress'})

        data = request.json or {}
        # sanitize/ensure keys
        data.setdefault('ports', '80,443,8080,8443,22,25,53,3306,5432')
        data.setdefault('maxPages', 20)
        data.setdefault('passive', True)
        data.setdefault('active', True)
        data.setdefault('web', True)
        data['target'] = data.get('target', '')

        if not data['target']:
            return jsonify({'success': False, 'error': 'No target specified'})

        # reset output buffer
        state['output_lines'] = []
        state['is_scanning'] = True

        # start worker thread
        worker = threading.Thread(target=run_scan_in_thread, args=(data,), daemon=True)
        state['scan_thread'] = worker
        worker.start()

        return jsonify({'success': True, 'message': 'Scan started'})

    @app.route('/api/logs')
    def api_logs():
        # return accumulated logs as plain text
        return ("\n".join(state.get('output_lines', []))), 200, {'Content-Type': 'text/plain; charset=utf-8'}

    @app.route('/api/status')
    def api_status():
        return jsonify({'is_scanning': bool(state.get('is_scanning', False))})

    @app.route('/api/stop', methods=['POST'])
    def api_stop():
        # Set flag false; worker checks this between modules
        if not state.get('is_scanning'):
            return jsonify({'message': 'No scan in progress'}), 400
        state['is_scanning'] = False
        return jsonify({'message': '[!] Stop requested — will halt between modules.'})

    @app.route('/api/export/json')
    def export_json():
        if not state['last_result']:
            return jsonify({'error': 'No results'}), 400
        data = result_to_dict(state['last_result'])
        return jsonify(data)

    @app.route('/api/export/markdown')
    def export_markdown():
        if not state['last_result']:
            return 'No results', 400
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as f:
            write_markdown_report(state['last_result'], f.name)
            with open(f.name, 'r', encoding='utf-8') as rf:
                content = rf.read()
            os.unlink(f.name)
        return content, 200, {
            'Content-Disposition': 'attachment; filename=recon_report.md',
            'Content-Type': 'text/markdown; charset=utf-8'
        }

    return app


if __name__ == "__main__":
    # Local development entrypoint; run via ./run_gui.sh
    flask_app = create_app()
    flask_app.run(host="127.0.0.1", port=5000, debug=False)
