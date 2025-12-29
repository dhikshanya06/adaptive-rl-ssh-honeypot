import json
import requests
from datetime import datetime
import os
from twisted.internet import threads, defer

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "tinyllama"   # or "mistral" or "llama3.2"
MITRE_FILE = os.path.join(SCRIPT_DIR, "enterprise-attack.json")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "latest_llm_output.json")

class LLMAnalyzer:
    def __init__(self):
        self.mitre_db = self.load_mitre_knowledge()

    # -----------------------------
    # LOAD MITRE DATA (RAG)
    # -----------------------------
    def load_mitre_knowledge(self):
        if not os.path.exists(MITRE_FILE):
            print(f"WARNING: MITRE file not found at {MITRE_FILE}")
            return []
            
        with open(MITRE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        techniques = []
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                # Extract tactics from kill_chain_phases
                tactics = []
                for phase in obj.get("kill_chain_phases", []):
                    if phase.get("kill_chain_name") == "mitre-attack":
                        tactics.append(phase.get("phase_name", "").replace("-", " "))

                techniques.append({
                    "id": obj.get("external_references", [{}])[0].get("external_id", ""),
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "tactics": tactics
                })
        return techniques

    # -----------------------------
    # SIMPLE RETRIEVAL
    # -----------------------------
    def retrieve_context(self, commands, labels, mitre_db, top_k=3):
        keywords = " ".join(commands).lower()
        label_text = " ".join(labels).lower()
        scored = []

        # Map specific tools to their most relevant MITRE Techniques
        tool_boosts = {
            "wget": ["T1105"], # Ingress Tool Transfer
            "curl": ["T1105"],
            "ls": ["T1083"], # File and Directory Discovery
            "cat": ["T1005", "T1552"], # Data from Local System / Unsecured Credentials
            "grep": ["T1005", "T1552"],
            "pwd": ["T1083"],
            "whoami": ["T1033"], # System Owner/User Discovery
            "id": ["T1033"],
            "ifconfig": ["T1016"], # System Network Configuration Discovery
            "ip": ["T1016"],
            "ps": ["T1057"], # Process Discovery
            "nmap": ["T1595", "T1046"], # Active Scanning, Network Service Discovery
            "sudo": ["T1548.003"], # Abuse Elevation Control Mechanism: Sudo
            "chmod": ["T1222"], # File and Directory Permissions Modification
            "chattr": ["T1222"],
            "useradd": ["T1136"], # Create Account
            "ssh": ["T1021.004"], # Remote Services: SSH
        }

        # Map Rule Labels to Tactics for stronger filtering
        label_to_tactic_map = {
            "Malware Download Attempt": ["execution", "command and control"],
            "Network Discovery / Scanning": ["discovery"],
            "Reconnaissance": ["reconnaissance"],
            "Privilege Escalation Attempt": ["privilege escalation"],
            "Persistence Attempt": ["persistence"]
        }

        target_tactics = []
        for label in labels:
            if label in label_to_tactic_map:
                target_tactics.extend(label_to_tactic_map[label])

        for t in mitre_db:
            score = 0
            name_lower = t['name'].lower()
            desc_lower = t['description'].lower()
            tech_id = t['id']
            tech_tactics = t.get('tactics', [])

            # 1. Direct Tool Boost (Highest Priority)
            # Give much higher weight to TOOLS in the CURRENT (last) command
            for i, cmd in enumerate(commands):
                cmd_lower = cmd.lower()
                # Recency factor: 1.0 for the latest command, decreasing for older ones
                recency_factor = (i + 1) / len(commands)
                
                for tool, tech_ids in tool_boosts.items():
                    if tool in cmd_lower and tech_id in tech_ids:
                        # Base boost + recency bonus
                        score += 100 * recency_factor

            # 2. Tactic Match Boost
            for tt in target_tactics:
                if tt in tech_tactics:
                    score += 30

            # 3. Keyword Match (Name) - Weighted by recency
            for k in keywords.split():
                if len(k) < 3: continue
                if k in name_lower:
                    score += 15
            
            # 4. Keyword Match (Description)
            for k in keywords.split():
                if len(k) < 4: continue
                if k in desc_lower:
                    score += 2

            # 5. Label Match in Name
            for l in labels:
                if l.lower() in name_lower:
                    score += 10

            if score > 0:
                scored.append((score, t))

        # Sort by score, then by technique ID (tie-breaker)
        scored.sort(reverse=True, key=lambda x: (x[0], x[1]['id']))
        return scored[:top_k]


    # -----------------------------
    # LOCAL LLM CALL (Blocking - Wrapped later)
    # -----------------------------
    def _call_local_llm_blocking(self, prompt, system_prompt=""):
        payload = {
            "model": MODEL,
            "prompt": prompt,
            "system": system_prompt,
            "stream": False
        }

        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=5)
            response.raise_for_status()
            data = response.json()
            if "response" in data:
                return data["response"]
            else:
                return f"Error: Ollama response missing 'response' key. JSON: {json.dumps(data)}"
        except requests.exceptions.RequestException as e:
            return f"Error connecting to Ollama: {e}"
        except Exception as e:
            return f"Error: {e}"


    # -----------------------------
    # ANALYSIS (Public Async Method)
    # -----------------------------
    @defer.inlineCallbacks
    def analyze(self, summary, rule_labels=None):
        if not summary:
            return {'intent': 'Unknown', 'skill_level': 'Unknown', 'summary': 'No session data'}
        
        commands = summary.get('commands', [])
        if rule_labels is None:
            rule_labels = []

        mitre_context = self.retrieve_context(commands, rule_labels, self.mitre_db)
        
        # Build Context Text
        context_text = ""
        if mitre_context:
            for _, t in mitre_context:
                tactics_str = ", ".join(t.get('tactics', []))
                context_text += f"- {t['id']} ({t['name']}): {t['description'][:400]}... [Tactics: {tactics_str}]\n"

        system_prompt = (
            "You are a cyber security analyst specializing in Linux honeypot activity. "
            "Your task is to analyze session data and categorize it using MITRE ATT&CK concepts. "
            "Be concise, technical, and avoid hallucinations. "
            "Do NOT mention tools or IP addresses that are not present in the provided commands. "
            "Strictly follow the output format."
        )

        prompt = f"""
[CONTEXT]
Full Session History: {commands}
MOST RECENT COMMAND: "{commands[-1] if commands else 'none'}"
Detections from Rule Engine: {rule_labels}
Relevant MITRE Techniques for {commands[-1] if commands else 'current activity'}:
{context_text}

[INSTRUCTIONS]
Categorize the session based ONLY on the Actual Commands.
The Summary MUST be a narrative sentence starting with "The user executed a command sequence...".
Describe what the commands do and the potential impact (e.g., privilege escalation, persistence).
Do NOT start with the Technique ID.

[EXAMPLE]
Commands: ['sudo', 'wget', 'exit']
Summary: The user executed a command sequence ('sudo', 'wget', 'exit') that potentially attempts to download malware or deploy a container, indicating a possible privilege escalation attempt.

[OUTPUT]
Intent: <label>
Skill level: <Beginner|Intermediate|Advanced>
Attack Stage: <label>
Summary: <Narrative description>
"""

        # Call LLM in a thread to verify blocking
        output = yield threads.deferToThread(self._call_local_llm_blocking, prompt, system_prompt)

        # Keyword extraction
        result = {
            "intent": "Unknown",
            "skill_level": "Unknown",
            "attack_stage": "Unknown",
            "summary": ""
        }

        for line in output.split('\n'):
            if ':' not in line: continue
            key_part, val_part = line.split(":", 1)
            key = key_part.strip().lower()
            val = val_part.strip()
            
            if "intent" in key:
                result["intent"] = val
            elif "skill" in key:
                result["skill_level"] = val
            elif "stage" in key:
                result["attack_stage"] = val
            elif "summary" in key:
                result["summary"] = val

        # --- POST-PROCESSING & HALLUCINATION FIXES ---
        
        # Extract MITRE info for fallback
        mitre_info = ""
        primary_tech = "Unknown Technique"
        primary = None
        if mitre_context:
            primary = mitre_context[0][1]
            primary_tech = f"{primary['name']} ({primary['id']})"
            mitre_info = f" (Ref: {primary['id']} - {primary['name']})"

        # Hallucination Check: If the summary mentions tools NOT in the commands, it's a hallucination
        hallucination_detected = False
        common_hallucinations = ["nmap", "ping", "scanning", "discovery", "192.168", "wget", "payload", "curl"]
        for word in common_hallucinations:
            if word in result["summary"].lower() and word not in str(commands).lower():
                hallucination_detected = True
                break
                
        # Heuristic fallback for Intent
        last_cmd = commands[-1].lower() if commands else ""
        if result["intent"] == "Unknown" or len(result["intent"]) > 50 or hallucination_detected:
            if any("Malware Download" in l for l in rule_labels) and ("wget" in last_cmd or "curl" in last_cmd):
                result["intent"] = "Malware Delivery"
            elif any("Privilege Escalation" in l for l in rule_labels) and ("sudo" in last_cmd or "su " in last_cmd):
                result["intent"] = "Privilege Escalation"
            elif any("Brute Force" in l for l in rule_labels):
                result["intent"] = "Brute Force"
            elif any("Database Enumeration" in l for l in rule_labels) and "mysql" in last_cmd:
                result["intent"] = "Database Enumeration"
            elif "Network" in str(rule_labels) and ("nmap" in last_cmd or "nc " in last_cmd):
                result["intent"] = "Reconnaissance (Network)"
            elif any("Reconnaissance" in l for l in rule_labels):
                result["intent"] = "System Discovery"
            elif any("Suspicious" in l for l in rule_labels):
                result["intent"] = "Suspicious Activity"

        if result["attack_stage"] == "Unknown" or len(result["attack_stage"]) > 50 or hallucination_detected:
            if "Privilege Escalation" in result["intent"]:
                result["attack_stage"] = "Privilege Escalation"
            elif "Malware" in result["intent"]:
                result["attack_stage"] = "Execution"
            elif "Database" in result["intent"]:
                 result["attack_stage"] = "Discovery"
            elif "Discovery" in result["intent"] or "Reconnaissance" in result["intent"]:
                result["attack_stage"] = "Reconnaissance"
            
        # --- Sophisticated Skill Level Heuristic ---
        if result["skill_level"] == "Unknown" or len(result["skill_level"]) > 40:
            cmd_str = str(commands).lower()
            num_cmds = len(commands)
            
            # Advanced Indicators
            advanced_tools = ["nmap", "iptables", "crontab", "systemctl", "service", "tcpdump", "lsof", "ufw", "auditctl"]
            scripting_patterns = ["|", ">", ">>", "&&", ";", "$(", "for ", "while "]
            complex_recon = ["find /", "grep -r", "ls -laR", "cat /etc/shadow", "history"]
            intermediate_tools = ["sudo", "wget", "curl", "python", "perl", "gcc", "chmod", "chattr"]

            is_advanced = any(tool in cmd_str for tool in advanced_tools) or any(p in cmd_str for p in scripting_patterns)
            is_intermediate = (
                any(tool in cmd_str for tool in intermediate_tools) or 
                any(p in cmd_str for p in complex_recon) or 
                "Malware Download Attempt" in rule_labels or
                num_cmds > 7
            )

            if is_advanced:
                result["skill_level"] = "Advanced"
            elif is_intermediate:
                result["skill_level"] = "Intermediate"
            else:
                result["skill_level"] = "Beginner"

        # Fix Summary if it's a hallucination or too generic OR missing the command list
        # Check if at least one command from the list is in the summary (to avoid generic summaries)
        commands_present = any(c in result["summary"] for c in commands)
        
        if hallucination_detected or len(result["summary"]) < 10 or not commands_present:
            cmd_text = ", ".join([f"'{c}'" for c in commands])
            # If we have a valid technique, use it. Otherwise rely on rule labels.
            matches_text = f"matches {primary_tech} behavior" if primary else "indicates suspicious activity"
            
            # Deduplicate labels for cleaner output
            unique_labels = sorted(list(set(rule_labels)))
            
            result["summary"] = f"The user executed a command sequence ({cmd_text}) that {matches_text}, triggering detections: {', '.join(unique_labels)}."

        # Remove code blocks or "Response:" artifacts
        result["summary"] = result["summary"].replace("Response:", "").strip()
        
        # Add RAG (MITRE ATT&CK) mapping to result
        result["mitre_technique"] = "N/A"
        if primary:
            result["mitre_technique"] = f"{primary['name']} ({primary['id']})"

        return result


if __name__ == "__main__":
    from session_analyzer import SessionAnalyzer
    from rule_based_analyzer import RuleBasedAnalyzer
    from twisted.internet import reactor

    @defer.inlineCallbacks
    def test():
        try:
            s_analyzer = SessionAnalyzer()
            latest = s_analyzer.get_latest_session()
            if latest:
                summary = s_analyzer.summarize_session(latest)
                
                # Get rule labels for context to simulate controller passing them
                rb = RuleBasedAnalyzer()
                rb_result = rb.analyze(summary)
                labels = []
                # Use the exact logic from adaptive_controller to pass correct labels
                rule_matches = rb_result.get('rule_matches', [])
                for match in rule_matches:
                    if 'wget' in match or 'curl' in match:
                        labels.append("Malware Download Attempt")
                    elif 'sudo' in match or 'su' in match:
                        labels.append("Privilege Escalation Attempt")
                    elif 'nmap' in match:
                        labels.append("Network Scanning Activity")
                    elif 'mysql' in match:
                        labels.append("Database Enumeration Attempt")
                    elif 'shadow' in match or 'passwd' in match:
                        labels.append("Credential Theft Attempt")
                    elif any(x in match for x in ['whoami', 'ifconfig', 'df', 'ls', 'pwd', 'uname']):
                        labels.append("System Discovery (Reconnaissance)")
                    else:
                        labels.append(f"Suspicious Command: {match}")

                llm_analyzer = LLMAnalyzer()
                print("Running LLM analysis (this may take a moment)...")
                
                # Retrieve context manually to get the MITRE details for display (RAG)
                # In analyze() we do this internaly, but here we want to show the retrieved RAG entry matches
                commands = summary.get('commands', [])
                mitre_db = llm_analyzer.mitre_db
                mitre_context = llm_analyzer.retrieve_context(commands, labels, mitre_db, top_k=1)
                
                result = yield llm_analyzer.analyze(summary, labels)

                print("\nLLM INTELLIGENCE OUTPUT")
                print("-" * 23)
                print(f"Session ID   : {latest['session_id']}")
                print(f"Intent       : {result.get('intent')}")
                print(f"Skill Level  : {result.get('skill_level')}")
                print(f"Attack Stage : {result.get('attack_stage')}")
                print(f"Summary      : {result.get('summary')}")
                
                print("\nMITRE ATT&CK EXPERT ANALYSIS (RAG)")
                print("-" * 34)
                if mitre_context:
                    top_match = mitre_context[0][1] # (score, tactic_obj)
                    print(f"Technique ID : {top_match['id']}")
                    print(f"Technique    : {top_match['name']}")
                    
                    # Wrap description (Short and Precise)
                    desc = top_match['description']
                    
                    # 1. Remove citations like (Citation: ...) cleaning up text
                    import re
                    # Remove citations
                    clean_desc = re.sub(r'\(Citation:.*?\)', '', desc)
                    # Remove newlines that might break sentences awkwardly 
                    clean_desc = clean_desc.replace('\n', ' ')
                    
                    # 2. Extract first sentence or reasonable length
                    if '. ' in clean_desc:
                        short_desc = clean_desc.split('. ')[0] + '.'
                    else:
                        short_desc = clean_desc[:200] + "..."

                    print(f"Description  : {short_desc}")
                else:
                    print("No direct MITRE ATT&CK technique mapping found for these specific commands.")
                    
            else:
                print("No sessions found.")
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            reactor.stop()

    reactor.callWhenRunning(test)
    reactor.run()
