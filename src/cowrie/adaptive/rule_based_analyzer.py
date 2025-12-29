class RuleBasedAnalyzer:
    def __init__(self):
        self.suspicious_commands = {
            'wget': 2,
            'curl': 2,
            'chmod +x': 3,
            'python': 2,
            'perl': 2,
            'grep /etc/shadow': 10,
            'cat /etc/passwd': 5,
            'nmap': 5,
            'mysql': 5,
            'git': 3,
            'docker': 3,
            'sudo': 2,
            'iptables': 5,
            'sqlmap': 10,
            'g++': 3,
            'gcc': 3,
            'apt-get install': 4,
            'yum install': 4,
            'whoami': 1,
            'ifconfig': 2,
            'df': 1,
            'nc': 5,
            'netstat': 3,
            'ls': 1,
            'pwd': 1,
            'uname': 1
        }

    def analyze(self, summary):
        if not summary:
            return {'risk_score': 0, 'intent': 'Unknown'}

        score = 0
        commands = summary.get('commands', [])
        
        # Base score for any interaction (1.0 per command for gradual progression)
        score += len(commands) * 1.0
        
        for cmd in commands:
            for susp_cmd, susp_score in self.suspicious_commands.items():
                if susp_cmd in cmd:
                    score += susp_score

        # Login attempt analysis
        login_attempts = summary.get('login_attempts', [])
        failed_logins = len([l for l in login_attempts if not l['success']])
        score += min(failed_logins, 5)  # Max 5 points for brute force (was 10)
  
  	#intent classification
        intent = "Normal"
        if score > 15:
            intent = "Highly Malicious"
        elif score > 5:
            intent = "Suspicious"
        elif score > 0:
            intent = "Curious / Exploratory"

        return {
            'risk_score': score,
            'intent': intent,
            'rule_matches': [cmd for cmd in commands if any(s in cmd for s in self.suspicious_commands)]
        }

if __name__ == "__main__":
    import json
    from session_analyzer import SessionAnalyzer
    
    s_analyzer = SessionAnalyzer()
    latest = s_analyzer.get_latest_session()
    if latest:
        summary = s_analyzer.summarize_session(latest)
        rb_analyzer = RuleBasedAnalyzer()
        analysis = rb_analyzer.analyze(summary)
        print("\nRULE-BASED ANALYSIS RESULT")
        print("-" * 26)
        
        # Map common commands to readable labels for the report
        labels = []
        for match in analysis.get('rule_matches', []):
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

        # specific intent print
        if not labels and analysis['risk_score'] > 0:
             labels.append(f"General Suspicious Activity (Score: {analysis['risk_score']})")
        
        for label in set(labels):
            print(f"- {label}")
        
        if not labels:
             print("- No specific threats detected.")
        print("")
