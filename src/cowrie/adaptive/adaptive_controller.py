from twisted.internet import defer

class AdaptiveController:
    def __init__(self, rb_analyzer, llm_analyzer):
        self.rb_analyzer = rb_analyzer
        self.llm_analyzer = llm_analyzer

    @defer.inlineCallbacks
    def decide_level(self, summary):
        if not summary:
            return 0  # Stealth by default

        rb_result = self.rb_analyzer.analyze(summary)
        
        # Extract labels to guide LLM RAG
        labels = []
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

        llm_result = yield self.llm_analyzer.analyze(summary, labels)

        risk_score = rb_result.get('risk_score', 0)
        intent = llm_result.get('intent', rb_result.get('intent', 'Unknown'))
        skill_level = llm_result.get('skill_level', 'Unknown')

        # Logic to map analysis to level (0-3) - Adjusted for faster progression (2-3 commands)
        level = 0
        
        # Lowered thresholds: 
        # Score > 2 (approx 2-3 commands) -> Level 1
        # Score > 5 (approx 5 commands) -> Level 2
        # Score > 10 -> Level 3
        if risk_score >= 15:
            level = 3
        elif risk_score >= 8:
            level = 2
        elif risk_score > 1:
            level = 1
        else:
            level = 0

        # Adjust based on LLM intent (Case-insensitive matching)
        intent_lower = intent.lower()
        if any(x in intent_lower for x in ["malware", "highly malicious", "exploit", "credential", "steal", "shell"]):
            level = max(level, 3)
        elif any(x in intent_lower for x in ["suspicious", "scanning", "escalation", "nmap", "privilege"]):
            level = max(level, 2)
        elif any(x in intent_lower for x in ["exploratory", "curious", "benign", "reconnaissance", "discovery"]):
            level = max(level, 1)
        
        # Adjust based on skill level
        if any(x in skill_level.lower() for x in ["advanced", "expert"]):
            level = max(level, 3)
        elif "intermediate" in skill_level.lower():
            level = max(level, 2)

        return {
            'level': level,
            'reasoning': {
                'rule_based': rb_result,
                'llm_based': llm_result
            }
        }

if __name__ == "__main__":
    from twisted.internet import reactor
    from session_analyzer import SessionAnalyzer
    from rule_based_analyzer import RuleBasedAnalyzer
    from llm_analyzer import LLMAnalyzer
    import json
    import datetime

    @defer.inlineCallbacks
    def run_controller_test():
        s_analyzer = SessionAnalyzer()
        latest = s_analyzer.get_latest_session()
        
        if not latest:
            print("No sessions found.")
            reactor.stop()
            return

        rb_analyzer = RuleBasedAnalyzer()
        llm_analyzer = LLMAnalyzer()
        controller = AdaptiveController(rb_analyzer, llm_analyzer)
        
        decision = yield controller.decide_level(s_analyzer.summarize_session(latest))
        
        print("\nADAPTIVE DECISION FOR LATEST SESSION")
        print("-" * 36)
        print(f"Session ID      : {latest['session_id']}")
        
        # Derive detected labels similar to rule_based_analyzer logic
        labels = []
        rule_matches = decision['reasoning']['rule_based'].get('rule_matches', [])
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
        
        # fallback if valid risk score
        if not labels and decision['reasoning']['rule_based']['risk_score'] > 0:
             labels.append("Suspicious Activity Detected")

        # Dedup labels for cleaner output
        unique_labels = list(set(labels))
        print(f"Detected Labels : {unique_labels}")
        
        llm_summary = decision['reasoning']['llm_based'].get('summary', 'N/A')
        print(f"LLM Summary     : {llm_summary}\n")
        
        print("Policy Output:")
        policy_output = {
            "timestamp": datetime.datetime.now().isoformat(),
            "interaction_level": "VERY_HIGH" if decision['level'] == 3 else ("HIGH" if decision['level'] == 2 else ("MEDIUM" if decision['level'] == 1 else "LOW")),
            "command_realism": "FULL" if decision['level'] >= 2 else "PARTIAL",
            "filesystem_depth": "DEEP" if decision['level'] >= 2 else "SHALLOW",
            "response_delay": 0,
            "logging_level": "MAXIMUM",
            "reason": decision['reasoning']['llm_based'].get('intent', 'Unknown')
        }
        print(json.dumps(policy_output, indent=4))
        
        reactor.stop()

    reactor.callWhenRunning(run_controller_test)
    reactor.run()
