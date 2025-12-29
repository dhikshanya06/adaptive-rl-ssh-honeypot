#!/home/dhikshanya06/cowrie/cowrie-env/bin/python3
import json
import time
import datetime
import os
import sys

# Add the adaptive directory to path so it can find its siblings
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from twisted.internet import reactor, task, defer
    from session_analyzer import SessionAnalyzer
    from rule_based_analyzer import RuleBasedAnalyzer
    from llm_analyzer import LLMAnalyzer
    from adaptive_controller import AdaptiveController
    from behavior_logger import BehaviorLogger
except ImportError as e:
    print(f"\n[!] Error: Missing dependencies: {e}")
    sys.exit(1)

# Determine the project root relative to this script
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..'))
LOG_DIR = os.path.join(PROJECT_ROOT, 'var', 'log', 'adaptive')

class LiveAdaptiveController:
    def __init__(self):
        self.s_analyzer = SessionAnalyzer()
        self.rb_analyzer = RuleBasedAnalyzer()
        self.llm_analyzer = LLMAnalyzer()
        self.controller = AdaptiveController(self.rb_analyzer, self.llm_analyzer)
        self.logger = BehaviorLogger(LOG_DIR)
        self.session_event_counts = {}

    @defer.inlineCallbacks
    def update(self):
        if not os.path.exists(self.s_analyzer.log_path):
            return

        sessions = {}
        with open(self.s_analyzer.log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    sid = event.get('session')
                    if sid:
                        if sid not in sessions:
                            sessions[sid] = []
                        sessions[sid].append(event)
                except Exception:
                    continue

        if not sessions:
            return

        for session_id, events in sessions.items():
            if len(events) == self.session_event_counts.get(session_id, 0):
                continue
            
            print(f"[DEBUG] New events detected for session {session_id}. Processing...")
            
            try:
                self.session_event_counts[session_id] = len(events)
                summary = self.s_analyzer.summarize_session({'session_id': session_id, 'events': events})
                decision = yield self.controller.decide_level(summary)
                
                level = decision['level']
                reasoning = decision['reasoning']
                llm_info = reasoning.get('llm_based', {})
                
                classification = 'MALICIOUS' if level >= 3 else ('SUSPICIOUS' if level == 2 else 'NORMAL')

                # Prepare data for behavior logger
                log_data = {
                    "commands": summary.get('commands', []),
                    "intent": llm_info.get('intent', 'Unknown'),
                    "skill_level": llm_info.get('skill_level', 'Unknown'),
                    "attack_stage": llm_info.get('attack_stage', 'Unknown'),
                    "mitre_technique": llm_info.get('mitre_technique', 'N/A'),
                    "summary": llm_info.get('summary', 'N/A'),
                    "risk_score": reasoning.get('rule_based', {}).get('risk_score', 0)
                }
                
                # Perform Adaptive Logging
                self.logger.log_event(level, session_id, log_data)
                
                # Update Session Policy File for real-time adaptation
                policy_file = os.path.join(PROJECT_ROOT, 'var', 'lib', 'cowrie', 'session_policies.json')
                policies = {}
                if os.path.exists(policy_file):
                    try:
                        with open(policy_file, 'r') as f:
                            policies = json.load(f)
                    except Exception:
                        pass
                
                policies[str(session_id)] = {"level": level}
                
                # Ensure directory exists
                os.makedirs(os.path.dirname(policy_file), exist_ok=True)
                
                with open(policy_file, 'w') as f:
                    json.dump(policies, f)
                
                # Console output for visibility during demo
                print("\n" + "="*50)
                print(f"ADAPTIVE INTELLIGENCE FOR SESSION: {session_id}")
                print(f"Detected Level : {level} ({classification})")
                print(f"Intent         : {log_data['intent']}")
                print(f"Skill Level    : {log_data['skill_level']}")
                print(f"Attack Stage   : {log_data['attack_stage']}")
                print(f"RAG Mapping    : {log_data['mitre_technique']}")
                print(f"Summary        : {log_data['summary']}")
                print(f"Status         : Policy Updated for Live Session")
                print("="*50 + "\n")


            except Exception as e:
                print(f"[!] Error processing session {session_id}: {e}")


    def run(self):
        print("[*] Loop starting...")
        
        # Catch up with existing logs to avoid replaying history
        print("[*] Synchronizing with existing logs...")
        sessions = self.s_analyzer.parse_logs()
        self.session_event_counts = {}
        for session_id, events in sessions.items():
            self.session_event_counts[session_id] = len(events)
        print(f"[*] Waiting for NEW activity...")

        # Poll every 1 second for better responsiveness
        l = task.LoopingCall(self.update)
        l.start(1.0)
        reactor.run()

if __name__ == "__main__":
    live_controller = LiveAdaptiveController()
    print("[*] Starting Live Adaptive Controller...")
    live_controller.run()
