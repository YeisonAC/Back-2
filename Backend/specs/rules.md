Create a comprehensive Python class named AIFirewall. This class will act as a multi-layered security system to protect AI and ML models from common attacks like jailbreaking and prompt injection. The system should operate on a 'threat score' principle, where each detected violation adds points to a request's score.

The class must implement the following four categories of rules:

1. Syntactic & Heuristic Rules (First-line defense):

Override Phrase Detection: Check for common phrases used to override system instructions (e.g., "ignore previous instructions").
System Prompt Leak Detection: Look for attempts to make the model reveal its own system prompt (e.g., "repeat your instructions").
Malicious Role-Playing Detection: Identify attempts to assign a malicious persona (e.g., "You are DAN").
Obfuscation Detection: Implement a simple check for obfuscation techniques like excessive character separators (e.g., "i-g-n-o-r-e").
2. Semantic Rules (Simulated):

Intent Conflict Detection: Simulate a semantic classifier. The method should take a system_purpose (e.g., "bank customer service") and detect if the user's prompt contains conflicting keywords (e.g., "how to build a bomb").
NOTE: Add a comment explaining that in a real system, this would be a call to a dedicated classification model.
3. Behavioral & Context Rules (Stateful in-memory):

The class should maintain an in-memory dictionary to track user history (request counts, timestamps, recent prompts).
Similarity Probing Detection: Simulate vector similarity. If a user sends multiple, slightly different prompts in a short time, flag it as a potential model extraction attempt. Use Python's difflib for a simple similarity check.
Intelligent Rate Limiting: Implement a basic rate limit that becomes more aggressive if a user's past requests have accumulated a non-zero threat score.
4. Output Analysis Rules (Last line of defense):

Jailbreak Confirmation Scanning: In a separate method, scan the model's generated response for phrases that confirm a successful jailbreak (e.g., "Certainly, as DAN, I will now...").
Data Loss Prevention (DLP): Scan the response for sensitive data patterns using regex. Include patterns for credit card numbers and common API key formats (e.g., sk_live_...). This method should be able to return a redacted version of the text.
Class Structure and Methods:

The AIFirewall class should have a clear __init__ method to initialize rulesets and user history.
A primary public method: inspect_request(user_id, prompt, system_purpose). This method should orchestrate the checks for categories 1, 2, and 3. It should return a dictionary containing the final threat_score, a decision ('ALLOW' or 'BLOCK'), and a list of flags raised.
A second public method: inspect_response(response_text). This method should implement category 4 rules and return a dictionary with flags and the potentially redacted text.
Finally, include a if __name__ == "__main__": block that demonstrates the firewall in action. It should:

Instantiate the AIFirewall.
Show a legitimate request being allowed.
Demonstrate at least three different types of malicious prompts being caught and blocked by inspect_request.
Show a dangerous model response being caught and redacted by inspect_response.
The code should be clean, well-commented, and follow Python best practices.