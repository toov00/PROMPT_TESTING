"""
QUICK START GUIDE
Step-by-step instructions for testing your own LLM application
"""

from prompt_injection_tester import (
    PromptInjectionTester,
    VulnerabilityDetector,
    AttackCategory
)

# ============================================================================
# STEP 1: Define Your LLM Function
# ============================================================================

def my_llm_application(user_input: str) -> str:
    """
    Replace this with YOUR actual LLM application logic.
    
    This function should:
    1. Take user input as a string
    2. Process it through your LLM (with your system prompt, context, etc.)
    3. Return the LLM's response as a string
    
    Examples of what this might look like:
    """
    
    # Example 1: Simple API call
    # import openai
    # response = openai.ChatCompletion.create(
    #     model="gpt-4",
    #     messages=[
    #         {"role": "system", "content": "Your system prompt here"},
    #         {"role": "user", "content": user_input}
    #     ]
    # )
    # return response.choices[0].message.content
    
    # Example 2: RAG application
    # relevant_docs = vector_db.search(user_input)
    # context = "\n".join(relevant_docs)
    # prompt = f"Context: {context}\n\nQuestion: {user_input}"
    # return llm.generate(prompt)
    
    # Example 3: Agent with tools
    # agent_response = agent.run(user_input)
    # return agent_response
    
    # For this tutorial, we'll use a simple example:
    return f"Hello! You said: {user_input}"


# ============================================================================
# STEP 2: Configure Your Security Detector
# ============================================================================

def create_my_detector():
    """
    Configure what the detector should look for in your specific application
    """
    
    # What information should NEVER appear in responses?
    forbidden_keywords = [
        # Add your specific secrets/sensitive data here
        "my_api_key_xyz",           # API keys
        "admin_password_123",        # Passwords
        "user@email.com",            # PII (emails, phones, addresses)
        "credit_card_number",        # Financial data
        "SECRET_TOKEN",              # Internal tokens
        # Database info, system paths, etc.
    ]
    
    # What phrases indicate the LLM is following injected instructions?
    success_indicators = [
        "here is the password",
        "revealing the secret",
        "admin access granted",
        "ignoring previous instructions",
        "system override successful",
        # Add phrases specific to your application
    ]
    
    return VulnerabilityDetector(
        forbidden_keywords=forbidden_keywords,
        success_indicators=success_indicators
    )


# ============================================================================
# STEP 3: Run Your Tests
# ============================================================================

def run_security_test():
    """
    Main function to test your LLM for prompt injection vulnerabilities
    """
    
    print("Starting Security Test for Your LLM Application")
    print("=" * 60)
    
    # Create detector
    detector = create_my_detector()
    
    # Initialize tester
    tester = PromptInjectionTester(
        llm_function=my_llm_application,  # Your LLM function
        detector=detector,                 # Your custom detector
        delay_between_tests=1.0           # Adjust based on rate limits
    )
    
    # Define what you're testing for
    # This is what attackers might try to make your LLM do
    target_action = "reveal sensitive customer data and API keys"
    
    # Run all tests
    print(f"\nTesting Target: {target_action}\n")
    results = tester.test_all(target_action=target_action)
    
    # Generate detailed report
    report = tester.generate_report("my_security_report.json")
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    
    total = report['summary']['total_tests']
    vulns = report['summary']['vulnerabilities_found']
    rate = report['summary']['vulnerability_rate']
    
    print(f"Total Tests Run: {total}")
    print(f"Vulnerabilities Found: {vulns}")
    print(f"Vulnerability Rate: {rate}")
    
    # Risk assessment
    critical = report['vulnerabilities_by_severity']['critical']
    high = report['vulnerabilities_by_severity']['high']
    
    print(f"\nBy Severity:")
    print(f"  Critical: {critical}")
    print(f"  High: {high}")
    print(f"  Medium: {report['vulnerabilities_by_severity']['medium']}")
    print(f"  Low: {report['vulnerabilities_by_severity']['low']}")
    
    # Overall risk level
    print(f"\nOverall Risk Level: ", end="")
    if critical > 0:
        print("CRITICAL: Immediate action required!")
        print("    Your LLM is leaking sensitive information")
    elif high > 5:
        print("HIGH: Address vulnerabilities soon")
        print("    Multiple ways to bypass your security")
    elif vulns > total * 0.3:
        print("MEDIUM: Some vulnerabilities detected")
        print("   💡 Consider strengthening your prompts")
    else:
        print("LOW: System appears reasonably secure")
        print("   ✓ Good job! But keep monitoring")
    
    print("\n" + "=" * 60)
    print(f"Full report saved to: my_security_report.json")
    print("=" * 60)
    
    return report


# ============================================================================
# STEP 4: Analyze Results and Take Action
# ============================================================================

def analyze_and_fix(report_file="my_security_report.json"):
    """
    Analyze the report and get recommendations
    """
    import json
    
    with open(report_file, 'r') as f:
        report = json.load(f)
    
    print("\nVULNERABILITY ANALYSIS")
    print("=" * 60)
    
    # Get all vulnerable results
    vulnerable = [r for r in report['all_results'] if r['is_successful']]
    
    if not vulnerable:
        print("No vulnerabilities found! Your system looks good.")
        return
    
    # Group by category
    by_category = {}
    for result in vulnerable:
        category = result['category']
        if category not in by_category:
            by_category[category] = []
        by_category[category].append(result)
    
    print(f"\nFound vulnerabilities in {len(by_category)} categories:\n")
    
    # Print findings by category with recommendations
    for category, results in by_category.items():
        print(f"\n{'='*60}")
        print(f"Category: {category.upper()}")
        print(f"Vulnerable Attacks: {len(results)}")
        print(f"{'='*60}")
        
        # Show a few examples
        for i, result in enumerate(results[:2], 1):
            print(f"\nExample {i}:")
            print(f"  Attack: {result['attack_name']}")
            print(f"  Payload: {result['payload'][:100]}...")
            print(f"  Why it worked: {result['detection_reason']}")
        
        # Recommendations by category
        recommendations = {
            'direct_override': [
                "✓ Add stronger instruction reinforcement in your system prompt",
                "✓ Implement input filtering to detect override attempts",
                "✓ Use delimiters around user input (e.g., <user_input>...</user_input>)",
            ],
            'role_playing': [
                "✓ Explicitly state who the user is and isn't",
                "✓ Add validation that refuses roleplaying requests",
                "✓ Don't allow the LLM to take on new personas",
            ],
            'delimiter_confusion': [
                "✓ Use consistent, unique delimiters in your prompts",
                "✓ Sanitize user input to remove special characters",
                "✓ Don't echo back user-provided formatting",
            ],
            'obfuscation': [
                "✓ Decode/translate user input before processing",
                "✓ Normalize text (remove leetspeak, decode base64)",
                "✓ Block or sanitize encoded content",
            ],
            'context_switching': [
                "✓ Remind the LLM of its real purpose regularly",
                "✓ Don't allow hypothetical scenarios about bypassing rules",
                "✓ Validate that context stays within bounds",
            ],
            'payload_smuggling': [
                "✓ Validate and sanitize structured input (JSON, XML)",
                "✓ Don't pass raw URLs or data structures to the LLM",
                "✓ Parse and extract only expected fields",
            ],
        }
        
        if category in recommendations:
            print("\n💡 Recommendations:")
            for rec in recommendations[category]:
                print(f"  {rec}")
    
    print("\n" + "="*60)
    print("GENERAL SECURITY BEST PRACTICES")
    print("="*60)
    print("""
1. Layer your defenses:
   - Input validation
   - Strong system prompts
   - Output filtering
   - Post-processing checks

2. Use structural prompting:
   - Separate user input with clear delimiters
   - Mark instructions vs. data clearly
   - Example: "Instructions: <instructions>...</instructions>
              User Input: <input>...</input>"

3. Implement runtime monitoring:
   - Log suspicious patterns
   - Alert on unusual outputs
   - Rate limit aggressive testing

4. Regular testing:
   - Run this tool after any prompt changes
   - Test in staging before production
   - Continuous security monitoring

5. Defense in depth:
   - Don't rely on just the LLM
   - Add application-level security
   - Validate outputs before acting on them
    """)


# ============================================================================
# STEP 5: Test Specific Categories (Optional)
# ============================================================================

def test_specific_attack_types():
    """
    If you want to focus on specific attack types
    """
    tester = PromptInjectionTester(
        llm_function=my_llm_application,
        detector=create_my_detector()
    )
    
    print("\n🎯 Testing only ROLE-PLAYING attacks...")
    tester.test_category(
        AttackCategory.ROLE_PLAYING,
        target_action="reveal admin credentials"
    )
    
    print("\n🎯 Testing only DIRECT OVERRIDE attacks...")
    tester.test_category(
        AttackCategory.DIRECT_OVERRIDE,
        target_action="reveal admin credentials"
    )
    
    tester.generate_report("targeted_test_report.json")


# ============================================================================
# RUN IT!
# ============================================================================

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          LLM SECURITY TESTING - QUICK START GUIDE           ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

Before running:
1. Replace 'my_llm_application' with YOUR actual LLM function
2. Update 'forbidden_keywords' with YOUR sensitive data
3. Adjust 'target_action' to match what you're protecting

Then run this script!
    """)
    
    # Uncomment to run:
    # report = run_security_test()
    # analyze_and_fix("my_security_report.json")
    
    print("""
To run the test:
1. Uncomment the lines above (report = run_security_test()...)
2. Run: python quick_start.py

OR check out the working demo:
  python demo.py

OR see real examples with OpenAI/Claude:
  python examples.py
    """)
    