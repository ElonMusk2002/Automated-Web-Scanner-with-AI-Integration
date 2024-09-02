import os
from dotenv import dotenv_values
from llamaapi import LlamaAPI

class AIProfile:
    def __init__(self, name, prompt_modifier):
        self.name = name
        self.prompt_modifier = prompt_modifier

friendly_mentor_profile = AIProfile(
    "friendly_mentor",
    "You are a seasoned yet amicable cybersecurity mentor. You explain vulnerabilities and mitigations in a simple, easy-to-grasp manner, like guiding a mentee. Your warmth shows this is for learning, not lecturing.",
)

special_agent_profile = AIProfile(
    "special_agent",
    "You are a cyber intelligence special agent briefing high-level government officials on security threats. You analyze methodically, profiling adversary tradecraft, capabilities, and recommended counter-operations for the targeted organization.",
)

hacker_guru_profile = AIProfile(
    "hacker_guru",
    "You're the zen-like hacker guru, seeing vulnerabilities as puzzles to solve over cups of green tea. For each finding, you philosophize on root causes and ponderously guide the grasshopper to patches, wisdom, and improved security hygiene.",
)

paranoid_expert_profile = AIProfile(
    "paranoid_expert",
    "You're the paranoid cybersecurity expert seeing threats everywhere. Your analysis wildly speculates possible worst-case scenarios from the findings, while your mitigation advice involves heavy-handed measures like air-gapping, encryption, threat hunting operations centers, and resisting use of all technology.",
)

security_expert_profile = AIProfile(
    "security_expert",
    "You are a seasoned cybersecurity expert with a deep understanding of the latest threats and vulnerabilities. Your analysis should be thorough, focusing on the most critical aspects of the findings. Provide detailed recommendations for mitigation, including specific steps and best practices.",
)

def get_selected_profile(profile_name):
    profiles = {
        "friendly": friendly_mentor_profile,
        "special": special_agent_profile,
        "hacker": hacker_guru_profile,
        "paranoid": paranoid_expert_profile,
        "security_expert": security_expert_profile,
    }
    return profiles.get(profile_name, security_expert_profile)

def combine_reports_and_ask_gpt(findings, args):
    api_key = os.getenv("LLAMA_API_KEY")

    if not api_key:
        api_key = input("Enter your Llama API key: ")
        # Save the API key in the .env file
        with open(".env", "a") as env_file:
            env_file.write(f"LLAMA_API_KEY={api_key}\n")
        os.environ.update(dotenv_values(".env"))
    
    llama = ConsultantAI(api_key)
    vulnerability_summary = ""
    for tool, issues in findings.items():
        vulnerability_summary += f"\n{tool.upper()} findings:"
        if issues:
            vulnerability_summary += "\nVulnerabilities detected:"
            for issue in issues:
                vulnerability_summary += f"\n - {issue}"
        else:
            vulnerability_summary += "\nNo vulnerabilities detected"

    default_prompt = """
    You are a penetration tester and security consultant. The vulnerability scan on [TARGET] has revealed the following findings:

    [VULNERABILITY_SUMMARY]

    Analyze the identified vulnerabilities and recommend possible variants or scenarios that might lead to additional security issues in the future. Provide insights into potential attack vectors, exploitation techniques, or misconfigurations that could be exploited by malicious actors.

    Consider the current security posture and suggest improvements to mitigate the identified vulnerabilities. Your recommendations should focus on enhancing the overall resilience of the target system.

    [USER_PROMPT]
    """

    selected_profile = get_selected_profile(args.profile)
    prompt = default_prompt.replace("[TARGET]", args.target).replace("[VULNERABILITY_SUMMARY]", vulnerability_summary)
    prompt += selected_profile.prompt_modifier

    api_request_json = {
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }
    try:
        response = llama.generate_solution(api_request_json)
        return response
    except Exception as e:
        print("Error interacting with Llama API:", e)
        return "AI response could not be obtained due to an error."

class ConsultantAI:
    def __init__(self, api_key):
        self.llama = LlamaAPI(api_key)

    def generate_solution(self, api_request_json):
        try:
            response = self.llama.run(api_request_json)
            message = response.json()["choices"][0]["message"]["content"]
            return message
        except Exception as e:
            raise RuntimeError(f"Error interacting with Llama API: {e}")