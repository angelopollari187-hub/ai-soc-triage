import os
import argparse
import json
from datetime import datetime

from dotenv import load_dotenv
import anthropic

from prompt_template import SYSTEM_PROMPT, build_user_prompt
from formatter import format_report


def main():
    parser = argparse.ArgumentParser(description="AI SOC Triage Tool")

    parser.add_argument("--log", help="Path to single log file")
    parser.add_argument("--batch", help="Directory of log files")

    parser.add_argument("--save", action="store_true", help="Save output to file")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")

    args = parser.parse_args()

    # Load API key
    load_dotenv()
    api_key = os.getenv("ANTHROPIC_API_KEY")

    if not api_key:
        raise ValueError("API key not found. Check your .env file.")

    client = anthropic.Anthropic(api_key=api_key)

    # Build list of log files
    log_files = []

    if args.log:
        log_files.append(args.log)
    elif args.batch:
        for file in os.listdir(args.batch):
            if file.endswith(".txt"):
                log_files.append(os.path.join(args.batch, file))
    else:
        raise ValueError("Provide --log or --batch")

    # Process each log file
    for log_file in log_files:
        with open(log_file, "r") as f:
            log_data = f.read()

        user_prompt = build_user_prompt(log_data)

        if not args.quiet:
            print(f"[+] Sending {log_file} to AI for analysis...")

        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=800,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )

        raw_output = response.content[0].text

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            print(f"[-] Failed to parse AI response for {log_file}:")
            print(raw_output)
            continue

        report = format_report(parsed, log_file)

        if not args.quiet:
            print(report)

        if args.save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = os.path.basename(log_file).replace(".txt", "")
            output_file = f"output/{base_name}_report_{timestamp}.txt"

            with open(output_file, "w") as f:
                f.write(report)

            print(f"[+] Saved: {output_file}")

if __name__ == "__main__":
    main()