import os
import argparse
import json
from datetime import datetime

from dotenv import load_dotenv
import anthropic
from tenacity import retry, stop_after_attempt, wait_exponential

from logger_config import get_logger
from prompt_template import SYSTEM_PROMPT, build_user_prompt
from formatter import format_report


logger = get_logger("triage")


def main():
    parser = argparse.ArgumentParser(description="AI SOC Triage Tool")

    parser.add_argument("--log", help="Path to single log file")
    parser.add_argument("--batch", help="Directory of log files")
    parser.add_argument("--save", action="store_true", help="Save output to file")
    parser.add_argument("--quiet", action="store_true", help="Minimal output")

    args = parser.parse_args()

    load_dotenv()
    api_key = os.getenv("ANTHROPIC_API_KEY")

    if not api_key:
        logger.error("API key not found. Check your .env file.")
        raise ValueError("API key not found. Check your .env file.")

    client = anthropic.Anthropic(api_key=api_key)

    log_files = []

    if args.log:
        log_files.append(args.log)
    elif args.batch:
        if not os.path.isdir(args.batch):
            logger.error(f"Batch directory not found: {args.batch}")
            raise ValueError(f"Batch directory not found: {args.batch}")

        for file in os.listdir(args.batch):
            if file.endswith(".txt"):
                log_files.append(os.path.join(args.batch, file))
    else:
        logger.error("No input provided. User must provide --log or --batch.")
        raise ValueError("Provide --log or --batch")

    if not log_files:
        logger.warning("No .txt log files found to process.")
        print("[-] No .txt log files found to process.")
        return

    total_logs = 0
    successful = 0
    failed = 0

    for log_file in log_files:
        total_logs += 1
        start_time = datetime.now()

        logger.info(f"Starting analysis for {log_file}")

        if not os.path.isfile(log_file):
            failed += 1
            logger.warning(f"Log file not found, skipping: {log_file}")
            continue

        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            log_data = f.read().strip()

        if not log_data:
            failed += 1
            logger.warning(f"Log file is empty, skipping: {log_file}")
            continue

        if len(log_data) > 50000:
            logger.warning(f"Log file exceeds 50,000 characters, truncating: {log_file}")
            log_data = log_data[:50000]

        user_prompt = build_user_prompt(log_data)

        if not args.quiet:
            print(f"[+] Sending {log_file} to AI for analysis...")

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=2, max=10))
        def call_ai():
            return client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=800,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

        try:
            response = call_ai()
        except Exception as e:
            failed += 1
            logger.error(f"API call failed for {log_file}: {e}")
            if not args.quiet:
                print(f"[-] API failed for {log_file}, skipping...")
            continue

        raw_output = response.content[0].text

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            failed += 1
            logger.error(f"Failed to parse AI response for {log_file}")
            if not args.quiet:
                print(f"[-] Failed to parse AI response for {log_file}:")
                print(raw_output)
            continue

        report = format_report(parsed, log_file)
        successful += 1

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        logger.info(f"Completed analysis for {log_file}")
        logger.info(f"Risk level: {parsed.get('risk_level')}")
        logger.info(f"MITRE technique: {parsed.get('attack_technique')}")
        logger.info(f"Processing time: {duration:.2f}s")

        if not args.quiet:
            print(report)

        if args.save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_name = os.path.basename(log_file).replace(".txt", "")
            output_file = f"output/{base_name}_report_{timestamp}.txt"

            os.makedirs("output", exist_ok=True)

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)

            logger.info(f"Report saved to {output_file}")

            if not args.quiet:
                print(f"[+] Saved: {output_file}")

    logger.info("=== SOC TRIAGE SUMMARY ===")
    logger.info(f"Total logs processed: {total_logs}")
    logger.info(f"Successful analyses: {successful}")
    logger.info(f"Failed analyses: {failed}")

    if total_logs > 0:
        success_rate = (successful / total_logs) * 100
        logger.info(f"Success rate: {success_rate:.2f}%")


if __name__ == "__main__":
    main()