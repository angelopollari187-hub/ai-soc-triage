import os
import argparse
import json
from datetime import datetime

from tenacity import retry, stop_after_attempt, wait_exponential
from dotenv import load_dotenv
import anthropic

from logger_config import get_logger
from prompt_template import SYSTEM_PROMPT, build_user_prompt
from enrichment import extract_public_ip, enrich_ip
from formatter import format_report
from notifier import send_slack_alert
from csv_exporter import append_alert_to_csv

logger = get_logger("triage")


def main():
    parser = argparse.ArgumentParser(description="AI SOC Triage Tool")

    parser.add_argument("--log", help="Path to single log file")
    parser.add_argument("--batch", help="Directory of log files")
    parser.add_argument("--save", action="store_true", help="Save output to file")
    parser.add_argument("--json", action="store_true", help="Save structured JSON alert output")
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
        for file in os.listdir(args.batch):
            if file.endswith(".txt"):
                log_files.append(os.path.join(args.batch, file))
    else:
        logger.error("No input provided. Must provide --log or --batch.")
        raise ValueError("Provide --log or --batch")

    total = 0
    success = 0
    failed = 0

    for log_file in log_files:
        total += 1
        start_time = datetime.now()

        logger.info(f"Starting analysis for {log_file}")

        if not os.path.isfile(log_file):
            logger.warning(f"File not found: {log_file}")
            failed += 1
            continue

        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            log_data = f.read().strip()

        if not log_data:
            logger.warning(f"Empty log file: {log_file}")
            failed += 1
            continue

        if len(log_data) > 50000:
            logger.warning(f"Truncating large log file: {log_file}")
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
            logger.error(f"API call failed for {log_file}: {e}")
            print(f"[-] API failed for {log_file}")
            failed += 1
            continue

        raw_output = response.content[0].text

        try:
            parsed = json.loads(raw_output)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse AI response for {log_file}")
            if not args.quiet:
                print(raw_output)
            failed += 1
            continue

        now = datetime.now()

        # Analyst-friendly timestamp for Slack, JSON content, and CSV rows
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")

        # File-safe timestamp for report/JSON filenames
        file_timestamp = now.strftime("%Y%m%d_%H%M%S")

        # SOC-style incident ID
        incident_id = f"INC-{now.strftime('%Y%m%d-%H%M%S')}"

        report = format_report(parsed, log_file)

        public_ip = extract_public_ip(log_data)
        enrichment = enrich_ip(public_ip)

        logger.info(f"Completed analysis for {log_file}")
        logger.info(f"Risk level: {parsed.get('risk_level')}")
        logger.info(f"MITRE technique: {parsed.get('attack_technique')}")
        logger.info(f"Enriched IP: {enrichment.get('ip')}")
        logger.info(f"Enrichment status: {enrichment.get('enrichment_status')}")

        risk = parsed.get("risk_level", "").upper()

        alert = {
            "incident_id": incident_id,
            "source_file": log_file,
            "timestamp": timestamp,
            "status": "OPEN",
            "risk_level": parsed.get("risk_level"),
            "mitre_technique": parsed.get("attack_technique"),
            "confidence": parsed.get("confidence"),
            "false_positive_likelihood": parsed.get("false_positive_likelihood"),
            "recommended_action": parsed.get("recommended_action"),
            "enrichment": enrichment,
        }

        if risk in ["HIGH", "CRITICAL"]:
            slack_alert = alert.copy()
            slack_alert["risk_level"] = risk
            send_slack_alert(slack_alert)

        elapsed = (datetime.now() - start_time).total_seconds()
        logger.info(f"Processing time: {elapsed:.2f}s")

        if not args.quiet:
            print(report)

        if args.save:
            base_name = os.path.basename(log_file).replace(".txt", "")
            output_file = f"output/{base_name}_report_{file_timestamp}.txt"

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report)

            logger.info(f"Report saved to {output_file}")

            if not args.quiet:
                print(f"[+] Saved: {output_file}")

        if args.json:
            base_name = os.path.basename(log_file).replace(".txt", "")
            json_file = f"output/{base_name}_alert_{file_timestamp}.json"

            append_alert_to_csv(alert)

            with open(json_file, "w", encoding="utf-8") as f:
                json.dump(alert, f, indent=4)

            logger.info(f"JSON alert saved to {json_file}")

            if not args.quiet:
                print(f"[+] JSON Saved: {json_file}")

        success += 1

    logger.info("=== SOC TRIAGE SUMMARY ===")
    logger.info(f"Total logs processed: {total}")
    logger.info(f"Successful analyses: {success}")
    logger.info(f"Failed analyses: {failed}")

    if total > 0:
        success_rate = (success / total) * 100
        logger.info(f"Success rate: {success_rate:.2f}%")


if __name__ == "__main__":
    main()