from pathlib import Path

def run(args):
	workspace = Path(args.path)

	if not workspace.exists():
		print(f"[-] Workspace not found: {workspace}")
		return 1 

	reports = Path("reports")
	reports.mkdir(exist_ok=True)

	report_name = workspace.name + ".md"
	report = reports / report_name

	report.write_text(f"""# {workspace.name}

  ## Executive Summary

  ## Target

  ## Security Boundary

  ## Attack Surface

  ## Steps to Reproduce

  1.

  2.

  3.

  ## Expected  Behavior

  ## Observed  Behavior

  ## Impact

  ## Evidence 

  ### Requests

  ### Responses

  ### Screenshots

  ### Video

  ## Timeline

  ## Notes

  ## Suggested Remediation

  """)

	print(f"[+] Report Template created:") 
	print(report)

	return 0

