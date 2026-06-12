"""
Execute the code security audit workflow against a target codebase.

Usage:
    python scripts/run_audit.py --target C:\\path\\to\\repo
    python scripts/run_audit.py --target C:\\path\\to\\repo --provider minimax
    python scripts/run_audit.py --target C:\\path\\to\\repo --provider minimax --judgment-provider anthropic
    python scripts/run_audit.py --target C:\\path\\to\\repo --exposure Internet-facing

Default routing: bulk scanning nodes use --provider; judgment-heavy phases
(prioritization, consolidation, comparison) use --judgment-provider when given,
otherwise --provider.

Coordination mode is detected automatically: COORDINATED if a complete
<target>-threat-model/ exists, else STANDALONE (which asks the deployment
exposure question interactively unless --exposure is passed).

The audit resumes from audit_state/STATE.md if interrupted -- re-run the same
command and completed phases are skipped.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from audit.executor import AuditExecutor, detect_coordination_mode
from audit.providers import PROVIDER_CONFIGS, ModelRouter

EXPOSURE_CHOICES = ["Internet-facing", "Internal", "Hybrid", "Unknown"]


def main():
    parser = argparse.ArgumentParser(
        description="Execute the code security audit workflow against a target codebase.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target", required=True, metavar="DIR",
                        help="Path to the codebase to audit")
    parser.add_argument("--provider", default="minimax",
                        choices=list(PROVIDER_CONFIGS),
                        help="Provider for bulk scanning phases (default: minimax)")
    parser.add_argument("--judgment-provider", default=None,
                        choices=list(PROVIDER_CONFIGS),
                        help="Provider for judgment phases (default: same as --provider)")
    parser.add_argument("--model", default=None, help="Model override for bulk phases")
    parser.add_argument("--judgment-model", default=None,
                        help="Model override for judgment phases")
    parser.add_argument("--exposure", default=None, choices=EXPOSURE_CHOICES,
                        help="Deployment exposure (STANDALONE mode; skips the prompt)")
    parser.add_argument("--stop-after", default=None,
                        choices=["discovery", "prioritization", "security"],
                        help="Stop early for a cheap validation run")
    parser.add_argument("--only-partition", default=None, metavar="ID",
                        help="Review only this partition id (debug / re-run a single worker)")
    args = parser.parse_args()

    target_dir = Path(args.target)
    if not target_dir.is_dir():
        print(f"Error: target directory not found: {target_dir}")
        sys.exit(1)

    mode, tm_dir = detect_coordination_mode(target_dir)
    router = ModelRouter(args.provider, args.judgment_provider,
                         args.model, args.judgment_model)

    print(f"\n{'='*60}\n  Code Security Audit Workflow\n{'='*60}")
    print(f"  Target            : {target_dir}")
    print(f"  Coordination mode : {mode}")
    if tm_dir:
        print(f"  Threat model      : {tm_dir}")
    print(f"  Bulk phases       : {router.bulk[2]} / {router.bulk[1]}")
    print(f"  Judgment phases   : {router.judgment[2]} / {router.judgment[1]}")
    print(f"  Output            : {target_dir / 'audit_state'}")
    print(f"{'='*60}")

    executor = AuditExecutor(target_dir, router, exposure_override=args.exposure,
                             stop_after=args.stop_after,
                             only_partition=args.only_partition)
    executor.run()


if __name__ == "__main__":
    main()
