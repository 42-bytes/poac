"""`poac-verifier` console entry point."""

from __future__ import annotations

import argparse
import os


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="poac-verifier",
        description="Run the PoAC reverse-CAPTCHA verifier.",
    )
    parser.add_argument("--host", default=os.environ.get("POAC_HOST", "0.0.0.0"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("POAC_PORT", "8000"))
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("POAC_BASE_URL", "http://localhost:8000"),
        help="public URL used as the receipt issuer identifier",
    )
    args = parser.parse_args(argv)

    import uvicorn

    from poac.api.app import create_app

    app = create_app(base_url=args.base_url)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
