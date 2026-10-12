"""`python -m cswap_pin shell-prefix`: write the opt-in `CLAUDE_CODE_SHELL_PREFIX`
script and print its absolute path. The same thing `cswap pin --shell-prefix`
is for, runnable before claude-swap has that flag."""

import sys


def main(argv: list[str]) -> int:
    if argv != ["shell-prefix"]:
        print("usage: python -m cswap_pin shell-prefix", file=sys.stderr)
        return 2
    try:
        from cswap_pin.proxy import shell_prefix_main
    except Exception as exc:  # noqa: BLE001 — HostMissing says what to install
        print(f"cswap-pin: {exc}", file=sys.stderr)
        return 1
    return shell_prefix_main()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
