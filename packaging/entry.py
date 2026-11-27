import multiprocessing
import sys


def run() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "__volatility__":
        del sys.argv[1]
        from volatility3.cli import main as vol_main

        return vol_main()
    if len(sys.argv) == 1:
        from investigation import console_menu

        return console_menu.run_menu()
    from investigation.cli import main

    return main()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(run())
