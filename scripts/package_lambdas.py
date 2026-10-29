from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"
BUILD = ROOT / ".build"

REQUIRED = [
    "app/__init__.py",
    "app/detector.py",
    "app/finding_router.py",
    "app/response.py",
]


def main():
    for relative in REQUIRED:
        if not (ROOT / relative).is_file():
            raise ValueError(f"Missing required file: {relative}")

    BUILD.mkdir(exist_ok=True)

    files = sorted(APP.rglob("*.py"))

    if not files:
        raise ValueError("No Python application files found.")

    for name in ("detector.zip", "finding-router.zip", "response.zip"):
        destination = BUILD / name

        with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
            for path in files:
                relative = path.relative_to(ROOT).as_posix()

                # Stable metadata makes repeated builds reproducible
                # for identical source bytes and build environment.
                info = ZipInfo(
                    filename=relative,
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                info.compress_type = ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16

                archive.writestr(info, path.read_bytes())

        with ZipFile(destination) as archive:
            bad_file = archive.testzip()

            if bad_file:
                raise ValueError(f"Invalid ZIP entry: {bad_file}")

            names = archive.namelist()

            for relative in REQUIRED:
                if relative not in names:
                    raise ValueError(
                        f"{destination.name} missing {relative}"
                    )

        print(f"Built and checked: {destination.name}")


if __name__ == "__main__":
    main()