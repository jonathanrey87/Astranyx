import plistlib
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_MEMBERS = 10_000
MAX_ARCHIVE_MEMBER_BYTES = 1 * 1024**3
MAX_ARCHIVE_EXPANDED_BYTES = 2 * 1024**3
COPY_CHUNK_BYTES = 1024 * 1024


def find_app_dir(path: Path) -> Path | None:
    if path.is_dir() and path.suffix == ".app":
        return path

    if path.is_dir():
        for app in path.rglob("*.app"):
            return app

    return None


def load_plist(app_dir: Path) -> dict:
    plist_path = app_dir / "Info.plist"
    if not plist_path.exists():
        raise FileNotFoundError(f"Info.plist not found: {plist_path}")

    with plist_path.open("rb") as f:
        return plistlib.load(f)


def extract_ipa(ipa_path: Path) -> Path:
    temp = Path(tempfile.mkdtemp(prefix="astranyx_ipa_"))

    try:
        with zipfile.ZipFile(ipa_path, "r") as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ValueError(
                    f"IPA contains too many entries ({len(members)}; "
                    f"maximum {MAX_ARCHIVE_MEMBERS})"
                )

            destinations: set[tuple[str, ...]] = set()
            expanded_bytes = 0
            validated: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []

            for member in members:
                destination = _validated_member_destination(member)
                if destination in destinations:
                    raise ValueError(
                        f"IPA contains a duplicate path: {member.filename}"
                    )
                destinations.add(destination)

                if member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ValueError(
                        f"IPA entry exceeds the size limit: {member.filename}"
                    )
                expanded_bytes += member.file_size
                if expanded_bytes > MAX_ARCHIVE_EXPANDED_BYTES:
                    raise ValueError("IPA exceeds the expanded size limit")

                validated.append((member, destination))

            file_paths = {
                destination for member, destination in validated if not member.is_dir()
            }

            for _, destination in validated:
                if any(
                    destination[:index] in file_paths
                    for index in range(1, len(destination))
                ):
                    raise ValueError("IPA contains a file/directory path conflict")

            extracted_bytes = 0
            for member, destination in validated:
                target = temp.joinpath(*destination)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member, "r") as source, target.open("xb") as output:
                    member_bytes = 0
                    while chunk := source.read(COPY_CHUNK_BYTES):
                        member_bytes += len(chunk)
                        extracted_bytes += len(chunk)
                        if member_bytes > MAX_ARCHIVE_MEMBER_BYTES:
                            raise ValueError(
                                f"IPA entry exceeds the size limit: {member.filename}"
                            )
                        if extracted_bytes > MAX_ARCHIVE_EXPANDED_BYTES:
                            raise ValueError("IPA exceeds the expanded size limit")
                        output.write(chunk)
    except BaseException:
        shutil.rmtree(temp, ignore_errors=True)
        raise

    return temp


def _validated_member_destination(member: zipfile.ZipInfo) -> tuple[str, ...]:
    name = member.filename
    if not name or "\x00" in name or "\\" in name or name.startswith("/"):
        raise ValueError(f"IPA contains an unsafe path: {name!r}")

    raw_parts = name.rstrip("/").split("/")
    if not raw_parts or any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError(f"IPA contains an unsafe path: {name!r}")
    if len(raw_parts[0]) == 2 and raw_parts[0][0].isalpha() and raw_parts[0][1] == ":":
        raise ValueError(f"IPA contains an unsafe path: {name!r}")

    path = PurePosixPath(*raw_parts)
    mode = member.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise ValueError(f"IPA contains an unsupported entry type: {name}")
    if member.flag_bits & 0x1:
        raise ValueError(f"IPA contains an encrypted entry: {name}")

    return path.parts


def get_url_schemes(info: dict) -> list[str]:
    schemes = []
    for entry in info.get("CFBundleURLTypes", []) or []:
        schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    return sorted(set(schemes))


def run(args):
    target = Path(args.file)

    if not target.exists():
        print(f"[-] Target not found: {target}")
        return 1

    temp_dir = None

    try:
        if target.suffix == ".ipa":
            temp_dir = extract_ipa(target)
            app_dir = find_app_dir(temp_dir / "Payload")
        else:
            app_dir = find_app_dir(target)

        if not app_dir:
            print("[-] Could not locate .app directory")
            return 1

        info = load_plist(app_dir)

        print("ASTRANYX IPA ANALYSIS")
        print("==================")
        print()
        print(f"App Directory: {app_dir}")
        print(
            f"Name: {info.get('CFBundleDisplayName') or info.get('CFBundleName', 'Unknown')}"
        )
        print(f"Bundle ID: {info.get('CFBundleIdentifier', 'Unknown')}")
        print(f"Version: {info.get('CFBundleShortVersionString', 'Unknown')}")
        print(f"Build: {info.get('CFBundleVersion', 'Unknown')}")
        print(f"Minimum iOS: {info.get('MinimumOSVersion', 'Unknown')}")
        print()

        schemes = get_url_schemes(info)
        if schemes:
            print("URL Schemes")
            print("-----------")
            for s in schemes:
                print(f"- {s}://")
            print()

        associated = info.get("com.apple.developer.associated-domains")
        if associated:
            print("Associated Domains")
            print("------------------")
            for d in associated:
                print(f"- {d}")
            print()

        permissions = sorted(
            k for k in info if k.startswith("NS") and k.endswith("UsageDescription")
        )
        if permissions:
            print("Privacy Permissions")
            print("-------------------")
            for p in permissions:
                print(f"- {p}: {info.get(p)}")
            print()

        bg = info.get("UIBackgroundModes", []) or []
        if bg:
            print("Background Modes")
            print("----------------")
            for b in bg:
                print(f"- {b}")
            print()

        print("Recommended Manual Tests")
        print("------------------------")
        if schemes:
            print("- Deep link authorization testing")
        if associated:
            print("- Universal Link validation")
        if permissions:
            print("- Privacy permission behavior review")
        if bg:
            print("- Background behavior review")
        print("- API authorization testing")
        print("- Local storage review")

        return 0

    except (OSError, ValueError, zipfile.BadZipFile) as e:
        print(f"[-] Error: {e}")
        return 1

    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)
