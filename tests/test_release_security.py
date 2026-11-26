"""Regression tests for release workflow security controls."""

import hashlib
import io
import json
import subprocess
import textwrap
import urllib.error
import urllib.request
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"


def extract_scripts(marker):
    """Extract executable Python from workflow heredocs."""
    scripts = []
    body = None
    opening = f"python3 - <<'{marker}'"

    for line in WORKFLOW.read_text(encoding="utf-8").splitlines():
        if line.strip() == opening:
            assert body is None, "Nested heredoc"
            body = []
        elif body is not None:
            if line.strip() == marker:
                scripts.append(textwrap.dedent("\n".join(body)))
                body = None
            else:
                body.append(line)

    assert body is None, "Unterminated heredoc"
    return scripts


@pytest.mark.parametrize(
    ("marker", "expected"),
    [
        ("PY_GATE", 1),
        ("PY_VERIFY", 3),
        ("PY_PREFLIGHT", 3),
    ],
)
def test_security_script_inventory(marker, expected):
    scripts = extract_scripts(marker)
    assert len(scripts) == expected

    for script in scripts:
        compile(script, str(WORKFLOW), "exec")


def test_artifact_verifiers_are_identical():
    scripts = extract_scripts("PY_VERIFY")
    assert len(scripts) == 3
    assert scripts[0] == scripts[1] == scripts[2]


def test_publication_guards_are_identical():
    scripts = extract_scripts("PY_PREFLIGHT")
    assert len(scripts) == 3
    assert scripts[1] == scripts[2]


def test_manifest_provenance_required():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert (
        text.count("for artifact in dist/*.whl dist/*.tar.gz dist/SHA256SUMS; do") == 2
    )


def test_release_upload_does_not_overwrite():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "--clobber" not in text
    assert "gh release upload" in text


REQUIRED_CI_JOBS = (
    "test (3.11)",
    "test (3.12)",
    "test (3.13)",
    "test (3.14)",
    "Windows integrity baseline (3.13)",
    "Windows integrity baseline (3.14)",
    "Windows full test suite (3.14)",
    "Build and validate release artifacts (3.13)",
    "Build and validate release artifacts (3.14)",
)


@pytest.mark.parametrize(
    "scenario",
    [
        "valid",
        "missing-run",
        "pull-request",
        "wrong-branch",
        "wrong-sha",
        "failed-run",
        "incomplete-run",
        "missing-job",
        "skipped-job",
        "failed-job",
        "duplicate-job",
        "api-failure",
    ],
)
def test_ci_release_gate(monkeypatch, scenario):
    sha = "a" * 40
    repo = "example/astranyx"

    run = {
        "id": 123,
        "run_attempt": 1,
        "head_sha": sha,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
    }

    runs = [run]

    jobs = [
        {
            "name": name,
            "status": "completed",
            "conclusion": "success",
        }
        for name in REQUIRED_CI_JOBS
    ]

    if scenario == "missing-run":
        runs.clear()
    elif scenario == "pull-request":
        run["event"] = "pull_request"
    elif scenario == "wrong-branch":
        run["head_branch"] = "development"
    elif scenario == "wrong-sha":
        run["head_sha"] = "b" * 40
    elif scenario == "failed-run":
        run["conclusion"] = "failure"
    elif scenario == "incomplete-run":
        run["status"] = "in_progress"
        run["conclusion"] = None
    elif scenario == "missing-job":
        jobs.pop()
    elif scenario == "skipped-job":
        jobs[0]["conclusion"] = "skipped"
    elif scenario == "failed-job":
        jobs[0]["conclusion"] = "failure"
    elif scenario == "duplicate-job":
        jobs.append(dict(jobs[0]))

    def mock_command(command, **kwargs):
        if command == ["git", "rev-parse", "HEAD"]:
            return sha

        assert command[:2] == ["gh", "api"]

        if scenario == "api-failure":
            raise subprocess.CalledProcessError(1, command)

        endpoint = command[-1]

        if endpoint == (
            f"repos/{repo}/actions/workflows/ci.yml/runs"
            f"?head_sha={sha}&branch=main&event=push"
            "&per_page=100"
        ):
            return json.dumps({"workflow_runs": runs})

        if endpoint == (
            f"repos/{repo}/actions/runs/123" "/attempts/1/jobs?per_page=100"
        ):
            return json.dumps({"jobs": jobs})

        raise AssertionError(f"Unexpected command: {command}")

    monkeypatch.setenv("GITHUB_REPOSITORY", repo)
    monkeypatch.setattr(subprocess, "check_output", mock_command)

    script = extract_scripts("PY_GATE")[0]
    code = compile(script, str(WORKFLOW), "exec")

    if scenario == "valid":
        execute_workflow_script(code)
    elif scenario == "api-failure":
        with pytest.raises(subprocess.CalledProcessError):
            execute_workflow_script(code)
    else:
        with pytest.raises(SystemExit) as error:
            execute_workflow_script(code)

        assert error.value.code not in (0, None)


def execute_workflow_script(code):
    """Execute repository workflow code for regression testing."""
    # Intentional execution of extracted repository workflow scripts.
    # External API operations are mocked by the behavioral tests.
    exec(code, {})  # noqa: S102


@pytest.mark.parametrize(
    "scenario",
    [
        "valid",
        "modified-wheel",
        "modified-sdist",
        "missing-wheel",
        "missing-manifest",
        "unexpected-file",
        "additional-wheel",
        "unexpected-directory",
        "symlink",
        "duplicate-checksum",
        "incomplete-manifest",
        "path-traversal",
        "malformed-manifest",
    ],
)
def test_artifact_integrity(tmp_path, monkeypatch, scenario):
    monkeypatch.chdir(tmp_path)

    wheel = Path("astranyx_engine-4.0.0a7-py3-none-any.whl")
    sdist = Path("astranyx_engine-4.0.0a7.tar.gz")
    manifest = Path("SHA256SUMS")

    wheel.write_bytes(b"validated wheel")
    sdist.write_bytes(b"validated source distribution")

    entries = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
        for p in (wheel, sdist)
    ]

    manifest.write_text(
        "\n".join(entries) + "\n",
        encoding="utf-8",
    )

    if scenario == "modified-wheel":
        wheel.write_bytes(b"modified wheel")
    elif scenario == "modified-sdist":
        sdist.write_bytes(b"modified source")
    elif scenario == "missing-wheel":
        wheel.unlink()
    elif scenario == "missing-manifest":
        manifest.unlink()
    elif scenario == "unexpected-file":
        Path("unexpected.txt").write_bytes(b"unexpected")
    elif scenario == "additional-wheel":
        Path("additional.whl").write_bytes(b"unexpected")
    elif scenario == "unexpected-directory":
        Path("unexpected").mkdir()
    elif scenario == "symlink":
        target = tmp_path.parent / f"{tmp_path.name}-target"
        target.write_bytes(wheel.read_bytes())
        wheel.unlink()

        try:
            wheel.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("Symbolic links unavailable")
    elif scenario == "duplicate-checksum":
        manifest.write_text(
            "\n".join(entries + [entries[0]]) + "\n",
            encoding="utf-8",
        )
    elif scenario == "incomplete-manifest":
        manifest.write_text(
            entries[0] + "\n",
            encoding="utf-8",
        )
    elif scenario == "path-traversal":
        manifest.write_text(
            f"{'0' * 64}  ../outside.whl\n",
            encoding="utf-8",
        )
    elif scenario == "malformed-manifest":
        manifest.write_text(
            "invalid checksum entry\n",
            encoding="utf-8",
        )

    scripts = extract_scripts("PY_VERIFY")
    assert len(scripts) == 3

    for script in scripts:
        code = compile(script, str(WORKFLOW), "exec")

        if scenario == "valid":
            execute_workflow_script(code)
        else:
            with pytest.raises(SystemExit) as error:
                execute_workflow_script(code)

            assert error.value.code not in (0, None)


@pytest.mark.parametrize(
    "scenario",
    [
        "valid-lightweight",
        "valid-annotated",
        "wrong-commit",
        "wrong-annotated-target",
        "wrong-release-id",
        "wrong-release-tag",
        "draft-release",
        "immutable-release",
        "existing-assets",
        "existing-pypi-version",
        "http-403",
        "http-429",
        "http-500",
        "api-failure",
        "network-failure",
        "invalid-tag",
        "redirect",
    ],
)
def test_publication_preflight(monkeypatch, scenario):
    sha = "a" * 40
    tag_sha = "c" * 40
    tag = "v4.0.0a7"
    repo = "example/astranyx"

    target = {
        "type": "commit",
        "sha": sha,
    }

    annotated_target = {
        "type": "commit",
        "sha": sha,
    }

    release = {
        "id": 123,
        "tag_name": tag,
        "draft": False,
        "immutable": False,
        "assets": [],
    }

    if scenario in {
        "valid-annotated",
        "wrong-annotated-target",
    }:
        target = {
            "type": "tag",
            "sha": tag_sha,
        }

    if scenario == "wrong-commit":
        target["sha"] = "b" * 40
    elif scenario == "wrong-annotated-target":
        annotated_target["sha"] = "b" * 40
    elif scenario == "wrong-release-id":
        release["id"] = 999
    elif scenario == "wrong-release-tag":
        release["tag_name"] = "v9.9.9"
    elif scenario == "draft-release":
        release["draft"] = True
    elif scenario == "immutable-release":
        release["immutable"] = True
    elif scenario == "existing-assets":
        release["assets"] = [{"id": 1}]

    def mock_command(command, **kwargs):
        assert command[:2] == ["gh", "api"]

        if scenario == "api-failure":
            raise subprocess.CalledProcessError(1, command)

        endpoint = command[-1]

        if endpoint == f"repos/{repo}/git/ref/tags/{tag}":
            return json.dumps({"object": target})

        if endpoint == f"repos/{repo}/git/tags/{tag_sha}":
            return json.dumps({"object": annotated_target})

        if endpoint == f"repos/{repo}/releases/tags/{tag}":
            return json.dumps(release)

        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    class ExistingVersion:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def mock_urlopen(url, timeout):
        assert url == ("https://pypi.org/pypi/" "astranyx-engine/4.0.0a7/json")
        assert timeout == 30

        if scenario == "network-failure":
            raise urllib.error.URLError("Network unavailable")

        if scenario == "existing-pypi-version":
            return ExistingVersion()

        status = {
            "http-403": 403,
            "http-429": 429,
            "http-500": 500,
        }.get(scenario, 404)

        raise urllib.error.HTTPError(url, status, "Simulated response", {}, None)

    monkeypatch.setenv("GITHUB_REPOSITORY", repo)
    monkeypatch.setenv("GITHUB_SHA", sha)
    monkeypatch.setenv("RELEASE_ID", "123")
    monkeypatch.setenv(
        "RELEASE_TAG",
        "invalid-tag" if scenario == "invalid-tag" else tag,
    )

    monkeypatch.setattr(subprocess, "check_output", mock_command)

    class Opener:
        def open(self, url, timeout):
            return mock_urlopen(url, timeout)

    def mock_opener(handler):
        if scenario == "redirect":
            handler.redirect_request(None, None, 302, "", {}, "https://example.invalid")
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", mock_opener)

    scripts = extract_scripts("PY_PREFLIGHT")
    assert len(scripts) == 3

    code = compile(scripts[0], str(WORKFLOW), "exec")

    if scenario in {"valid-lightweight", "valid-annotated"}:
        execute_workflow_script(code)
    elif scenario == "api-failure":
        with pytest.raises(subprocess.CalledProcessError):
            execute_workflow_script(code)
    elif scenario == "network-failure":
        with pytest.raises(urllib.error.URLError):
            execute_workflow_script(code)
    else:
        with pytest.raises(SystemExit) as error:
            execute_workflow_script(code)

        assert error.value.code not in (0, None)


PUBLICATION_CASES = [
    ("before-pypi", "valid", 404, True),
    ("before-pypi", "existing-version", 200, False),
    ("before-github", "valid", 200, True),
    ("before-github", "missing-version", 404, False),
]

PUBLICATION_CASES += [
    (stage, scenario, status, False)
    for stage, status in [
        ("before-pypi", 404),
        ("before-github", 200),
    ]
    for scenario in [
        "commit",
        "release-id",
        "draft",
        "immutable",
        "assets",
        "api",
        "redirect",
        "network",
    ]
]

PUBLICATION_CASES += [
    ("before-github", scenario, 200, False)
    for scenario in [
        "digest",
        "missing",
        "duplicate",
        "unexpected",
        "yanked",
        "package",
        "version",
    ]
]

PUBLICATION_CASES += [
    (stage, f"http-{status}", status, False)
    for stage in ["before-pypi", "before-github"]
    for status in [403, 429, 500]
]

PUBLICATION_CASES += [
    ("before-pypi", "null-json", 200, False),
    ("before-github", "null-json", 200, False),
    ("before-pypi", "malformed-json", 200, False),
    ("before-github", "malformed-json", 200, False),
    ("before-pypi", "modified-copy", 404, False),
    ("before-pypi", "missing-copy", 404, False),
    ("before-pypi", "extra-copy", 404, False),
    ("before-pypi", "directory-copy", 404, False),
    ("before-pypi", "symlink-copy", 404, False),
    ("before-pypi", "release-tag", 404, False),
    ("before-github", "release-tag", 200, False),
]


@pytest.mark.parametrize(
    ("stage", "scenario", "status", "allowed"),
    PUBLICATION_CASES,
)
def test_publication_guard(tmp_path, monkeypatch, stage, scenario, status, allowed):
    monkeypatch.chdir(tmp_path)

    sha = "a" * 40
    tag = "v4.0.0a7"
    repo = "example/astranyx"

    dist = Path("dist")
    packages = Path("packages")

    dist.mkdir()
    packages.mkdir()

    files = {
        "astranyx_engine-4.0.0a7-py3-none-any.whl": b"wheel",
        "astranyx_engine-4.0.0a7.tar.gz": b"sdist",
    }

    urls = []

    for name, data in files.items():
        (dist / name).write_bytes(data)
        (packages / name).write_bytes(data)

        urls.append(
            {
                "filename": name,
                "digests": {"sha256": hashlib.sha256(data).hexdigest()},
                "yanked": False,
            }
        )

    wheel = packages / next(iter(files))

    metadata = {
        "info": {
            "name": "astranyx-engine",
            "version": tag[1:],
        },
        "urls": urls,
    }

    target = {"type": "commit", "sha": sha}

    release = {
        "id": 123,
        "tag_name": tag,
        "draft": False,
        "immutable": False,
        "assets": [],
    }

    if scenario == "commit":
        target["sha"] = "b" * 40
    elif scenario == "release-id":
        release["id"] = 999
    elif scenario == "release-tag":
        release["tag_name"] = "v9.9.9"
    elif scenario == "draft":
        release["draft"] = True
    elif scenario == "immutable":
        release["immutable"] = True
    elif scenario == "assets":
        release["assets"] = [{"id": 1}]
    elif scenario == "digest":
        urls[0]["digests"]["sha256"] = "0" * 64
    elif scenario == "missing":
        urls.pop()
    elif scenario == "duplicate":
        urls.append(dict(urls[0]))
    elif scenario == "unexpected":
        urls.append(
            {
                "filename": "unexpected.whl",
                "digests": {"sha256": "0" * 64},
                "yanked": False,
            }
        )
    elif scenario == "yanked":
        urls[0]["yanked"] = True
    elif scenario == "package":
        metadata["info"]["name"] = "wrong-package"
    elif scenario == "version":
        metadata["info"]["version"] = "9.9.9"
    elif scenario == "null-json":
        metadata = None
    elif scenario == "modified-copy":
        wheel.write_bytes(b"modified")
    elif scenario == "missing-copy":
        wheel.unlink()
    elif scenario == "extra-copy":
        (packages / "unexpected.whl").write_bytes(b"extra")
    elif scenario == "directory-copy":
        wheel.unlink()
        wheel.mkdir()
    elif scenario == "symlink-copy":
        wheel.unlink()

        try:
            wheel.symlink_to((dist / wheel.name).resolve())
        except (OSError, NotImplementedError):
            pytest.skip("Symbolic links unavailable")

    def mock_command(command, **kwargs):
        assert command[:2] == ["gh", "api"]

        if scenario == "api":
            raise subprocess.CalledProcessError(1, command)

        endpoint = command[-1]

        if endpoint == f"repos/{repo}/git/ref/tags/{tag}":
            return json.dumps({"object": target})

        if endpoint == f"repos/{repo}/releases/tags/{tag}":
            return json.dumps(release)

        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    class Response(io.StringIO):
        status = 200

    class Opener:
        def open(self, url, timeout):
            assert url == ("https://pypi.org/pypi/" "astranyx-engine/4.0.0a7/json")
            assert timeout == 30

            if scenario == "network":
                raise urllib.error.URLError("Network unavailable")

            if status != 200:
                raise urllib.error.HTTPError(
                    url, status, "Simulated response", {}, None
                )

            if scenario == "malformed-json":
                return Response("{invalid")

            return Response(json.dumps(metadata))

    def mock_opener(handler):
        if scenario == "redirect":
            handler.redirect_request(None, None, 302, "", {}, "https://example.invalid")

        return Opener()

    monkeypatch.setenv("GITHUB_REPOSITORY", repo)
    monkeypatch.setenv("GITHUB_SHA", sha)
    monkeypatch.setenv("RELEASE_TAG", tag)
    monkeypatch.setenv("RELEASE_ID", "123")
    monkeypatch.setenv("PUBLICATION_STAGE", stage)

    monkeypatch.setattr(subprocess, "check_output", mock_command)
    monkeypatch.setattr(urllib.request, "build_opener", mock_opener)

    scripts = extract_scripts("PY_PREFLIGHT")
    assert len(scripts) == 3

    script = scripts[1 if stage == "before-pypi" else 2]
    code = compile(script, str(WORKFLOW), "exec")

    if allowed:
        execute_workflow_script(code)
    elif scenario == "api":
        with pytest.raises(subprocess.CalledProcessError):
            execute_workflow_script(code)
    elif scenario == "network":
        with pytest.raises(urllib.error.URLError):
            execute_workflow_script(code)
    elif scenario == "malformed-json" and stage == "before-github":
        with pytest.raises(json.JSONDecodeError):
            execute_workflow_script(code)
    else:
        with pytest.raises(SystemExit) as error:
            execute_workflow_script(code)

        assert error.value.code not in (0, None)
