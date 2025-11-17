import os
import csv
import json
import zipfile
import urllib.request
import sched
from packaging.version import Version, InvalidVersion

DUMP_URL = "https://storage.googleapis.com/osv-vulnerabilities/PyPI/all.zip"
DUMP_ZIP = "PyPI_all.zip"
OUT_CSV = "pypi_cve_dict.csv"


def download_pypi_dump(zip_path: str = DUMP_ZIP):
    """
    PyPI 전체 취약점 덤프(all.zip)를 다운로드.
    이미 파일이 있으면 재다운로드하지 않음.
    """
    if os.path.exists(zip_path):
        print(f"[+] 기존 덤프 파일 사용: {zip_path}")
        return zip_path

    print(f"[+] PyPI 덤프 다운로드 중: {DUMP_URL}")
    urllib.request.urlretrieve(DUMP_URL, zip_path)
    print(f"[+] 다운로드 완료: {zip_path}")
    return zip_path


def cvss_level(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0:
        return "Low"
    else:
        return ""


def extract_vuln_rows(vuln: dict):
    """
    하나의 OSV vuln(JSON)에서
    (패키지, 범위, 취약점) 정보를 여러 행으로 뽑아냄.
    """
    rows = []

    vuln_id = vuln.get("id", "")
    summary = vuln.get("summary", "")

    # CVSS 최대 점수 계산
    max_score = 0.0
    severity_list = vuln.get("severity") or []
    for sev in severity_list:
        score = sev.get("score")
        if score:
            try:
                s = float(score)
                if s > max_score:
                    max_score = s
            except ValueError:
                pass
    level = cvss_level(max_score)
    cvss_max_str = f"{max_score:.1f}" if max_score > 0 else ""

    # affected 배열 안에 패키지/범위 정보 있음
    affected = vuln.get("affected") or []
    for aff in affected:
        pkg = aff.get("package") or {}
        pkg_name = pkg.get("name")
        ecosystem = pkg.get("ecosystem")

        # PyPI 만 대상 (그래도 혹시 몰라 확인)
        if ecosystem != "PyPI" or not pkg_name:
            continue

        ranges = aff.get("ranges") or []
        if not ranges:
            # ranges 없이 versions만 있는 케이스도 있음
            # 그런 경우 versions 리스트를 events_json으로만 넣어두자
            versions = aff.get("versions") or []
            events_json = json.dumps({"versions": versions}, ensure_ascii=False)
            rows.append({
                "package": pkg_name,
                "vuln_id": vuln_id,
                "summary": summary,
                "cvss_max": cvss_max_str,
                "cvss_level": level,
                "range_type": "",
                "events_json": events_json,
                "introduced": "",
                "fixed": "",
            })
            continue

        # ranges 가 있는 경우
        for r in ranges:
            r_type = r.get("type", "")
            events = r.get("events") or []

            # events 전체를 JSON으로 저장 (정확한 범위 계산용)
            events_json = json.dumps(events, ensure_ascii=False)

            # 간단히 보기용 대표 introduced / fixed 하나 뽑기
            introduced_ver = ""
            fixed_ver = ""

            for ev in events:
                if "introduced" in ev and not introduced_ver:
                    introduced_ver = ev["introduced"]
                if "fixed" in ev:
                    fixed_ver = ev["fixed"]  # 마지막 fixed가 가장 최신

            rows.append({
                "package": pkg_name,
                "vuln_id": vuln_id,
                "summary": summary,
                "cvss_max": cvss_max_str,
                "cvss_level": level,
                "range_type": r_type,
                "events_json": events_json,
                "introduced": introduced_ver,
                "fixed": fixed_ver,
            })

    return rows


def build_pypi_cve_dict(zip_path: str = DUMP_ZIP,
                         out_csv_path: str = OUT_CSV):
    zip_path = download_pypi_dump(zip_path)

    print(f"[+] ZIP 열기: {zip_path}")
    total_rows = 0

    fieldnames = [
        "package",
        "vuln_id",
        "summary",
        "cvss_max",
        "cvss_level",
        "range_type",
        "events_json",
        "introduced",
        "fixed",
    ]

    with zipfile.ZipFile(zip_path, "r") as zf, \
         open(out_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        members = [m for m in zf.namelist() if m.endswith(".json")]
        print(f"[+] JSON 파일 개수: {len(members)}")

        for idx, name in enumerate(members, start=1):
            if idx % 1000 == 0:
                print(f"    - {idx}/{len(members)} 처리 중...")

            with zf.open(name) as jf:
                try:
                    vuln = json.load(jf)
                except Exception:
                    continue

            rows = extract_vuln_rows(vuln)
            if not rows:
                continue

            writer.writerows(rows)

if __name__ == "__main__":
    try:
        build_pypi_cve_dict()
    except Exception as e:
        print("[!] 실행 중 예외 발생:", repr(e))
        input("엔터를 누르면 종료합니다...")
