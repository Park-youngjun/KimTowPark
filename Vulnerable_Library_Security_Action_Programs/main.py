import os, sys, csv, json, zipfile, tempfile, threading, urllib.request, urllib.error
from tkinter import Tk, ttk, filedialog, messagebox, StringVar, N, S, E, W

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# ==== requirements.txt 파싱 (== 고정 버전만) ====
def parse_requirements_txt(path):
    pkgs = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                # 아주 단순 파싱: 'name==version' 패턴만 인식
                if "==" in s and "@" not in s:
                    name, ver = s.split("==", 1)
                    name = name.strip().lower()
                    ver = ver.strip()
                    if name and ver:
                        pkgs.append((name, ver))
    except Exception as e:
        raise RuntimeError(f"requirements.txt 읽기 실패: {e}")
    return pkgs

def find_requirements_in_dir(root):
    cand = os.path.join(root, "requirements.txt")
    return cand if os.path.exists(cand) else None

def extract_zip_to_tmp(zip_path):
    tmpdir = tempfile.mkdtemp(prefix="vulnally_")
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(tmpdir)
    return tmpdir

# ==== OSV 호출 (표준 라이브러리만 사용) ====
def http_post_json(url, payload, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))

def build_osv_queries_pypi(pkgs):
    return {"queries": [{"package": {"name": name, "ecosystem": "PyPI"}} for (name, _ver) in pkgs]}

# 영향 범위 스펙 계산(간단화: introduced..fixed → ">=intro,<fixed")
def _ranges_to_specifiers(affected_obj):
    specs = []
    for r in (affected_obj.get("ranges") or []):
        if r.get("type") not in ("ECOSYSTEM","SEMVER"):
            continue
        intro = None
        for ev in r.get("events", []):
            if "introduced" in ev:
                intro = ev["introduced"]
            if "fixed" in ev:
                fixed = ev["fixed"]
                if intro is not None:
                    expr = f">={intro}"
                    if fixed:
                        expr += f",<{fixed}"
                    specs.append(expr)
                    intro = None
        if intro is not None:
            specs.append(f">={intro}")
    return specs

def _pick_min_fixed(affected_obj):
    cands = []
    for r in (affected_obj.get("ranges") or []):
        for ev in r.get("events", []):
            if "fixed" in ev:
                cands.append(ev["fixed"])
    # 문자열 비교로 충분(버전 정렬 정확도는 낮지만 안내용으로 OK)
    cands = [c for c in cands if c]
    return sorted(cands)[0] if cands else None

# 아주 단순한 버전 포함 판정: ">=a,<b" 등 문자열 비교 기반 (정확한 SemVer는 packaging 필요)
def _ver_in_spec_simple(cur, spec_expr):
    parts = [p.strip() for p in spec_expr.split(",") if p.strip()]
    ok = True
    for p in parts:
        if p.startswith(">="):
            if cur < p[2:]:
                ok = False
        elif p.startswith("<"):
            if not (cur < p[1:]):
                ok = False
        elif p.startswith(">"):
            if not (cur > p[1:]):
                ok = False
        elif p.startswith("=="):
            if cur != p[2:]:
                ok = False
        # 그 외 연산자는 생략
    return ok

def analyze_with_osv_pypi(pkgs):
    if not pkgs:
        return [], {"total_packages":0,"total_findings":0,"affected_packages":0,"critical_high":0}

    payload = build_osv_queries_pypi(pkgs)
    res = http_post_json(OSV_BATCH_URL, payload, timeout=30)
    results = res.get("results", [])

    ver_map = {name: ver for (name, ver) in pkgs}
    rows = []
    affected_keys = set()
    crit_high = 0

    for res_item in results:
        vulns = res_item.get("vulns") or []
        for v in vulns:
            cves = [a for a in (v.get("aliases") or []) if str(a).startswith("CVE-")]
            if not cves:
                continue

            severity_str = ""
            sev = v.get("severity") or []
            if sev:
                first = sev[0]
                # type/score 중 하나 표시
                severity_str = first.get("score") or first.get("type") or ""

            for aff in (v.get("affected") or []):
                pkg = (aff.get("package") or {}).get("name","").lower()
                eco = (aff.get("package") or {}).get("ecosystem")
                if eco != "PyPI" or not pkg or pkg not in ver_map:
                    continue

                cur_ver = ver_map[pkg]
                specs = _ranges_to_specifiers(aff)

                # 간단 판정(정확도 < packaging): 그래도 안내용으로 쓸만
                vulnerable = any(_ver_in_spec_simple(cur_ver, s) for s in specs) if specs else False
                if not vulnerable:
                    continue

                fixed = _pick_min_fixed(aff)
                if fixed:
                    action = "update"
                    recommend = f">= {fixed}"
                    note = "해당 버전 이상으로 업그레이드 권장"
                else:
                    action = "mitigate/remove"
                    recommend = "대체/완화책 적용 (고정 버전 정보 없음)"
                    note = "공식 패치 정보 부재"

                rows.append({
                    "package": pkg,
                    "version": cur_ver,
                    "cves": ", ".join(cves),
                    "severity": severity_str,
                    "action": action,
                    "recommend": recommend,
                    "note": note
                })
                affected_keys.add(f"{pkg}=={cur_ver}")
                if "CRITICAL" in severity_str.upper() or "HIGH" in severity_str.upper():
                    crit_high += 1

    summary = {
        "total_packages": len(pkgs),
        "total_findings": len(rows),
        "affected_packages": len(affected_keys),
        "critical_high": crit_high
    }
    return rows, summary

# ==== Tkinter UI ====
class App:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("VulnAlly Desktop (PyPI / No-Deps)")
        self.root.geometry("1000x640")

        self.selected_path = StringVar(value="선택: 없음")
        self.rows_cache = []
        self.summary_cache = {}

        # 상단 툴바
        frame_top = ttk.Frame(root)
        frame_top.grid(row=0, column=0, sticky=E+W, padx=12, pady=8)
        self.btn_choose = ttk.Button(frame_top, text="파일/폴더 선택", command=self.choose_path)
        self.btn_choose.grid(row=0, column=0, padx=(0,6))
        self.btn_scan = ttk.Button(frame_top, text="스캔 시작", command=self.start_scan, state="disabled")
        self.btn_scan.grid(row=0, column=1)
        ttk.Label(frame_top, textvariable=self.selected_path).grid(row=0, column=2, padx=12)

        # 진행바
        frame_prog = ttk.Frame(root)
        frame_prog.grid(row=1, column=0, sticky=E+W, padx=12, pady=4)
        self.prog = ttk.Progressbar(frame_prog, mode="determinate", maximum=100)
        self.prog.grid(row=0, column=0, sticky=E+W)
        frame_prog.columnconfigure(0, weight=1)

        # 테이블
        frame_tbl = ttk.Frame(root)
        frame_tbl.grid(row=2, column=0, sticky=N+S+E+W, padx=12, pady=8)
        cols = ("Package","Version","CVEs","Severity","Action","Recommend")
        self.table = ttk.Treeview(frame_tbl, columns=cols, show="headings", height=20)
        for c in cols:
            self.table.heading(c, text=c)
            self.table.column(c, width=150 if c!="CVEs" else 300, anchor="w")
        vsb = ttk.Scrollbar(frame_tbl, orient="vertical", command=self.table.yview)
        self.table.configure(yscroll=vsb.set)
        self.table.grid(row=0, column=0, sticky=N+S+E+W)
        vsb.grid(row=0, column=1, sticky=N+S)

        frame_tbl.rowconfigure(0, weight=1)
        frame_tbl.columnconfigure(0, weight=1)

        # 하단 버튼
        frame_bot = ttk.Frame(root)
        frame_bot.grid(row=3, column=0, sticky=E+W, padx=12, pady=8)
        self.btn_csv = ttk.Button(frame_bot, text="CSV 내보내기", command=self.export_csv)
        self.btn_csv.grid(row=0, column=0)
        self.btn_html = ttk.Button(frame_bot, text="HTML 내보내기", command=self.export_html)
        self.btn_html.grid(row=0, column=1, padx=(6,0))

        # 그리드 확장
        root.rowconfigure(2, weight=1)
        root.columnconfigure(0, weight=1)

    def choose_path(self):
        # 파일 먼저
        path = filedialog.askopenfilename(
            title="폴더/ZIP/requirements.txt 선택",
            filetypes=[("All", "*.*"), ("ZIP", "*.zip"), ("Text", "*.txt")]
        )
        if not path:
            # 폴더 선택
            d = filedialog.askdirectory(title="폴더 선택")
            if d:
                path = d
        if not path:
            return
        self.selected_path.set(f"선택: {path}")
        self.btn_scan.configure(state="normal")
        self.table.delete(*self.table.get_children())
        self.rows_cache = []
        self.summary_cache = {}
        self.prog["value"] = 0

    def start_scan(self):
        path = self.selected_path.get().replace("선택: ","",1)
        if not path or path == "없음":
            messagebox.showwarning("안내","먼저 파일 또는 폴더를 선택하세요.")
            return
        self.btn_scan.configure(state="disabled")
        self.prog["value"] = 5
        self.table.delete(*self.table.get_children())

        t = threading.Thread(target=self._scan_thread, args=(path,), daemon=True)
        t.start()

    def _scan_thread(self, path):
        try:
            self._set_prog(15)
            work_dir = None
            req_path = None

            if os.path.isdir(path):
                work_dir = path
            elif path.lower().endswith(".zip"):
                work_dir = extract_zip_to_tmp(path)
            elif path.lower().endswith(".txt"):
                req_path = path
            else:
                raise RuntimeError("지원: 폴더 / ZIP / requirements.txt")

            self._set_prog(30)
            if not req_path:
                req_path = find_requirements_in_dir(work_dir or os.path.dirname(path))
                if not req_path:
                    raise RuntimeError("requirements.txt 을 찾지 못했습니다.")

            pkgs = parse_requirements_txt(req_path)
            if not pkgs:
                raise RuntimeError("고정(==)된 파이썬 패키지가 없습니다.")

            self._set_prog(55)
            rows, summary = analyze_with_osv_pypi(pkgs)
            self._set_prog(90)

            self.rows_cache = rows
            self.summary_cache = summary
            self._fill_table(rows)

            self._set_prog(100)
            self._enable_scan()
            messagebox.showinfo("완료",
                f"의존 {summary['total_packages']}개 / 취약 {summary['total_findings']}개 / 영향 패키지 {summary['affected_packages']}개")
        except urllib.error.URLError as e:
            self._enable_scan()
            messagebox.showerror("네트워크 오류", f"OSV 접근 실패: {e}")
        except Exception as e:
            self._enable_scan()
            messagebox.showerror("오류", str(e))

    # UI thread에서 실행되도록 after 사용
    def _set_prog(self, v):
        self.root.after(0, lambda: self.prog.configure(value=v))

    def _fill_table(self, rows):
        def run():
            for r in rows:
                self.table.insert("", "end", values=(r["package"], r["version"], r["cves"], r["severity"], r["action"], r["recommend"]))
        self.root.after(0, run)

    def _enable_scan(self):
        self.root.after(0, lambda: self.btn_scan.configure(state="normal"))

    def export_csv(self):
        if not self.rows_cache:
            messagebox.showinfo("안내","내보낼 데이터가 없습니다.")
            return
        path = filedialog.asksaveasfilename(title="CSV 저장", defaultextension=".csv", initialfile="vuln_report.csv")
        if not path: return
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=["package","version","cves","severity","action","recommend","note"])
                w.writeheader()
                for r in self.rows_cache:
                    if "note" not in r: r["note"] = ""
                    w.writerow(r)
            messagebox.showinfo("완료", f"저장됨: {path}")
        except Exception as e:
            messagebox.showerror("오류", str(e))

    def export_html(self):
        if not self.rows_cache:
            messagebox.showinfo("안내","내보낼 데이터가 없습니다.")
            return
        path = filedialog.asksaveasfilename(title="HTML 저장", defaultextension=".html", initialfile="vuln_report.html")
        if not path: return
        try:
            s = self.summary_cache or {}
            html = []
            html.append("<html><meta charset='utf-8'><body style='font-family:Segoe UI, Arial'>")
            html.append(f"<h2>프로젝트 취약점 리포트</h2>")
            html.append(f"<p>의존 {s.get('total_packages','-')}개 / 취약 {s.get('total_findings','-')}개 / 영향 패키지 {s.get('affected_packages','-')}개 / CRIT+HIGH {s.get('critical_high','-')}</p>")
            html.append("<table border='1' cellpadding='6' cellspacing='0'>")
            html.append("<tr><th>Package</th><th>Version</th><th>CVEs</th><th>Severity</th><th>Action</th><th>Recommend</th></tr>")
            for r in self.rows_cache:
                html.append(f"<tr><td>{r['package']}</td><td>{r['version']}</td><td>{r['cves']}</td><td>{r['severity']}</td><td>{r['action']}</td><td>{r['recommend']}</td></tr>")
            html.append("</table></body></html>")
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(html))
            messagebox.showinfo("완료", f"저장됨: {path}")
        except Exception as e:
            messagebox.showerror("오류", str(e))

def main():
    root = Tk()
    # 윈도우 테마(ttk 기본) 사용. 다크모드는 OS 차원의 설정에 따름
    style = ttk.Style()
    # style.theme_use("vista")  # 필요시 강제 테마
    app = App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
