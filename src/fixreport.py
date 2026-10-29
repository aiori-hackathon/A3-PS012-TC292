from pathlib import Path
p = Path("/app/dnsassess/report.py")
s = p.read_text()
old = """    if Environment and template_path.exists():
        env = Environment(
            loader=FileSystemLoader(str(template_path.parent)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        tmpl = env.get_template(template_path.name)
        html = tmpl.render(
            results=results,
            counts=counts,
            comparison=comparison,
            run_meta=run_meta,
        )
        html_path.write_text(html, encoding="utf-8")
        return"""
new = """    if Environment and template_path.exists():
        try:
            env = Environment(
                loader=FileSystemLoader(str(template_path.parent)),
                autoescape=select_autoescape(["html", "xml"]),
            )
            tmpl = env.get_template(template_path.name)
            html = tmpl.render(
                results=results,
                counts=counts,
                comparison=comparison,
                run_meta=run_meta,
            )
            html_path.write_text(html, encoding="utf-8")
            return
        except Exception:
            pass"""
if old in s:
    p.write_text(s.replace(old, new))
    print("ok")
else:
    print("nf")
