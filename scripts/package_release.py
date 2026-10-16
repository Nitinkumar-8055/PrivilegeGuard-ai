import zipfile
import os
import pathlib

def package_project():
    root = pathlib.Path(__file__).resolve().parent.parent
    out_zip = root / "privilegeguard_ai_release.zip"
    
    excludes = {".pytest_cache", "__pycache__", "backups", ".git", "venv", ".venv"}
    exclude_exts = {".db", ".db-wal", ".db-shm", ".pyc", ".zip"}
    exclude_files = {".env"}
    
    count = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            if any(part in excludes for part in p.parts):
                continue
            if p.suffix in exclude_exts or p.name in exclude_files or p == out_zip:
                continue
            
            arcname = p.relative_to(root)
            zf.write(p, arcname)
            count += 1

    size_kb = os.path.getsize(out_zip) / 1024
    print(f"[+] Successfully packaged {count} files into '{out_zip.name}' ({size_kb:.2f} KB)")
    return out_zip

if __name__ == "__main__":
    package_project()
