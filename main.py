import sys
import os
import re
import json
import time
import struct
import random
import shutil
import zipfile
import tempfile
import threading
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path
from hashlib import md5, sha256
import vpk
from rich.console import Console
from rich.text import Text

try:
    from PIL import Image, ImageOps
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

UNWANTED_EXTENSIONS = {"mov", "png", "txt", "vcss", "vjs", "vmat", "vmdl", "vpcf", "vsnap", "vsnd", "vsndevts", "vtex", "vxml", "log", "md", "bak", "tmp"}
IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "tga", "webp"}

BLACKLISTED_FILENAMES = {"items_game.txt"}
BLACKLISTED_EXTENSIONS = {"ini", "bin", "sqlite3", "sqlite3-shm", "sqlite3-wal", "lua", "exe", "zip", "7z"}

PREVIEW_SIZE = (854, 480)
MANIFEST_TEMPLATE = {
    "tags": {
        "effects": True,
        "icons": True,
    },
    "links": [
        {"type": "author", "url": " "},
    ],
}
APP_VERSION = "v1.3"
GITHUB_REPO = "h6rd/PreMod"
UPDATE_CHECK_TIMEOUT = 5
UPDATE_DOWNLOAD_TIMEOUT = 30
UPDATE_ASSETS = {"win32": "PreMod-Win.zip", "linux": "PreMod-Linux.zip"}
UPDATE_BINARIES = {"win32": "PreMod.exe", "linux": "PreMod"}
CONFIG_FILENAME = "config.json"
DEFAULT_CONFIG = {
    "author": "",
}

console = Console()

def supportsUnicode():
    try:
        "✓".encode(sys.stdout.encoding or "utf-8")
        return True
    except (UnicodeEncodeError, AttributeError):
        return False

if supportsUnicode():
    SYM = {"ok": "✅", "err": "❌", "trash": "🗑️", "dir": "📂", "pkg": "📦", "save": "💾", "info": "ℹ️"}
else:
    SYM = {"ok": "[OK]", "err": "[ERROR]", "trash": "[DEL]", "dir": "[DIR]", "pkg": "[PACK]", "save": "[SAVE]", "info": "[INFO]"}

def banner():
    width = console.size.width
    lines = [
        "██████╗ ██████╗ ███████╗███╗   ███╗ ██████╗ ██████╗ ",
        "██╔══██╗██╔══██╗██╔════╝████╗ ████║██╔═══██╗██╔══██╗",
        "██████╔╝██████╔╝█████╗  ██╔████╔██║██║   ██║██║  ██║",
        "██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║██║  ██║",
        "██║     ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝██████╔╝",
        "╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ",
    ]
    console.print()
    for line in lines:
        console.print(Text(line.center(width), style="#B486FF"))
    console.print()

def isFrozen():
    return bool(getattr(sys, "frozen", False))

def parseVersion(tag):
    return tuple(int(n) for n in re.findall(r"\d+", tag or ""))

def fetchLatestTag():
    req = urllib.request.Request(
        f"https://github.com/{GITHUB_REPO}/releases/latest",
        method="HEAD",
        headers={"User-Agent": "PreMod-Updater"},
    )
    with urllib.request.urlopen(req, timeout=UPDATE_CHECK_TIMEOUT) as r:
        finalUrl = r.geturl()
    marker = "/releases/tag/"
    if marker not in finalUrl:
        raise ValueError(f"no releases found (ended up at {finalUrl})")
    return urllib.parse.unquote(finalUrl.split(marker, 1)[1].split("?", 1)[0].strip("/"))

def checkForUpdate():
    assetName = UPDATE_ASSETS.get(sys.platform)
    current = parseVersion(APP_VERSION)
    if not assetName or not current:
        return None
    box = {}

    def worker():
        try:
            box["tag"] = fetchLatestTag()
        except Exception:
            pass

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(UPDATE_CHECK_TIMEOUT)
    tag = box.get("tag")
    if not tag:
        return None
    if parseVersion(tag) <= current:
        return None
    url = f"https://github.com/{GITHUB_REPO}/releases/download/{urllib.parse.quote(tag)}/{assetName}"
    return tag, url, None

def downloadUpdate(url, digest, newPath):
    req = urllib.request.Request(url, headers={"User-Agent": "PreMod-Updater"})
    with tempfile.TemporaryDirectory() as tmp:
        zipPath = Path(tmp) / "update.zip"
        h = sha256()
        with urllib.request.urlopen(req, timeout=UPDATE_DOWNLOAD_TIMEOUT) as r, open(zipPath, "wb") as f:
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
                h.update(chunk)
        if digest and digest.lower().startswith("sha256:"):
            if h.hexdigest() != digest.split(":", 1)[1].lower():
                raise ValueError("checksum mismatch")
        binName = UPDATE_BINARIES[sys.platform]
        with zipfile.ZipFile(zipPath) as z:
            member = next((i for i in z.infolist() if not i.is_dir() and Path(i.filename).name == binName), None)
            if member is None:
                raise ValueError("binary not found in archive")
            data = z.read(member)
        magic = b"MZ" if sys.platform == "win32" else b"\x7fELF"
        if len(data) < 1024 * 1024 or not data.startswith(magic):
            raise ValueError("downloaded file is not a valid executable")
        newPath.write_bytes(data)

def applyUpdate(exePath, newPath):
    if sys.platform == "win32":
        oldPath = exePath.with_name(exePath.name + ".old")
        if oldPath.exists():
            oldPath.unlink()
        exePath.rename(oldPath)
        try:
            newPath.rename(exePath)
        except Exception:
            oldPath.rename(exePath)
            raise
    else:
        newPath.chmod(0o755)
        os.replace(newPath, exePath)

def cleanupOldBinary():
    if not isFrozen():
        return
    exePath = Path(sys.executable)
    for suffix in (".old", ".new"):
        try:
            exePath.with_name(exePath.name + suffix).unlink()
        except OSError:
            pass

def selfUpdate():
    if not isFrozen() or os.environ.get("PREMOD_JUST_UPDATED"):
        return
    cleanupOldBinary()
    info = checkForUpdate()
    if not info:
        return
    tag, url, digest = info
    exePath = Path(sys.executable)
    newPath = exePath.with_name(exePath.name + ".new")
    console.print(f"{SYM['info']} New version {tag} found (current {APP_VERSION}), updating...")
    try:
        downloadUpdate(url, digest, newPath)
        applyUpdate(exePath, newPath)
    except Exception:
        try:
            newPath.unlink()
        except OSError:
            pass
        console.print(f"{SYM['err']} Update failed, continuing with {APP_VERSION}")
        return
    console.print(f"{SYM['ok']} Updated to {tag}, restarting...")
    env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1", PREMOD_JUST_UPDATED="1")
    sys.exit(subprocess.call([str(exePath)] + sys.argv[1:], env=env))

VPK_SIGNATURE = 0x55AA1234

def readCString(data, offset):
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("utf-8", errors="replace"), end + 1

def parseHeader(data):
    sig, version, treeLen = struct.unpack_from("<III", data, 0)
    if sig != VPK_SIGNATURE:
        raise ValueError("Not a VPK file (bad signature)")
    if version != 2:
        raise ValueError(f"Unsupported VPK version: {version}")
    embedLen, chunkHashLen, selfHashLen, sigLen = struct.unpack_from("<IIII", data, 12)
    return {
        "treeLen": treeLen,
        "embedLen": embedLen,
        "chunkHashLen": chunkHashLen,
        "selfHashLen": selfHashLen,
        "sigLen": sigLen,
        "headerLen": 28,
    }

def parseTree(data, offset):
    entries = []
    while True:
        ext, offset = readCString(data, offset)
        if ext == "":
            break
        while True:
            path, offset = readCString(data, offset)
            if path == "":
                break
            while True:
                name, offset = readCString(data, offset)
                if name == "":
                    break
                crc, preloadLen, arcIdx, entryOff, entryLen, term = struct.unpack_from("<IHHIIH", data, offset)
                offset += struct.calcsize("<IHHIIH")
                if term != 0xFFFF:
                    raise ValueError(f"Corrupt tree entry near offset {offset}")
                preload = data[offset:offset + preloadLen]
                offset += preloadLen
                entries.append({
                    "ext": ext, "path": path, "name": name,
                    "crc": crc, "arcIdx": arcIdx,
                    "entryOff": entryOff, "entryLen": entryLen,
                    "preload": preload,
                })
    return entries, offset

def buildTree(entries):
    grouped = {}
    for e in entries:
        grouped.setdefault(e["ext"], {}).setdefault(e["path"], []).append(e)
    out = bytearray()
    for ext, paths in grouped.items():
        out += ext.encode("utf-8") + b"\x00"
        for path, files in paths.items():
            out += path.encode("utf-8") + b"\x00"
            for e in files:
                out += e["name"].encode("utf-8") + b"\x00"
                out += struct.pack("<IHHIIH", e["crc"], len(e["preload"]), e["arcIdx"], e["entryOff"], e["entryLen"], 0xFFFF)
                out += e["preload"]
        out += b"\x00"
    out += b"\x00"
    out += b"\x00"
    return bytes(out)

def isJunk(entry):
    if len(entry["name"]) > 100 or len(entry["ext"]) > 15:
        return True
    if entry["entryLen"] == 0 and entry["name"].isdigit():
        return True
    return False

def selfHashes(headerBytes, treeBytes, embedBytes):
    treeHash = md5(treeBytes)
    chunkHash = md5(b"")
    fileHash = md5()
    fileHash.update(headerBytes)
    fileHash.update(treeBytes)
    fileHash.update(embedBytes)
    fileHash.update(treeHash.digest())
    fileHash.update(chunkHash.digest())
    return treeHash.digest() + chunkHash.digest() + fileHash.digest()

def repairVpkIfNeeded(vpkPath, tmpDir):
    try:
        with vpk.open(str(vpkPath)):
            pass
        return vpkPath
    except Exception as e:
        console.print(f"  {SYM['info']} {vpkPath.name}: failed to open normally ({e}), attempting repair...")
        data = vpkPath.read_bytes()
        try:
            header = parseHeader(data)
            entries, treeEnd = parseTree(data, header["headerLen"])
        except Exception as e:
            console.print(f"  {SYM['err']} {vpkPath.name}: structure not recognized ({e}), cannot repair")
            return vpkPath
        
        junk = [e for e in entries if isJunk(e)]
        clean = [e for e in entries if e not in junk]
        if junk:
            console.print(f"  {SYM['trash']} {vpkPath.name}: found {len(junk)} foreign entries, removing")
        
        newTree = buildTree(clean) if junk else data[header["headerLen"]:treeEnd]
        embedAndChunkLen = header["embedLen"] + header["chunkHashLen"]
        embedAndChunk = data[treeEnd:treeEnd + embedAndChunkLen]
        after = treeEnd + embedAndChunkLen
        oldSelfHashes = data[after:after + header["selfHashLen"]]
        signature = data[after + header["selfHashLen"]:]
        needsHashFix = header["selfHashLen"] != 48
        
        if not junk and not needsHashFix:
            console.print(f"  {SYM['info']} {vpkPath.name}: no foreign entries found, the problem is something else")
            return vpkPath
        
        newHeader = bytearray(28)
        struct.pack_into("<III", newHeader, 0, VPK_SIGNATURE, 2, len(newTree))
        struct.pack_into("<IIII", newHeader, 12, header["embedLen"], header["chunkHashLen"], 48, header["sigLen"])
        
        if needsHashFix:
            newSelfHashes = selfHashes(bytes(newHeader), newTree, embedAndChunk)
            console.print(f"  {SYM['trash']} {vpkPath.name}: self-hashes section was corrupt, rebuilding it")
        else:
            newSelfHashes = oldSelfHashes
            
        repaired = tmpDir / f"{vpkPath.stem}_repaired.vpk"
        with open(repaired, "wb") as f:
            f.write(newHeader)
            f.write(newTree)
            f.write(embedAndChunk)
            f.write(newSelfHashes)
            f.write(signature)
        console.print(f"  {SYM['ok']} {vpkPath.name}: structure repaired in a temporary copy ({len(clean)} entries kept)")
        return repaired

SPLIT_PART_RE = re.compile(r'^(.+)_(\d{3}).vpk$', re.IGNORECASE)
BAD_SUFFIX_RE = re.compile(r'[^a-zA-Z0-9]$')
INVALID_FILENAME_CHARS_RE = re.compile(r'[\/:*?"<>|]')

def isSplitPart(item):
    m = SPLIT_PART_RE.match(item.name)
    return bool(m) and not item.name.lower().endswith("_dir.vpk")

def findSplitParts(dirVpkPath):
    m = re.match(r'^(.+)dir.vpk$', dirVpkPath.name, re.IGNORECASE)
    if not m:
        return []
    base = re.escape(m.group(1))
    partRe = re.compile(rf'^{base}(\d{{3}}).vpk$', re.IGNORECASE)
    return [p for p in dirVpkPath.parent.iterdir() if p.is_file() and partRe.match(p.name)]

def deletePath(path):
    try:
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
        return True
    except Exception:
        return False

def cleanupBadNames(rootDir):
    for root, _dirs, files in os.walk(rootDir):
        for name in files:
            if BAD_SUFFIX_RE.search(name):
                deletePath(Path(root) / name)

def cleanupUnwantedExtensions(rootDir, extensions):
    if not extensions:
        return
    exts = {e.lower().lstrip(".") for e in extensions}
    removed = 0
    for root, _dirs, files in os.walk(rootDir):
        for name in files:
            if Path(name).suffix.lower().lstrip(".") in exts:
                if deletePath(Path(root) / name):
                    removed += 1
    if removed:
        console.print(f"  {SYM['trash']} Removed {removed} unwanted files")

def cleanupBlacklistedFiles(rootDir):
    removed_files = 0
    for root, dirs, files in os.walk(rootDir, topdown=False):
        for name in files:
            file_path = Path(root) / name
            ext = file_path.suffix.lower().lstrip(".")
            
            if name in BLACKLISTED_FILENAMES or ext in BLACKLISTED_EXTENSIONS:
                try:
                    file_path.unlink()
                    removed_files += 1
                except Exception:
                    pass
        
        try:
            if not os.listdir(root):
                os.rmdir(root)
        except Exception:
            pass

    if removed_files > 0:
        console.print(f"  {SYM['trash']} Removed {removed_files} blacklisted files")

def sanitizeFilename(name):
    name = INVALID_FILENAME_CHARS_RE.sub("_", name).strip()
    return name or "mod"

def loadConfig(workDir):
    configPath = workDir / CONFIG_FILENAME
    if not configPath.exists():
        configPath.write_text(json.dumps(DEFAULT_CONFIG, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"{SYM['info']} Created {CONFIG_FILENAME} (fill in \"author\" to have it added to the manifest automatically)")
        return dict(DEFAULT_CONFIG)
    try:
        config = json.loads(configPath.read_text(encoding="utf-8"))
        if not isinstance(config, dict):
            raise ValueError("config.json must contain a JSON object")
        return config
    except Exception as e:
        console.print(f"  {SYM['err']} Could not read {CONFIG_FILENAME} ({e}), using defaults")
        return dict(DEFAULT_CONFIG)

def unpackVpks(vpkFiles, extractDir):
    console.print(f"{SYM['pkg']} Found VPK to extract: {len(vpkFiles)}")
    with tempfile.TemporaryDirectory() as repairTmp:
        repairTmpPath = Path(repairTmp)
        for vpkFile in vpkFiles:
            console.print(f"\n{SYM['dir']} Extracting: {vpkFile.name}")
            target = repairVpkIfNeeded(vpkFile, repairTmpPath)
            try:
                with vpk.open(str(target)) as archive:
                    count = 0
                    for entryPath in archive:
                        try:
                            data = archive.get_file(entryPath).read()
                            outPath = extractDir / entryPath
                            outPath.parent.mkdir(parents=True, exist_ok=True)
                            outPath.write_bytes(data)
                            count += 1
                        except Exception:
                            pass
                    console.print(f"  {SYM['ok']} Extracted files: {count}")
            except Exception as e:
                console.print(f"  {SYM['err']} Extraction error for {target.name}: {e}")
                
    cleanupBadNames(extractDir)
    cleanupUnwantedExtensions(extractDir, UNWANTED_EXTENSIONS)
    cleanupBlacklistedFiles(extractDir)

def calculate_sha256(file_path):
    hash_sha256 = sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def compileVpk(items, workDir):
    items = [i for i in items if not BAD_SUFFIX_RE.search(i.name)]
    console.print(f"{SYM['pkg']} Compiling {len(items)} items into a VPK...")
    with tempfile.TemporaryDirectory() as tmp:
        tmpPath = Path(tmp)
        pakName = f"pak{random.randint(1, 99):02d}_dir"
        buildDir = tmpPath / pakName
        buildDir.mkdir()
        for item in items:
            dest = buildDir / item.name
            if item.is_dir():
                shutil.copytree(item, dest)
                cleanupBadNames(dest)
            else:
                shutil.copy2(item, dest)
            
        outputPath = workDir / f"{pakName}.vpk"
        console.print(f"\n{SYM['save']} Saving VPK: {outputPath.name}")
        newPak = vpk.new(str(outputPath))
        newPak.read_dir(str(buildDir))
        newPak.save(str(outputPath))
        console.print(f"{SYM['ok']} VPK compilation complete")

    return outputPath

def convertToPreviewWebp(srcPath, dstPath, size):
    if not PIL_AVAILABLE:
        console.print(f"  {SYM['err']} Pillow is not installed (pip install Pillow), skipping image conversion")
        return False
    try:
        with Image.open(srcPath) as img:
            fitted = ImageOps.fit(img.convert("RGB"), size, method=Image.LANCZOS)
            fitted.save(dstPath, "WEBP")
            console.print(f"  {SYM['ok']} Preview created: {dstPath.name} ({size[0]}x{size[1]})")
            return True
    except Exception as e:
        console.print(f"  {SYM['err']} Failed to convert image: {e}")
        return False

def zipVpk(vpkPath, dstZipPath):
    files = [vpkPath] + findSplitParts(vpkPath)
    with zipfile.ZipFile(dstZipPath, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for f in files:
            zf.write(f, f.name)
    console.print(f"  {SYM['ok']} VPK packed into: {dstZipPath.name}")
    return files

def writeManifest(jsonPath, modName, authorName=None):
    manifest = {
        "name": modName,
        "preview": f"{modName}.webp",
        "file": f"{modName}.zip",
        **MANIFEST_TEMPLATE,
    }
    if authorName:
        for link in manifest["links"]:
            if link.get("type") == "author":
                link["name"] = authorName
    jsonPath.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    console.print(f"  {SYM['ok']} Manifest created: {jsonPath.name}")

def packageMod(workDir, vpkPath, imageFile, authorName=None):
    console.print(f"\n{SYM['pkg']} Building the final mod package...")
    modName = sanitizeFilename(input("Enter mod name: ").strip())
    
    vpk_hash = calculate_sha256(vpkPath)
    
    with tempfile.TemporaryDirectory() as tmp:
        tmpPath = Path(tmp)
        webpPath = None
        if imageFile and imageFile.exists():
            webpPath = tmpPath / f"{modName}.webp"
            if not convertToPreviewWebp(imageFile, webpPath, PREVIEW_SIZE):
                webpPath = None
        else:
            console.print(f"  {SYM['info']} No preview image found, skipping")
            
        vpkZipPath = tmpPath / f"{modName}.zip"
        vpkSourceFiles = zipVpk(vpkPath, vpkZipPath)
        
        manifestPath = tmpPath / "mod.json"
        writeManifest(manifestPath, modName, authorName)
        
        vpk_zip_hash = calculate_sha256(vpkZipPath)
        
        hash_path = tmpPath / "hash.json"
        hash_data = {
            "mod_name": modName,
            "vpk_hash": vpk_hash,
            "vpk_zip_hash": vpk_zip_hash
        }
        hash_path.write_text(json.dumps(hash_data, indent=2, ensure_ascii=False), encoding="utf-8")
        
        finalArchive = workDir / f"{modName}.zip"
        with zipfile.ZipFile(finalArchive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.write(vpkZipPath, vpkZipPath.name)
            if webpPath:
                zf.write(webpPath, webpPath.name)
            zf.write(manifestPath, manifestPath.name)
            zf.write(hash_path, hash_path.name)
            
    console.print(f"\n{SYM['trash']} Cleaning up intermediate files...")
    for f in vpkSourceFiles:
        deletePath(f)
    if imageFile and imageFile.exists():
        deletePath(imageFile)
        
    console.print(f"  {SYM['ok']} Hashes saved")
    console.print(f"\n{SYM['save']} Done: {finalArchive.name}")

def main():
    selfUpdate()
    banner()
    workDir = Path.cwd()
    scriptName = Path(sys.executable if isFrozen() else sys.argv[0]).name
    config = loadConfig(workDir)
    authorName = (config.get("author") or "").strip() or None
    
    vpkFiles, otherItems, imageFile = [], [], None
    for item in workDir.iterdir():
        if item.name in (scriptName, CONFIG_FILENAME) or item.name.startswith(scriptName + "."):
            continue
        if item.is_file() and item.suffix.lower() == ".zip":
            continue
        if item.is_file() and item.name.lower().endswith(".vpk"):
            if not isSplitPart(item):
                vpkFiles.append(item)
        elif (imageFile is None and item.is_file()
              and item.suffix.lower().lstrip(".") in IMAGE_EXTENSIONS):
            imageFile = item
        else:
            otherItems.append(item)
            
    try:
        if vpkFiles:
            with tempfile.TemporaryDirectory() as extractTmp:
                extractDir = Path(extractTmp)
                unpackVpks(vpkFiles, extractDir)
                cleanedItems = list(extractDir.iterdir())
                if not cleanedItems:
                    console.print(f"{SYM['err']} No files left to compile after cleanup.")
                    time.sleep(3)
                    return
                vpkPath = compileVpk(cleanedItems, workDir)
                
            sourcePaths = list(vpkFiles)
            for f in vpkFiles:
                sourcePaths.extend(findSplitParts(f))
            for p in sourcePaths:
                deletePath(p)
                
            packageMod(workDir, vpkPath, imageFile, authorName)
        elif otherItems:
            time.sleep(1)
            vpkPath = compileVpk(otherItems, workDir)
            packageMod(workDir, vpkPath, imageFile, authorName)
        else:
            console.print(f"{SYM['info']} No VPK files or mod files found next to the script.")
            time.sleep(2)
    except Exception as e:
        console.print(f"{SYM['err']} Error: {e}")
        time.sleep(5)
        sys.exit(1)

if __name__ == "__main__":
    main()