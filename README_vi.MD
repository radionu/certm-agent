# CertM Agent

[English](README.md) · [Lịch sử phiên bản](CHANGELOG.md) · [Ghi chú kỹ thuật](docs/TECHNICAL_NOTES.md)

CertM Agent kết nối máy chủ hoặc firewall với CertM. Agent tự tìm các website
HTTPS trên hệ thống, gửi thông tin chứng thư đang sử dụng và cài chứng thư đã
được quản trị viên gán trên CertM.

Agent chủ động kết nối ra ngoài. CertM không cần đăng nhập vào máy chủ và agent
không tự cấp chứng thư.

## Các agent được hỗ trợ

| Hệ thống | Dịch vụ | Agent sử dụng |
|---|---|---|
| Ubuntu / Debian | nginx, Apache, Zimbra 9 một máy chủ | Linux agent |
| RHEL / AlmaLinux / Rocky Linux | nginx, Apache | Linux agent |
| Windows Server 2016 trở lên | IIS | Windows agent |
| pfSense CE / Plus | HAProxy package | pfSense HAProxy agent |

Trước khi cài, lấy operations bootstrap credential từ quản trị viên CertM.
Client mới và địa chỉ IP nguồn có thể cần được duyệt trên CertM trước khi nhận
được chứng thư đã gán.

## Agent Linux: nginx, Apache và Zimbra

nginx, Apache và Zimbra dùng chung một Linux agent. Chạy lệnh cài đặt bằng
`root` hoặc qua `sudo`.

Yêu cầu:

- Python 3.8 trở lên;
- kết nối HTTPS ra CertM;
- nginx hoặc Apache đang chạy, hoặc một máy chủ Zimbra được hỗ trợ;
- `systemd`.

### Cài đặt tự động

Ubuntu hoặc Debian:

```bash
sudo apt-get update
sudo apt-get install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

RHEL, AlmaLinux hoặc Rocky Linux:

```bash
sudo dnf install -y git
sudo git clone https://github.com/radionu/certm-agent.git /opt/certm-agent-src
cd /opt/certm-agent-src/linux
sudo ./install.sh
```

Installer thường tự nhận nginx hoặc Apache. Nếu cả hai cùng chạy, chọn rõ dịch
vụ cần quản lý:

```bash
sudo ./install.sh --web-server nginx --display-name 'Web Server 01'
sudo ./install.sh --web-server apache --display-name 'Web Server 01'
```

Zimbra dùng cùng bộ source Linux:

```bash
cd /opt/certm-agent-src
sudo bash linux/install.sh --web-server zimbra --display-name 'Zimbra Mail 01'
```

Nhập bootstrap credential khi được hỏi. Quá trình cài đặt chỉ đăng ký hệ thống,
chưa thay đổi chứng thư ngay.

### Cài đặt thủ công

Dùng cách này khi máy chủ không có Git:

1. Tải repository ZIP trên máy quản trị tin cậy:
   `https://github.com/radionu/certm-agent/archive/refs/heads/main.zip`
2. Copy file ZIP sang máy chủ và giải nén.
3. Chạy installer trong thư mục `linux` vừa giải nén.

Ví dụ:

```bash
cd /tmp/certm-agent-main/linux
sudo ./install.sh --web-server nginx --display-name 'Web Server 01'
```

Với Zimbra:

```bash
cd /tmp/certm-agent-main
sudo bash linux/install.sh --web-server zimbra --display-name 'Zimbra Mail 01'
```

### Kiểm tra và bật lịch cho nginx hoặc Apache

Sau khi quản trị viên duyệt client và gán chứng thư:

```bash
sudo /opt/certm-agent/certm-agent.py inventory
sudo /opt/certm-agent/certm-agent.py renew --dry-run
sudo /opt/certm-agent/certm-agent.py renew
sudo systemctl enable --now certm-agent.timer
```

### Kiểm tra và bật lịch cho Zimbra

Triển khai chứng thư Zimbra sẽ khởi động lại các dịch vụ Zimbra. Nên thực hiện
lần đầu trong thời gian bảo trì. Khi cần xử lý khẩn cấp chứng thư đã hết hạn,
quản trị viên có thể cho phép chạy ngoài khung giờ bình thường:

```bash
sudo /opt/certm-agent/certm-agent.py renew --dry-run
sudo /opt/certm-agent/certm-agent.py renew --emergency
sudo /opt/certm-agent/certm-agent.py verify
sudo systemctl enable --now certm-agent.timer
```

Nếu không có `--emergency`, chứng thư Zimbra chỉ được thay đổi trong khung giờ
bảo trì đã cấu hình. Lệnh `verify` kiểm tra chứng thư và dịch vụ mà không thay
đổi hay khởi động lại Zimbra.

### Lệnh kiểm tra và log Linux

```bash
sudo systemctl status certm-agent.timer --no-pager
sudo systemctl list-timers certm-agent.timer --all
sudo tail -n 100 /var/log/certm/certm-agent.log
sudo journalctl -u certm-agent.service -n 100 --no-pager
```

Chạy ngay một chu kỳ đầy đủ. Lệnh này có thể cài agent update đã được duyệt và
triển khai các chứng thư đã gán:

```bash
sudo systemctl start certm-agent.service
```

Các vị trí quan trọng:

- Cấu hình: `/etc/certm/agent.json`
- Agent: `/opt/certm-agent`
- Log: `/var/log/certm/certm-agent.log`
- Backup: `/opt/certm-agent/bkup`
- Chứng thư do CertM quản lý: `/etc/certm/live`

Khi cần quản trị viên CertM hỗ trợ, gửi 100 dòng cuối của agent log và kết quả
lệnh `systemctl status certm-agent.timer`.

## Agent Windows IIS

Yêu cầu:

- Windows Server 2016 trở lên;
- IIS và PowerShell module WebAdministration;
- Windows PowerShell 5.1;
- kết nối HTTPS ra CertM;
- cửa sổ PowerShell chạy bằng quyền Administrator.

### Cài đặt tự động

Mở PowerShell bằng quyền Administrator và chạy:

```powershell
$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p="$env:TEMP\Install-CertM.ps1"; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/radionu/certm-agent/main/windows/Bootstrap-CertMAgent.ps1' -OutFile $p; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p
```

Installer hỏi bootstrap credential bằng ô nhập ẩn, đăng ký máy chủ và tạo task
`CertM IIS Agent` chạy mỗi 6 giờ.

Nếu muốn giữ automation ở trạng thái tắt cho đến khi kiểm tra thủ công xong:

```powershell
$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $p="$env:TEMP\Install-CertM.ps1"; Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/radionu/certm-agent/main/windows/Bootstrap-CertMAgent.ps1' -OutFile $p; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $p -Staged
```

### Cài đặt thủ công

Dùng cách này khi máy chủ không tải được từ GitHub:

1. Tải `main.zip` trên máy quản trị tin cậy.
2. Copy bốn file trong thư mục `windows` vào `C:\Temp\CertM-Agent`:
   `CertM.Agent.ps1`, `CertM.Update.ps1`, `Install-CertMAgent.ps1` và
   `Uninstall-CertMAgent.ps1`.
3. Mở PowerShell bằng quyền Administrator rồi chạy:

```powershell
Set-Location 'C:\Temp\CertM-Agent'
Set-ExecutionPolicy -Scope Process Bypass -Force
Get-ChildItem -Filter '*.ps1' | Unblock-File

$secureCredential = Read-Host 'Enter the CertM operations bootstrap credential' -AsSecureString
$credentialPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCredential)
try {
    $plainCredential = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($credentialPointer)
    .\Install-CertMAgent.ps1 `
        -DisplayName 'IIS Server 01' `
        -EnrollmentToken $plainCredential `
        -RunOnce `
        -EnableTask
}
finally {
    $plainCredential = $null
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($credentialPointer)
}
```

### Lệnh kiểm tra và log Windows

Sau khi client được duyệt và đã gán chứng thư:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode Discover
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode Inventory
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode DryRun
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\CertM\bin\CertM.Agent.ps1' -Mode Run
```

Kiểm tra task:

```powershell
Get-ScheduledTask -TaskName 'CertM IIS Agent'
Get-ScheduledTaskInfo -TaskName 'CertM IIS Agent' |
    Select-Object LastRunTime, LastTaskResult, NextRunTime
```

Bật hoặc tắt automation:

```powershell
Enable-ScheduledTask -TaskName 'CertM IIS Agent'
Disable-ScheduledTask -TaskName 'CertM IIS Agent'
```

Lấy log gửi quản trị viên CertM:

```powershell
Get-Content 'C:\CertM\logs\agent.log' -Tail 100
Get-Content 'C:\CertM\logs\agent-update.log' -Tail 100
```

Các vị trí quan trọng:

- Cấu hình: `C:\CertM\config.json`
- Agent: `C:\CertM\bin`
- Log: `C:\CertM\logs`
- File update tạm: `C:\CertM\staging`

Không gửi `config.json` cho người khác vì file này chứa định danh client đã được
bảo vệ và chỉ dùng cho máy Windows đó.

## Agent pfSense HAProxy

Yêu cầu:

- pfSense CE hoặc pfSense Plus;
- pfSense HAProxy package;
- kết nối HTTPS ra CertM;
- shell quyền `root`.

### Cài đặt tự động

Chạy trong pfSense root shell:

```sh
fetch -qo /tmp/install-certm-pfsense.sh \
  'https://raw.githubusercontent.com/radionu/certm-agent/main/pfsense/install.sh'
/bin/sh -n /tmp/install-certm-pfsense.sh && \
  /bin/sh /tmp/install-certm-pfsense.sh
```

Nhập địa chỉ CertM, tên hiển thị và bootstrap credential khi được hỏi. Installer
đăng ký firewall và tạo lịch pfSense cron chạy mỗi 6 giờ.

### Cài đặt thủ công

Dùng cách này khi firewall không tải được file từ GitHub. Copy các file sau từ
thư mục `pfsense` của repository vào firewall:

- `CertM.HAProxy.Agent.php`
- `certm-haproxy`
- `config.example.json`

Sau đó chạy:

```sh
mkdir -p /conf/certm
chmod 700 /conf/certm
cp /tmp/CertM.HAProxy.Agent.php /conf/certm/CertM.HAProxy.Agent.php
cp /tmp/certm-haproxy /conf/certm/certm-haproxy
cp /tmp/config.example.json /conf/certm/config.json
chmod 700 /conf/certm/CertM.HAProxy.Agent.php /conf/certm/certm-haproxy
chmod 600 /conf/certm/config.json
cp /conf/certm/certm-haproxy /usr/local/sbin/certm-haproxy
chmod 700 /usr/local/sbin/certm-haproxy
vi /conf/certm/config.json
/bin/sh /conf/certm/certm-haproxy preflight
/bin/sh /conf/certm/certm-haproxy enroll
/bin/sh /conf/certm/certm-haproxy enable
```

Trong `config.json`, thay tên hiển thị và bootstrap credential mẫu trước khi chạy
lệnh `enroll`.

### Lệnh kiểm tra và log pfSense

Sau khi quản trị viên CertM duyệt client và gán chứng thư:

```sh
certm-haproxy status
certm-haproxy inventory
certm-haproxy dry-run
certm-haproxy renew
certm-haproxy logs 100
```

Các lệnh vận hành khác:

```sh
certm-haproxy enable
certm-haproxy disable
certm-haproxy update
```

Lệnh `update` chỉ cài version pfSense đã được gán hoặc duyệt trên CertM.

Nếu lệnh ngắn không còn sau khi nâng cấp pfSense, dùng bản lưu trong `/conf`:

```sh
/bin/sh /conf/certm/certm-haproxy status
/bin/sh /conf/certm/certm-haproxy update
```

Các vị trí quan trọng:

- Cấu hình và agent: `/conf/certm`
- Log: `/var/log/certm-haproxy.log`
- Lịch chạy: pfSense cron, phút 21 mỗi 6 giờ

Với pfSense HA pair, ban đầu chỉ cài trên node giữ cấu hình chính. Kiểm tra cơ
chế đồng bộ HA của hệ thống trước khi cài lên node thứ hai.

## Khi cần hỗ trợ

Gửi quản trị viên CertM các thông tin sau:

1. tên hiển thị của client;
2. lệnh đã chạy bị lỗi;
3. toàn bộ lỗi hiện trên màn hình;
4. 100 dòng log cuối;
5. thời gian gần đúng khi xảy ra lỗi.

Không gửi private key, bootstrap credential, client token, `config.json` hoặc cả
gói chứng thư qua chat hay email.
