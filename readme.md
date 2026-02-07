# AFT-desktop v0.1

project USAG: Advanced File Transfer desktop version

> AFT is simple secure storage for keeping important data and secrets.

## CLI Usage

| Option | Input | Info | 정보 |
| :--- | :--- | :--- | :--- |
| -m | import, export, view, trim, version | Sets the working mode. | 작업 모드를 설정합니다. |
| -o | dirpath | Sets the output path. | 출력 경로를 설정합니다. |
| -pw | text | Sets the password. | 비밀번호를 설정합니다. |
| -kf | filepath | Sets the key file path. | 키 파일 경로를 설정합니다. |
| -msg | text | Sets public message of vault. | 저장소의 공개 메세지를 설정합니다. |
| -legacy | | Enables Legacy Mode (RSA, png). | 레거시 모드(RSA, png)를 킵니다. |
| | | Argument following the options are interpreted as target path. | 옵션 이후 인자는 타겟 경로로 해석됩니다. |

- import: 타겟 폴더를 암호화하여 새 저장소를 생성합니다. Make new vault by encrypting target folder.
- export: 볼트를 복호화하여 원본 폴더를 생성합니다. Decrypt vault and generate original folder.
- view: 볼트의 메타데이터와 파일 리스트를 출력합니다. Print vault metadata and files list.
- trim: 볼트의 논리적 구조와 파일시스템의 물리적 구조를 동기화하고 암호화 키 쌍을 새 것으로 교체합니다. Sync logical structure of vault with physical file system, replace encryption key pair to new one.

CLI version does not support file transfer function. However, trim function is supported only with CLI version.

## GUI Usage

## Build Executable

This application uses Go programming language. [Install Go](https://go.dev/) to build yourself, or download pre-built release binary. It takes few minutes to download and build GUI version.

windows cli
```bat
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o aftcli.exe lib.go lite.go
```

linux/mac cli
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o aftcli lib.go lite.go
```

windows gui
```bat
go mod init example.com
go mod tidy
go build -ldflags="-H windowsgui -s -w" -trimpath -o aftgui.exe lib.go main.go
```

linux/mac gui
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o aftgui lib.go main.go
```

fyne2 GUI requires C compiler and X11 environment. check and install following packages before build.
```bash
gcc --version
sudo apt-get install pkg-config libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libxxf86vm-dev
```