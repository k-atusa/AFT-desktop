package main

// go mod init example.com
// go mod tidy
// go build -ldflags="-H windowsgui -s -w" -trimpath -o aft.exe login.go viewer.go

import (
	"fmt"
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// 1. 데이터 관리를 위한 구조체 정의
type LoginInfo struct {
	VaultPath    string
	KeyPath      string
	Password     string
	NewVaultPath string
	ImgType      string
	KeyAlgo      string
}

type LoginManager struct {
	App    fyne.App
	Window fyne.Window
	Info   LoginInfo
}

// 2. 기본 테마를 유지하되 글자 시인성만 높인 커스텀 테마
type ContrastTheme struct{}

func (m ContrastTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	// 글자색(Foreground)만 선명하게 보정
	if name == theme.ColorNameForeground {
		if variant == theme.VariantDark {
			return color.White // 다크모드: 순백색
		}
		return color.Black // 라이트모드: 순검정색
	}
	// 나머지는 시스템 기본 테마(OS 설정)를 그대로 따름
	return theme.DefaultTheme().Color(name, variant)
}

func (m ContrastTheme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (m ContrastTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (m ContrastTheme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) }

// 3. 메인 실행부
func main() {
	a := app.New()
	a.Settings().SetTheme(&ContrastTheme{}) // 커스텀 테마 적용

	m := &LoginManager{
		App:    a,
		Window: a.NewWindow("Stealth Vault - Authentication"),
	}

	m.ShowLogin()
	m.Window.Resize(fyne.NewSize(850, 480))
	m.Window.CenterOnScreen()
	m.Window.ShowAndRun()
}

// 4. 로그인 UI 빌드 함수
func (m *LoginManager) ShowLogin() {
	// --- [좌측 섹션: Vault Unlock] ---
	vPathLabel := widget.NewLabelWithStyle("선택된 볼트 없음", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	vSelect := widget.NewSelect([]string{"C:/Users/Secure/Vault1", "D:/Project/Vault2"}, func(s string) {
		m.Info.VaultPath = s
		vPathLabel.SetText("Path: " + s)
	})
	vSelect.PlaceHolder = "최근 볼트 바로가기"

	manualBtn := widget.NewButtonWithIcon("볼트 폴더 수동 선택", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(list fyne.ListableURI, err error) {
			if err == nil && list != nil {
				m.Info.VaultPath = list.Path()
				vPathLabel.SetText("Path: " + list.Path())
			}
		}, m.Window)
	})

	kPathLabel := widget.NewLabelWithStyle("키 파일을 선택하세요.", fyne.TextAlignLeading, fyne.TextStyle{Italic: true})
	kFileBtn := widget.NewButtonWithIcon("파일 선택", theme.FileIcon(), func() {
		dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
			if err == nil && r != nil {
				m.Info.KeyPath = r.URI().Path()
				kPathLabel.SetText("Key: " + m.Info.KeyPath)
			}
		}, m.Window)
	})
	kRecvBtn := widget.NewButtonWithIcon("키 받기", theme.DownloadIcon(), func() {
		kPathLabel.SetText("통신 수신 대기 중...")
		dialog.ShowInformation("통신 모드", "원격지로부터 보안 키를 수신합니다.", m.Window)
	})

	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Master Password")

	loginBtn := widget.NewButtonWithIcon("Unlock Vault", theme.ConfirmIcon(), func() {
		m.Info.Password = passEntry.Text
		if m.Info.VaultPath == "" || m.Info.Password == "" {
			dialog.ShowError(fmt.Errorf("경로와 비밀번호를 입력하세요."), m.Window)
			return
		}
		m.switchToMain()
	})
	loginBtn.Importance = widget.HighImportance

	leftBox := container.NewVBox(
		vSelect, manualBtn, vPathLabel,
		widget.NewSeparator(),
		kPathLabel,
		container.NewGridWithColumns(2, kFileBtn, kRecvBtn),
		passEntry,
		loginBtn,
	)

	// --- [우측 섹션: New Vault] ---
	nPathLabel := widget.NewLabelWithStyle("생성 위치 미정", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	nPathBtn := widget.NewButtonWithIcon("폴더 선택", theme.FolderNewIcon(), func() {
		dialog.ShowFolderOpen(func(list fyne.ListableURI, err error) {
			if err == nil && list != nil {
				m.Info.NewVaultPath = list.Path()
				nPathLabel.SetText(list.Path())
			}
		}, m.Window)
	})

	imgSelect := widget.NewSelect([]string{"webp", "png"}, func(s string) { m.Info.ImgType = s })
	imgSelect.SetSelected("webp")
	algoSelect := widget.NewSelect([]string{"ecc1", "rsa4k"}, func(s string) { m.Info.KeyAlgo = s })
	algoSelect.SetSelected("ecc1")

	createBtn := widget.NewButtonWithIcon("새 볼트 생성", theme.ContentAddIcon(), func() {
		if m.Info.NewVaultPath == "" {
			dialog.ShowError(fmt.Errorf("위치를 먼저 선택하세요."), m.Window)
			return
		}
		dialog.ShowInformation("성공", "새로운 보안 볼트가 생성되었습니다.", m.Window)
	})

	rightBox := container.NewVBox(
		container.NewBorder(nil, nil, nil, nPathBtn, nPathLabel),
		widget.NewSeparator(),
		widget.NewLabel("이미지 위장 포맷"), imgSelect,
		widget.NewLabel("암호화 알고리즘"), algoSelect,
		layout.NewSpacer(),
		createBtn,
	)

	// --- [전체 레이아웃 결합] ---
	mainGrid := container.NewGridWithColumns(2,
		widget.NewCard("Unlock Existing", "기존 볼트 해제", leftBox),
		widget.NewCard("Create New", "새로운 볼트 구축", rightBox),
	)

	m.Window.SetContent(container.NewPadded(mainGrid))
}

// 5. 화면 전환 함수
func (m *LoginManager) switchToMain() {
	// 로그인 창 닫기
	m.Window.Close()

	// 메인 탐색기 실행
	explorer := &MainExplorer{
		App: m.App,
	}
	explorer.ShowMain(m.Info)
}
